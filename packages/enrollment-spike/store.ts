/** Disposable E0 PostgreSQL store experiment. No routes or Better Auth hooks. */
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
} from "node:crypto";
import { Pool, type PoolClient } from "pg";
export { Pool };

export type Challenge = {
  version: number;
  enrollmentId: number[];
  hostId: number[];
  hostKeyFingerprint: number[];
  bootstrapSessionId: number[];
  audience: string;
  expiresAt: string;
  nonce: number[];
  operationId: number[];
};
export type Proof = { challenge: Challenge; signature: number[] };
export type Outcome =
  { ok: true; sealed: string } | { ok: false; code: string };
export type Credentials = { family: string; refresh: string; access: string };
export type Fault =
  "before_commit" | "after_commit" | "after_receipt" | undefined;
const TTL_SECONDS = 30;
const denied = (code: string): Outcome => ({ ok: false, code });
export const hash = (token: string) =>
  createHash("sha256").update(token).digest();
function canonicalUuid(...values: string[]) {
  if (
    values.some(
      (value) =>
        typeof value !== "string" ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
          value,
        ),
    )
  )
    throw new Error("expected canonical lowercase UUID");
}
export const bytes = (id: string) => {
  canonicalUuid(id);
  return Array.from(Buffer.from(id.replaceAll("-", ""), "hex"));
};
export const uuid = () => randomUUID();

/** Synthetic verifier bridge; signatures are implemented only in Rust. */
export async function rust(
  mode: "sign" | "verify" | "fingerprint" | "bundle",
  input?: unknown,
): Promise<any> {
  const binary = process.env.ENROLLMENT_FIXTURE_BINARY;
  if (!binary) throw new Error("fixture verifier missing");
  const p = Bun.spawn([binary, mode], {
    stdin:
      input === undefined
        ? "ignore"
        : new TextEncoder().encode(JSON.stringify(input)),
    stdout: "pipe",
    stderr: "ignore",
    env: {},
  });
  const timeout = setTimeout(() => p.kill(), 5000);
  try {
    const output = await new Response(p.stdout).text();
    if ((await p.exited) !== 0 || output.length > 16384)
      throw new Error("proof rejected");
    return mode === "verify" ? true : JSON.parse(output);
  } finally {
    clearTimeout(timeout);
  }
}

export class Store {
  constructor(
    readonly pool: Pool,
    private readonly key: Buffer,
  ) {
    if (key.length !== 32) throw new Error("recovery key must be 32 bytes");
  }
  private aad(
    kind: string,
    subject: string,
    operation: string,
    account: string,
    credential?: Buffer,
  ) {
    canonicalUuid(subject, operation, account);
    return Buffer.from(
      JSON.stringify([
        "e0-recovery-v1",
        kind,
        subject,
        operation,
        account,
        credential?.toString("hex") ?? null,
      ]),
    );
  }
  private seal(value: Credentials, aad: Buffer): Buffer {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, nonce);
    cipher.setAAD(aad);
    const encrypted = Buffer.concat([
      cipher.update(JSON.stringify(value)),
      cipher.final(),
    ]);
    return Buffer.concat([nonce, cipher.getAuthTag(), encrypted]);
  }
  open(
    sealed: string,
    kind: string,
    subject: string,
    operation: string,
    account: string,
    oldRefresh?: string,
  ): Credentials {
    canonicalUuid(subject, operation, account);
    const b = Buffer.from(sealed, "base64");
    if (b.length < 29 || b.length > 4096)
      throw new Error("invalid recovery envelope");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.key,
      b.subarray(0, 12),
    );
    decipher.setAAD(
      this.aad(
        kind,
        subject,
        operation,
        account,
        oldRefresh ? hash(oldRefresh) : undefined,
      ),
    );
    decipher.setAuthTag(b.subarray(12, 28));
    return JSON.parse(
      Buffer.concat([
        decipher.update(b.subarray(28)),
        decipher.final(),
      ]).toString(),
    );
  }
  private async transaction<T>(
    fn: (c: PoolClient) => Promise<T>,
    fault?: Fault,
  ): Promise<T> {
    const c = await this.pool.connect();
    try {
      await c.query("BEGIN");
      await c.query("SET LOCAL statement_timeout='5s'");
      const result = await fn(c);
      if (fault === "before_commit") process.exit(71);
      await c.query("COMMIT");
      if (fault === "after_commit") process.exit(72);
      return result;
    } catch (error) {
      await c.query("ROLLBACK");
      throw error;
    } finally {
      c.release();
    }
  }
  private async account(c: PoolClient, id: string) {
    return (
      await c.query(
        "SELECT * FROM enrollment_spike.account WHERE id=$1 FOR UPDATE",
        [id],
      )
    ).rows[0];
  }
  private async verify(proof: Proof, expected: Challenge, account: string) {
    const trusted = await rust("bundle");
    if (
      JSON.stringify(trusted.bundle.account_id) !==
      JSON.stringify(bytes(account))
    )
      throw new Error("fixture account binding rejected");
    await rust("verify", {
      proof,
      expected,
      now: Math.floor(Date.now() / 1000),
    });
    if (BigInt(Math.floor(Date.now() / 1000)) >= BigInt(expected.expiresAt))
      throw new Error("proof expired before effect");
  }
  private async mint(
    c: PoolClient,
    family: string,
    rotation: number,
  ): Promise<Credentials> {
    const refresh = randomBytes(32).toString("base64url");
    const access = randomBytes(32).toString("base64url");
    await c.query(
      "INSERT INTO enrollment_spike.credential(hash,family_id,rotation,expires_at) VALUES($1,$2,$3,clock_timestamp()+interval '90 days')",
      [hash(refresh), family, rotation],
    );
    await c.query(
      "UPDATE enrollment_spike.family SET rotation=$2,access_hash=$3,access_expires_at=clock_timestamp()+interval '5 minutes' WHERE id=$1",
      [family, rotation, hash(access)],
    );
    return { family, refresh, access };
  }
  async exchange(
    request: {
      enrollment: string;
      operation: string;
      bootstrapSession: string;
      clientClass: string;
      proof: Proof;
    },
    fault?: Fault,
  ): Promise<Outcome> {
    canonicalUuid(
      request.enrollment,
      request.operation,
      request.bootstrapSession,
    );
    return this.transaction(async (c) => {
      let e = (
        await c.query("SELECT * FROM enrollment_spike.enrollment WHERE id=$1", [
          request.enrollment,
        ])
      ).rows[0];
      if (!e) return denied("ENROLLMENT_NOT_FOUND");
      const a = await this.account(c, e.account_id);
      e = (
        await c.query("SELECT * FROM enrollment_spike.enrollment WHERE id=$1", [
          request.enrollment,
        ])
      ).rows[0];
      if (
        a.state !== "active" ||
        e.access_epoch !== a.access_epoch ||
        e.bootstrap_session_id !== request.bootstrapSession ||
        request.clientClass !== e.client_class
      )
        return denied("AUTH_REQUIRED");
      if (
        JSON.stringify(bytes(request.operation)) !==
        JSON.stringify(e.expected.operationId)
      )
        return denied("OPERATION_MISMATCH");
      if (
        JSON.stringify(e.expected.enrollmentId) !==
          JSON.stringify(bytes(e.id)) ||
        JSON.stringify(e.expected.hostId) !==
          JSON.stringify(bytes(e.host_id)) ||
        JSON.stringify(e.expected.bootstrapSessionId) !==
          JSON.stringify(bytes(e.bootstrap_session_id)) ||
        !Buffer.from(e.expected.hostKeyFingerprint).equals(e.host_fingerprint)
      )
        return denied("INVALID_BINDING");
      await this.verify(request.proof, e.expected, e.account_id);
      if (e.consumed_operation) {
        const f = (
          await c.query(
            "SELECT * FROM enrollment_spike.family WHERE enrollment_id=$1",
            [e.id],
          )
        ).rows[0];
        if (!f || f.revoked || f.confirmed || f.access_epoch !== a.access_epoch)
          return denied("AUTH_REQUIRED");
        const r = (
          await c.query(
            "SELECT sealed FROM enrollment_spike.recovery WHERE kind='exchange' AND subject_id=$1 AND operation_id=$2 AND expires_at>clock_timestamp()",
            [e.id, request.operation],
          )
        ).rows[0];
        if (r?.sealed) return { ok: true, sealed: r.sealed.toString("base64") };
        await c.query(
          "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1",
          [f.id],
        );
        return denied("RECOVERY_EXPIRED");
      }
      const family = uuid();
      await c.query(
        "INSERT INTO enrollment_spike.family(id,enrollment_id,account_id,access_epoch,access_hash,access_expires_at) VALUES($1,$2,$3,$4,$5,clock_timestamp())",
        [family, e.id, e.account_id, a.access_epoch, Buffer.alloc(32)],
      );
      const credentials = await this.mint(c, family, 0);
      const sealed = this.seal(
        credentials,
        this.aad("exchange", e.id, request.operation, e.account_id),
      );
      await c.query(
        "INSERT INTO enrollment_spike.recovery(kind,subject_id,operation_id,account_id,expected,sealed,expires_at) VALUES('exchange',$1,$2,$3,$4,$5,clock_timestamp()+($6 * interval '1 second'))",
        [
          e.id,
          request.operation,
          e.account_id,
          e.expected,
          sealed,
          TTL_SECONDS,
        ],
      );
      await c.query(
        "UPDATE enrollment_spike.enrollment SET consumed_operation=$2 WHERE id=$1",
        [e.id, request.operation],
      );
      return { ok: true, sealed: sealed.toString("base64") };
    }, fault);
  }
  async rotationChallenge(
    family: string,
    token: string,
    operation: string,
  ): Promise<Challenge | Outcome> {
    canonicalUuid(family, operation);
    return this.transaction(async (c) => {
      const f = (
        await c.query("SELECT * FROM enrollment_spike.family WHERE id=$1", [
          family,
        ])
      ).rows[0];
      if (!f) return denied("AUTH_REQUIRED");
      const a = await this.account(c, f.account_id);
      const current = (
        await c.query("SELECT * FROM enrollment_spike.family WHERE id=$1", [
          family,
        ])
      ).rows[0];
      const credential = (
        await c.query(
          "SELECT * FROM enrollment_spike.credential WHERE hash=$1 AND family_id=$2 AND expires_at>clock_timestamp()",
          [hash(token), family],
        )
      ).rows[0];
      if (
        !credential ||
        current.revoked ||
        a.state !== "active" ||
        current.access_epoch !== a.access_epoch
      )
        return denied("AUTH_REQUIRED");
      if (
        credential.consumed_operation &&
        credential.consumed_operation !== operation
      ) {
        await c.query(
          "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1",
          [family],
        );
        await c.query(
          "DELETE FROM enrollment_spike.recovery WHERE subject_id=$1",
          [family],
        );
        return denied("REFRESH_REUSE");
      }
      const existing = (
        await c.query(
          "SELECT *, expires_at>clock_timestamp() AS live FROM enrollment_spike.recovery WHERE kind='rotate' AND subject_id=$1 AND operation_id=$2",
          [family, operation],
        )
      ).rows[0];
      if (existing) {
        if (!existing.credential_hash.equals(hash(token)))
          return denied("OPERATION_MISMATCH");
        if (!existing.live) {
          await c.query(
            "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1",
            [family],
          );
          await c.query(
            "DELETE FROM enrollment_spike.recovery WHERE subject_id=$1",
            [family],
          );
          return denied("REFRESH_REUSE");
        }
        return existing.expected;
      }
      if (credential.consumed_operation) {
        await c.query(
          "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1",
          [family],
        );
        return denied("REFRESH_REUSE");
      }
      await c.query(
        "DELETE FROM enrollment_spike.recovery WHERE kind='rotate' AND subject_id=$1",
        [family],
      );
      const e = (
        await c.query(
          "SELECT expected FROM enrollment_spike.enrollment WHERE id=$1",
          [f.enrollment_id],
        )
      ).rows[0];
      const expected: Challenge = {
        ...e.expected,
        operationId: bytes(operation),
        audience: "lomi-remote-host-refresh-spike",
        expiresAt: String(Math.floor(Date.now() / 1000) + TTL_SECONDS),
        nonce: Array.from(randomBytes(32)),
      };
      await c.query(
        "INSERT INTO enrollment_spike.recovery(kind,subject_id,operation_id,account_id,credential_hash,expected,expires_at) VALUES('rotate',$1,$2,$3,$4,$5,clock_timestamp()+($6 * interval '1 second'))",
        [family, operation, f.account_id, hash(token), expected, TTL_SECONDS],
      );
      return expected;
    });
  }
  async rotate(
    family: string,
    token: string,
    operation: string,
    proof: Proof,
    fault?: Fault,
  ): Promise<Outcome> {
    canonicalUuid(family, operation);
    return this.transaction(async (c) => {
      let f = (
        await c.query("SELECT * FROM enrollment_spike.family WHERE id=$1", [
          family,
        ])
      ).rows[0];
      if (!f) return denied("AUTH_REQUIRED");
      const a = await this.account(c, f.account_id);
      f = (
        await c.query("SELECT * FROM enrollment_spike.family WHERE id=$1", [
          family,
        ])
      ).rows[0];
      const credential = (
        await c.query(
          "SELECT * FROM enrollment_spike.credential WHERE hash=$1 AND family_id=$2 AND expires_at>clock_timestamp()",
          [hash(token), family],
        )
      ).rows[0];
      if (
        !credential ||
        f.revoked ||
        a.state !== "active" ||
        f.access_epoch !== a.access_epoch
      )
        return denied("AUTH_REQUIRED");
      const r = (
        await c.query(
          "SELECT *, expires_at>clock_timestamp() AS live FROM enrollment_spike.recovery WHERE kind='rotate' AND subject_id=$1 AND operation_id=$2",
          [family, operation],
        )
      ).rows[0];
      if (
        credential.consumed_operation &&
        credential.consumed_operation !== operation
      ) {
        await c.query(
          "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1",
          [family],
        );
        await c.query(
          "DELETE FROM enrollment_spike.recovery WHERE subject_id=$1",
          [family],
        );
        return denied("REFRESH_REUSE");
      }
      if (!r || !r.credential_hash.equals(hash(token))) {
        if (credential.consumed_operation) {
          await c.query(
            "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1",
            [family],
          );
          return denied("REFRESH_REUSE");
        }
        return denied("CHALLENGE_REQUIRED");
      }
      if (!r.live) {
        await c.query(
          "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1",
          [family],
        );
        await c.query(
          "DELETE FROM enrollment_spike.recovery WHERE subject_id=$1",
          [family],
        );
        return denied("REFRESH_REUSE");
      }
      await this.verify(proof, r.expected, f.account_id);
      // Verification is asynchronous. Recheck both DB deadlines at replay or
      // credential consumption, rather than trusting the earlier SELECT.
      if (credential.consumed_operation) {
        const replay = (
          await c.query(
            "SELECT r.sealed FROM enrollment_spike.recovery r JOIN enrollment_spike.credential c ON c.hash=r.credential_hash WHERE r.kind='rotate' AND r.subject_id=$1 AND r.operation_id=$2 AND c.hash=$3 AND c.family_id=$1 AND c.consumed_operation=$2 AND c.expires_at>clock_timestamp() AND r.expires_at>clock_timestamp() AND r.sealed IS NOT NULL",
            [family, operation, hash(token)],
          )
        ).rows[0];
        if (replay)
          return { ok: true, sealed: replay.sealed.toString("base64") };
      } else if (credential.rotation === f.rotation) {
        const admitted = await c.query(
          "UPDATE enrollment_spike.credential SET consumed_operation=$2 WHERE hash=$3 AND family_id=$1 AND consumed_operation IS NULL AND expires_at>clock_timestamp() AND EXISTS (SELECT 1 FROM enrollment_spike.recovery WHERE kind='rotate' AND subject_id=$1 AND operation_id=$2 AND credential_hash=$3 AND expires_at>clock_timestamp()) RETURNING hash",
          [family, operation, hash(token)],
        );
        if (admitted.rowCount === 1) {
          const credentials = await this.mint(c, family, f.rotation + 1);
          const sealed = this.seal(
            credentials,
            this.aad("rotate", family, operation, f.account_id, hash(token)),
          );
          await c.query(
            "UPDATE enrollment_spike.recovery SET sealed=$4 WHERE kind='rotate' AND subject_id=$1 AND operation_id=$2 AND account_id=$3",
            [family, operation, f.account_id, sealed],
          );
          return { ok: true, sealed: sealed.toString("base64") };
        }
      }
      await c.query(
        "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1",
        [family],
      );
      await c.query(
        "DELETE FROM enrollment_spike.recovery WHERE kind='rotate' AND subject_id=$1",
        [family],
      );
      return denied("REFRESH_REUSE");
    }, fault);
  }
  async revokeAccount(account: string, suspended: boolean) {
    canonicalUuid(account);
    return this.transaction(async (c) => {
      await this.account(c, account);
      await c.query(
        "UPDATE enrollment_spike.account SET access_epoch=access_epoch+1,state=$2 WHERE id=$1",
        [account, suspended ? "suspended" : "active"],
      );
      await c.query(
        "UPDATE enrollment_spike.family SET revoked=true WHERE account_id=$1",
        [account],
      );
      await c.query(
        "DELETE FROM enrollment_spike.recovery WHERE account_id=$1",
        [account],
      );
    });
  }
  async active(family: string, token: string): Promise<boolean> {
    canonicalUuid(family);
    return (
      (
        await this.pool.query(
          "SELECT 1 FROM enrollment_spike.family f JOIN enrollment_spike.account a ON a.id=f.account_id WHERE f.id=$1 AND f.access_hash=$2 AND f.access_expires_at>clock_timestamp() AND NOT f.revoked AND a.state='active' AND f.access_epoch=a.access_epoch",
          [family, hash(token)],
        )
      ).rowCount === 1
    );
  }
  async acknowledgeExchange(
    enrollment: string,
    operation: string,
    proof: Proof,
  ) {
    canonicalUuid(enrollment, operation);
    return this.transaction(async (c) => {
      const e = (
        await c.query("SELECT * FROM enrollment_spike.enrollment WHERE id=$1", [
          enrollment,
        ])
      ).rows[0];
      if (!e || e.consumed_operation !== operation)
        return denied("AUTH_REQUIRED");
      const a = await this.account(c, e.account_id);
      if (a.state !== "active" || e.access_epoch !== a.access_epoch)
        return denied("AUTH_REQUIRED");
      const family = (
        await c.query(
          "SELECT * FROM enrollment_spike.family WHERE enrollment_id=$1 AND account_id=$2",
          [enrollment, e.account_id],
        )
      ).rows[0];
      if (
        !family ||
        family.revoked ||
        family.confirmed ||
        family.access_epoch !== a.access_epoch
      )
        return denied("AUTH_REQUIRED");
      await this.verify(proof, e.expected, e.account_id);
      // Check the database clock at the effect, after proof verification and
      // account-lock waits. Transaction-start now() can precede receipt expiry.
      const confirmed = await c.query(
        "UPDATE enrollment_spike.family SET confirmed=true WHERE id=$1 AND NOT revoked AND NOT confirmed AND EXISTS (SELECT 1 FROM enrollment_spike.recovery WHERE kind='exchange' AND subject_id=$2 AND operation_id=$3 AND account_id=$4 AND sealed IS NOT NULL AND expires_at>clock_timestamp()) RETURNING id",
        [family.id, enrollment, operation, e.account_id],
      );
      if (confirmed.rowCount !== 1) {
        await c.query(
          "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1 AND NOT confirmed",
          [family.id],
        );
        await c.query(
          "DELETE FROM enrollment_spike.recovery WHERE kind='exchange' AND subject_id=$1",
          [enrollment],
        );
        return denied("RECOVERY_EXPIRED");
      }
      await c.query(
        "DELETE FROM enrollment_spike.recovery WHERE kind='exchange' AND subject_id=$1 AND operation_id=$2",
        [enrollment, operation],
      );
      return { ok: true };
    });
  }
  async purgeExpired() {
    // Lock accounts in a consistent order before revoke/receipt retention work.
    return this.transaction(async (c) => {
      await c.query(
        "SELECT id FROM enrollment_spike.account ORDER BY id FOR UPDATE",
      );
      await c.query(
        "WITH expired AS (DELETE FROM enrollment_spike.recovery WHERE expires_at<=clock_timestamp() RETURNING kind,subject_id) UPDATE enrollment_spike.family SET revoked=true WHERE NOT confirmed AND enrollment_id IN (SELECT subject_id FROM expired WHERE kind='exchange')",
      );
    });
  }
}

/** In-process per-host actor. SQL account locks enforce cross-process ordering. */
export class SingleFlight {
  private running = new Map<
    string,
    { operation: string; value: Promise<Outcome> }
  >();
  run(
    family: string,
    operation: string,
    start: () => Promise<Outcome>,
  ): Promise<Outcome> {
    canonicalUuid(family, operation);
    const prior = this.running.get(family);
    if (prior)
      return prior.operation === operation
        ? prior.value
        : Promise.resolve(denied("ROTATION_BUSY"));
    const value = Promise.resolve()
      .then(start)
      .finally(() => this.running.delete(family));
    this.running.set(family, { operation, value });
    return value;
  }
}
