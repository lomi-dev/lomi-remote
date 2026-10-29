/** Isolated proof using the actual pinned Better Auth handler. No network server. */
import { betterAuth } from "better-auth";
import { deviceAuthorization } from "better-auth/plugins/device-authorization";
import { bearer } from "better-auth/plugins/bearer";
import { makeSignature } from "better-auth/crypto";
import { Kysely, PostgresDialect, sql, type Transaction } from "kysely";
import { Pool } from "pg";
import { createHash, randomBytes, randomUUID } from "node:crypto";
export { Pool, makeSignature };
export const ORIGIN = "http://localhost:49321";
export const SECRET =
  "synthetic-auth-binding-secret-not-for-production-32chars";
export const digest = (value: string) =>
  createHash("sha256").update(value).digest();
const idBytes = (value: string) =>
  Array.from(Buffer.from(value.replaceAll("-", ""), "hex"));
const bytesUuid = (value: number[]) => {
  const hex = Buffer.from(value).toString("hex");
  return uuid(
    `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
  );
};
const uuid = (value: string) => {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(
      value,
    )
  )
    throw Error("canonical UUID required");
  return value;
};
type DB = Kysely<any> | Transaction<any>;
type Kind = "web" | "mobile" | "desktop" | "bootstrap";
export function options(db: DB, sessionKind: Kind = "desktop") {
  return {
    baseURL: ORIGIN,
    basePath: "/api/auth",
    secret: SECRET,
    trustedOrigins: [ORIGIN],
    logger: { disabled: true },
    emailAndPassword: { enabled: false },
    session: { cookieCache: { enabled: false }, updateAge: 86400 },
    rateLimit: { enabled: false },
    advanced: {
      useSecureCookies: false,
      database: {
        generateId: () => `ba_${randomUUID()}`,
        validateSchema: !db.isTransaction,
      },
    },
    database: {
      db,
      type: "postgres" as const,
      schemaName: "ba_fixture",
      transaction: false,
    },
    databaseHooks: {
      session: {
        create: {
          before: async (session: { userId: string }) => {
            const policy =
              await sql<any>`SELECT state FROM auth_binding.policy WHERE account_id=${session.userId}`.execute(
                db,
              );
            if (policy.rows[0]?.state !== "active") return false;
          },
          after: async (session: { id: string; userId: string }) => {
            await sql`INSERT INTO auth_binding.session_class(session_id,account_id,kind) VALUES(${session.id},${session.userId},${sessionKind})`.execute(
              db,
            );
          },
        },
      },
    },
    plugins: [
      deviceAuthorization({
        expiresIn: "5m",
        interval: "1s",
        validateClient: (client: string) =>
          ["lomi-desktop", "lomi-remote-host", "lomi-mobile"].includes(client),
        verificationUri: `${ORIGIN}/device`,
      }),
      bearer(),
    ],
  };
}
export function auth(db: DB, kind: Kind = "desktop") {
  return betterAuth(options(db, kind));
}
export const post = (path: string, body: unknown, headers: HeadersInit = {}) =>
  new Request(`${ORIGIN}/api/auth${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: ORIGIN,
      ...Object.fromEntries(new Headers(headers)),
    },
    body: JSON.stringify(body),
  });
export async function fixture(
  mode:
    | "bundle"
    | "fingerprint"
    | "sign"
    | "verify"
    | "pending-host"
    | "verify-host-key"
    | "derive-host-binding"
    | "pending-sign"
    | "verify-committed",
  value?: unknown,
): Promise<any> {
  const binary = process.env.ENROLLMENT_FIXTURE_BINARY;
  if (!binary) throw Error("canonical fixture missing");
  const child = Bun.spawn([binary, mode], {
    stdin:
      value === undefined
        ? "ignore"
        : new TextEncoder().encode(JSON.stringify(value)),
    stdout: "pipe",
    stderr: "ignore",
    env: {},
  });
  const timer = setTimeout(() => child.kill(), 5000);
  try {
    const output = await new Response(child.stdout).text();
    if ((await child.exited) !== 0 || output.length > 16384)
      throw Error("canonical proof rejected");
    return mode === "verify" || mode === "verify-committed"
      ? true
      : JSON.parse(output);
  } finally {
    clearTimeout(timer);
  }
}

export class BindingProof {
  readonly db: Kysely<any>;
  constructor(readonly pool: Pool) {
    this.db = new Kysely({ dialect: new PostgresDialect({ pool }) });
  }
  async transaction<T>(run: (db: Transaction<any>) => Promise<T>): Promise<T> {
    return this.db.transaction().execute(async (db) => {
      await sql`SET LOCAL statement_timeout='7s'`.execute(db);
      // Deliberately coarse proof lock, shared by all auth mutation/revoke paths.
      await sql`SELECT pg_advisory_xact_lock(63421788)`.execute(db);
      return run(db);
    });
  }
  async raw(request: Request) {
    if (new URL(request.url).pathname !== "/api/auth/device/code")
      throw Error("binding coordinator required");
    return this.transaction((db) => auth(db).handler(request));
  }
  async beginHost(signed: unknown, pin: number[]) {
    // The canonical API validates the account-independent descriptor before the
    // handler creates a device code. No approved account or bound bundle exists.
    const initial = await fixture("verify-host-key", { signed, pin });
    const hostId = bytesUuid(initial.descriptor.hostId);
    return this.transaction(async (db) => {
      const response = await auth(db).handler(
        post("/device/code", { client_id: "lomi-remote-host" }),
      );
      if (response.status !== 200) throw Error("device creation failed");
      const code = (await response.json()) as {
        device_code: string;
        user_code: string;
      };
      const id = randomUUID(),
        bootstrap = randomUUID(),
        operation = randomUUID();
      await sql`INSERT INTO auth_binding.enrollment(id,host_id,initial_commitment,signed_key,device_hash,bootstrap_id,operation_id,expires_at,nonce) VALUES(${id},${hostId},${Buffer.from(initial.commitment)},${JSON.stringify(signed)}::jsonb,${digest(code.device_code)},${bootstrap},${operation},clock_timestamp()+interval '5 minutes',${randomBytes(32)})`.execute(
        db,
      );
      return { ...code, enrollment: id, bootstrap, operation };
    });
  }
  async approve(userCode: string, cookie: string) {
    return this.transaction(async (db) => {
      const handler = auth(db);
      const session = await handler.api.getSession({
        headers: new Headers({ cookie }),
      });
      if (!session) return new Response(null, { status: 401 });
      const classification = (
        await sql<any>`SELECT kind FROM auth_binding.session_class WHERE session_id=${session.session.id}`.execute(
          db,
        )
      ).rows[0];
      if (classification?.kind !== "web")
        return new Response(null, { status: 403 });
      const policy = (
        await sql<any>`SELECT * FROM auth_binding.policy WHERE account_id=${session.user.id} AND state='active'`.execute(
          db,
        )
      ).rows[0];
      if (!policy) return new Response(null, { status: 403 });
      const code = (
        await sql<any>`SELECT * FROM ba_fixture."deviceCode" WHERE "userCode"=${userCode}`.execute(
          db,
        )
      ).rows[0];
      if (!code) return new Response(null, { status: 400 });
      // The real handler binds the claim to the authenticated browser account.
      const claim = await handler.handler(
        new Request(
          `${ORIGIN}/api/auth/device?user_code=${encodeURIComponent(userCode)}`,
          { headers: { cookie, origin: ORIGIN } },
        ),
      );
      if (claim.status !== 200) return claim;
      const approved = await handler.handler(
        post("/device/approve", { userCode }, { cookie }),
      );
      if (approved.status !== 200) return approved;
      const enrollment = (
        await sql<any>`SELECT * FROM auth_binding.enrollment WHERE device_hash=${digest(code.deviceCode)}`.execute(
          db,
        )
      ).rows[0];
      if (enrollment) {
        // Derive from immutable init bytes plus the server-approved account.
        // Token requests never supply a replacement key descriptor or bundle.
        const bound = await fixture("derive-host-binding", {
          signed: enrollment.signed_key,
          pin: Array.from(enrollment.initial_commitment as Buffer),
          account: idBytes(policy.remote_account_id),
        });
        const updated =
          await sql`UPDATE auth_binding.enrollment SET account_id=${session.user.id},approved=true,epoch=${policy.epoch},fingerprint=${Buffer.from(bound.fingerprint)} WHERE id=${enrollment.id} AND NOT approved AND expires_at>clock_timestamp() RETURNING id`.execute(
            db,
          );
        if (updated.rows.length !== 1)
          throw Error("enrollment expired or already bound");
      }
      return approved;
    });
  }
  async redeem(
    deviceCode: string,
    clientId: string,
    untrusted: Record<string, unknown> = {},
    failAfterSession = false,
  ) {
    return this.transaction(async (db) => {
      const e = (
        await sql<any>`SELECT e.*,e.expires_at>clock_timestamp() AS live,p.state,p.epoch AS current_epoch FROM auth_binding.enrollment e LEFT JOIN auth_binding.policy p ON p.account_id=e.account_id WHERE e.device_hash=${digest(deviceCode)}`.execute(
          db,
        )
      ).rows[0];
      if (
        e &&
        (!e.approved ||
          e.revoked ||
          e.state !== "active" ||
          e.epoch !== e.current_epoch ||
          !e.live)
      )
        return new Response(null, { status: 403 });
      // Only an already approved server record selects bootstrap; client/body does not.
      const handler = auth(db, e ? "bootstrap" : "desktop");
      const response = await handler.handler(
        post("/device/token", {
          ...untrusted,
          grant_type: "urn:ietf:params:oauth:grant-type:device_code",
          device_code: deviceCode,
          client_id: clientId,
        }),
      );
      if (response.status !== 200) return response;
      const body = (await response.clone().json()) as { access_token: string };
      const session = (
        await sql<any>`SELECT id,"userId" FROM ba_fixture.session WHERE token=${body.access_token}`.execute(
          db,
        )
      ).rows[0];
      if (!session) throw Error("issued session missing");
      if (e) {
        if (session.userId !== e.account_id)
          throw Error("bootstrap owner mismatch");
        const mapped =
          await sql`INSERT INTO auth_binding.bootstrap(id,enrollment_id,account_id,session_id) SELECT ${e.bootstrap_id},${e.id},${e.account_id},${session.id} FROM auth_binding.enrollment WHERE id=${e.id} AND expires_at>clock_timestamp() RETURNING id`.execute(
            db,
          );
        if (mapped.rows.length !== 1)
          throw Error("enrollment expired before bootstrap binding");
      }
      if (failAfterSession)
        throw Error("synthetic rollback after handler session creation");
      return response;
    });
  }
  async challenge(enrollment: string) {
    uuid(enrollment);
    const e = (
      await sql<any>`SELECT * FROM auth_binding.enrollment WHERE id=${enrollment}`.execute(
        this.db,
      )
    ).rows[0];
    if (!e?.approved || !e.fingerprint)
      throw Error("approved enrollment required");
    return {
      version: 1,
      enrollmentId: idBytes(e.id),
      hostId: idBytes(e.host_id),
      hostKeyFingerprint: Array.from(e.fingerprint as Buffer),
      bootstrapSessionId: idBytes(e.bootstrap_id),
      audience: "lomi-remote-host-enrollment",
      expiresAt: String(Math.floor(e.expires_at.getTime() / 1000)),
      nonce: Array.from(e.nonce as Buffer),
      operationId: idBytes(e.operation_id),
    };
  }
  async exchange(token: string, operation: string, proof: unknown) {
    uuid(operation);
    return this.transaction(async (db) => {
      const handler = auth(db);
      const session = await handler.api.getSession({
        headers: new Headers({ authorization: `Bearer ${token}` }),
      });
      if (!session) throw Error("bootstrap session required");
      const binding = (
        await sql<any>`SELECT b.*,e.operation_id,e.host_id,e.fingerprint,e.signed_key,e.initial_commitment,e.expires_at,e.nonce,e.epoch,e.revoked,p.remote_account_id,p.state,p.epoch AS current_epoch FROM auth_binding.bootstrap b JOIN auth_binding.enrollment e ON e.id=b.enrollment_id JOIN auth_binding.policy p ON p.account_id=b.account_id WHERE b.session_id=${session.session.id}`.execute(
          db,
        )
      ).rows[0];
      if (
        !binding ||
        binding.consumed ||
        binding.revoked ||
        binding.operation_id !== operation ||
        binding.state !== "active" ||
        binding.epoch !== binding.current_epoch
      )
        throw Error("enrollment binding rejected");
      const expected = {
        version: 1,
        enrollmentId: idBytes(binding.enrollment_id),
        hostId: idBytes(binding.host_id),
        hostKeyFingerprint: Array.from(binding.fingerprint as Buffer),
        bootstrapSessionId: idBytes(binding.id),
        audience: "lomi-remote-host-enrollment",
        expiresAt: String(Math.floor(binding.expires_at.getTime() / 1000)),
        nonce: Array.from(binding.nonce as Buffer),
        operationId: idBytes(binding.operation_id),
      };
      await fixture("verify-committed", {
        proof,
        expected,
        signed: binding.signed_key,
        pin: Array.from(binding.initial_commitment as Buffer),
        account: idBytes(binding.remote_account_id),
        now: Math.floor(Date.now() / 1000),
      });
      const result =
        await sql`UPDATE auth_binding.bootstrap SET consumed=true WHERE id=${binding.id} AND NOT consumed AND EXISTS(SELECT 1 FROM auth_binding.enrollment WHERE id=${binding.enrollment_id} AND expires_at>clock_timestamp()) RETURNING id`.execute(
          db,
        );
      if (result.rows.length !== 1)
        throw Error("bootstrap expired or consumed");
      const id = randomUUID();
      await sql`INSERT INTO auth_binding.host_authorization(id,enrollment_id,account_id,epoch) VALUES(${id},${binding.enrollment_id},${binding.account_id},${binding.epoch})`.execute(
        db,
      );
      await sql`UPDATE ba_fixture.session SET "expiresAt"=clock_timestamp() WHERE id=${session.session.id}`.execute(
        db,
      );
      return id;
    });
  }
  async hostAllowed(authorization: string) {
    uuid(authorization);
    return (
      (
        await sql`SELECT 1 FROM auth_binding.host_authorization h JOIN auth_binding.policy p ON p.account_id=h.account_id WHERE h.id=${authorization} AND NOT h.revoked AND p.state='active' AND p.epoch=h.epoch`.execute(
          this.db,
        )
      ).rows.length === 1
    );
  }
  async consumer(token: string) {
    return this.transaction(async (db) => {
      const session = await auth(db).api.getSession({
        headers: new Headers({ authorization: `Bearer ${token}` }),
      });
      if (!session) throw Error("account session required");
      const row = (
        await sql<any>`SELECT c.*,p.epoch,p.state FROM auth_binding.session_class c JOIN auth_binding.policy p ON p.account_id=c.account_id WHERE c.session_id=${session.session.id}`.execute(
          db,
        )
      ).rows[0];
      if (!row || row.kind === "bootstrap" || row.state !== "active")
        throw Error("consumer class rejected");
      const existing = (
        await sql<any>`SELECT id FROM auth_binding.consumer WHERE coalesce(web_session_id,mobile_session_id,desktop_session_id)=${row.session_id}`.execute(
          db,
        )
      ).rows[0];
      if (existing) return existing.id as string;
      const id = randomUUID();
      await sql`INSERT INTO auth_binding.consumer(id,account_id,kind,web_session_id,mobile_session_id,desktop_session_id,epoch) VALUES(${id},${row.account_id},${row.kind},${row.kind === "web" ? row.session_id : null},${row.kind === "mobile" ? row.session_id : null},${row.kind === "desktop" ? row.session_id : null},${row.epoch})`.execute(
        db,
      );
      return id;
    });
  }
  async attach(consumer: string, fingerprint: Buffer) {
    uuid(consumer);
    return this.transaction(async (db) => {
      const live = await this.liveConsumer(db, consumer);
      if (!live) throw Error("consumer not active");
      const id = randomUUID();
      await sql`INSERT INTO auth_binding.window_key(id,consumer_id,fingerprint) VALUES(${id},${consumer},${fingerprint})`.execute(
        db,
      );
      return id;
    });
  }
  private async liveConsumer(db: DB, id: string) {
    return (
      (
        await sql`SELECT 1 FROM auth_binding.consumer c JOIN auth_binding.policy p ON p.account_id=c.account_id JOIN ba_fixture.session s ON s.id=coalesce(c.web_session_id,c.mobile_session_id,c.desktop_session_id) WHERE c.id=${id} AND p.state='active' AND p.epoch=c.epoch AND s."expiresAt">clock_timestamp()`.execute(
          db,
        )
      ).rows.length === 1
    );
  }
  async refreshWindow(
    consumer: string,
    oldWindow: string,
    fingerprint: Buffer,
  ) {
    uuid(consumer);
    uuid(oldWindow);
    return this.transaction(async (db) => {
      if (!(await this.liveConsumer(db, consumer)))
        throw Error("consumer not active");
      const old =
        await sql`UPDATE auth_binding.window_key SET retired=true WHERE id=${oldWindow} AND consumer_id=${consumer} AND NOT retired RETURNING id`.execute(
          db,
        );
      if (old.rows.length !== 1) throw Error("window missing");
      const id = randomUUID();
      await sql`INSERT INTO auth_binding.window_key(id,consumer_id,fingerprint) VALUES(${id},${consumer},${fingerprint})`.execute(
        db,
      );
      return id;
    });
  }
  async windowAllowed(id: string) {
    uuid(id);
    return (
      (
        await sql`SELECT 1 FROM auth_binding.window_key w JOIN auth_binding.consumer c ON c.id=w.consumer_id JOIN auth_binding.policy p ON p.account_id=c.account_id JOIN ba_fixture.session s ON s.id=coalesce(c.web_session_id,c.mobile_session_id,c.desktop_session_id) WHERE w.id=${id} AND NOT w.retired AND p.state='active' AND p.epoch=c.epoch AND s."expiresAt">clock_timestamp()`.execute(
          this.db,
        )
      ).rows.length === 1
    );
  }
  async signOut(token: string) {
    return this.transaction((db) =>
      auth(db).handler(
        post("/sign-out", {}, { authorization: `Bearer ${token}` }),
      ),
    );
  }
  async globalRevoke(account: string, suspended: boolean) {
    return this.transaction(async (db) => {
      await sql`UPDATE auth_binding.policy SET epoch=epoch+1,state=${suspended ? "suspended" : "active"} WHERE account_id=${account}`.execute(
        db,
      );
      await sql`UPDATE auth_binding.enrollment SET revoked=true WHERE account_id=${account}`.execute(
        db,
      );
      await sql`UPDATE auth_binding.host_authorization SET revoked=true WHERE account_id=${account}`.execute(
        db,
      );
      await sql`DELETE FROM ba_fixture.session WHERE "userId"=${account}`.execute(
        db,
      );
      await sql`DELETE FROM ba_fixture."deviceCode" WHERE "userId"=${account}`.execute(
        db,
      );
    });
  }
}
