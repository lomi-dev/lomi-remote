import { afterAll, beforeEach, expect, test } from "bun:test";
import {
  Pool,
  Store,
  SingleFlight,
  rust,
  bytes,
  uuid,
  type Challenge,
  type Outcome,
} from "../../packages/enrollment-spike/store.ts";
const pool = new Pool({
  connectionString: process.env.ENROLLMENT_TEST_URL,
  max: 12,
});
const owner = new Pool({
  connectionString: process.env.ENROLLMENT_OWNER_URL,
  max: 2,
});
const key = Buffer.from(process.env.ENROLLMENT_RECOVERY_KEY!, "hex");
const store = new Store(pool, key);
const account = "01010101-0101-0101-0101-010101010101";
let enrollment: string,
  operation: string,
  bootstrap: string,
  challenge: Challenge;
let request: Parameters<Store["exchange"]>[0];
beforeEach(async () => {
  await owner.query("TRUNCATE enrollment_spike.account CASCADE");
  await owner.query("INSERT INTO enrollment_spike.account(id) VALUES($1)", [
    account,
  ]);
  enrollment = uuid();
  operation = uuid();
  bootstrap = uuid();
  challenge = {
    version: 1,
    enrollmentId: bytes(enrollment),
    hostId: Array(16).fill(2),
    hostKeyFingerprint: await rust("fingerprint"),
    bootstrapSessionId: bytes(bootstrap),
    audience: "lomi-remote-host-enrollment",
    expiresAt: String(Math.floor(Date.now() / 1000) + 300),
    nonce: Array(32).fill(9),
    operationId: bytes(operation),
  };
  await owner.query(
    "INSERT INTO enrollment_spike.enrollment(id,account_id,access_epoch,host_id,host_fingerprint,bootstrap_session_id,client_class,expected,approved) VALUES($1,$2,1,$3,$4,$5,'host-enrollment',$6,true)",
    [
      enrollment,
      account,
      "02020202-0202-0202-0202-020202020202",
      Buffer.from(challenge.hostKeyFingerprint),
      bootstrap,
      challenge,
    ],
  );
  request = {
    enrollment,
    operation,
    bootstrapSession: bootstrap,
    clientClass: "host-enrollment",
    proof: await rust("sign", challenge),
  };
});
afterAll(async () => {
  await pool.end();
  await owner.end();
});
function sealed(result: Outcome) {
  if (!result.ok) throw new Error("expected secured result");
  return result.sealed;
}
async function enrolled() {
  const result = await store.exchange(request);
  return store.open(sealed(result), "exchange", enrollment, operation, account);
}
async function prepared(family: string, token: string, op = uuid()) {
  const c = await store.rotationChallenge(family, token, op);
  if (!("version" in c)) throw new Error("expected challenge");
  return { op, proof: await rust("sign", c) };
}
async function crash(input: unknown, exit: number) {
  const p = Bun.spawn(
    [process.execPath, "--no-env-file", `${import.meta.dir}/crash-worker.ts`],
    {
      stdin: new TextEncoder().encode(JSON.stringify(input)),
      stdout: "ignore",
      stderr: "ignore",
      env: { ...process.env },
    },
  );
  const timer = setTimeout(() => p.kill(), 10000);
  try {
    expect(await p.exited).toBe(exit);
  } finally {
    clearTimeout(timer);
  }
}

test("limited runtime role, immutable approved enrollment and SQL ownership constraints", async () => {
  expect(
    (
      await pool.query(
        "SELECT rolsuper,rolcreatedb FROM pg_roles WHERE rolname=current_user",
      )
    ).rows[0],
  ).toEqual({ rolsuper: false, rolcreatedb: false });
  await expect(
    pool.query("CREATE TABLE public.escape(id int)"),
  ).rejects.toBeDefined();
  await expect(
    pool.query(
      "UPDATE enrollment_spike.enrollment SET host_id=$1 WHERE id=$2",
      [uuid(), enrollment],
    ),
  ).rejects.toBeDefined();
  await expect(
    owner.query(
      "UPDATE enrollment_spike.enrollment SET bootstrap_session_id=$1 WHERE id=$2",
      [uuid(), enrollment],
    ),
  ).rejects.toBeDefined();
  await expect(
    owner.query(
      "UPDATE enrollment_spike.enrollment SET client_class='web' WHERE id=$1",
      [enrollment],
    ),
  ).rejects.toBeDefined();
  expect(
    (await pool.query("SELECT count(*)::int AS n FROM enrollment_spike.family"))
      .rows[0].n,
  ).toBe(0);
});

test("exchange requires exact bootstrap, class, operation and canonical Rust proof", async () => {
  expect(
    (await store.exchange({ ...request, bootstrapSession: uuid() })).ok,
  ).toBe(false);
  expect((await store.exchange({ ...request, clientClass: "web" })).ok).toBe(
    false,
  );
  expect((await store.exchange({ ...request, operation: uuid() })).ok).toBe(
    false,
  );
  const tampered = structuredClone(request);
  tampered.proof.challenge.nonce[0] ^= 1;
  await expect(store.exchange(tampered)).rejects.toBeDefined();
  expect(
    (await pool.query("SELECT count(*)::int AS n FROM enrollment_spike.family"))
      .rows[0].n,
  ).toBe(0);
});

test("concurrent exchange is one family and byte-identical encrypted recovery", async () => {
  const results = await Promise.all(
    Array.from({ length: 8 }, () => store.exchange(request)),
  );
  expect(results.every((r) => r.ok)).toBe(true);
  expect(new Set(results.map(sealed)).size).toBe(1);
  expect(
    (await pool.query("SELECT count(*)::int AS n FROM enrollment_spike.family"))
      .rows[0].n,
  ).toBe(1);
  const credentials = store.open(
    sealed(results[0]),
    "exchange",
    enrollment,
    operation,
    account,
  );
  expect(await store.active(credentials.family, credentials.access)).toBe(true);
  const db =
    JSON.stringify(
      (await pool.query("SELECT * FROM enrollment_spike.family")).rows,
    ) +
    JSON.stringify(
      (await pool.query("SELECT * FROM enrollment_spike.credential")).rows,
    ) +
    JSON.stringify(
      (await pool.query("SELECT * FROM enrollment_spike.recovery")).rows,
    );
  expect(db.includes(credentials.refresh)).toBe(false);
  expect(db.includes(credentials.access)).toBe(false);
  expect(() =>
    store.open(sealed(results[0]), "exchange", enrollment, uuid(), account),
  ).toThrow();
  await store.acknowledgeExchange(enrollment, operation, request.proof);
  expect((await store.exchange(request)).ok).toBe(false);
});

test("same rotation operation recovers exact ciphertext; singleflight and SQL serialize", async () => {
  const credentials = await enrolled();
  const { op, proof } = await prepared(credentials.family, credentials.refresh);
  const actor = new SingleFlight();
  let started = 0;
  const invoke = () =>
    actor.run(credentials.family, op, async () => {
      started++;
      return store.rotate(credentials.family, credentials.refresh, op, proof);
    });
  const first = invoke(),
    second = invoke();
  expect(
    (
      await actor.run(credentials.family, uuid(), async () => {
        throw new Error("must not execute");
      })
    ).ok,
  ).toBe(false);
  const results = await Promise.all([
    first,
    second,
    store.rotate(credentials.family, credentials.refresh, op, proof),
  ]);
  expect(started).toBe(1);
  expect(new Set(results.map(sealed)).size).toBe(1);
  const next = store.open(
    sealed(results[0]),
    "rotate",
    credentials.family,
    op,
    account,
    credentials.refresh,
  );
  expect(next.refresh === credentials.refresh).toBe(false);
  expect(
    (
      await pool.query(
        "SELECT count(*)::int AS n FROM enrollment_spike.credential",
      )
    ).rows[0].n,
  ).toBe(2);
  expect(await store.active(credentials.family, credentials.access)).toBe(
    false,
  );
  expect(await store.active(next.family, next.access)).toBe(true);
});

test("cross-operation refresh reuse revokes the whole family", async () => {
  const credentials = await enrolled();
  const { op, proof } = await prepared(credentials.family, credentials.refresh);
  const rotated = await store.rotate(
    credentials.family,
    credentials.refresh,
    op,
    proof,
  );
  const next = store.open(
    sealed(rotated),
    "rotate",
    credentials.family,
    op,
    account,
    credentials.refresh,
  );
  expect(
    (
      (await store.rotationChallenge(
        credentials.family,
        credentials.refresh,
        uuid(),
      )) as Outcome
    ).ok,
  ).toBe(false);
  expect(await store.active(next.family, next.access)).toBe(false);
  expect(
    (await store.rotate(credentials.family, credentials.refresh, op, proof)).ok,
  ).toBe(false);
});

test("expired recovery is removed and cannot resurrect consumed credentials", async () => {
  const credentials = await enrolled();
  const { op, proof } = await prepared(credentials.family, credentials.refresh);
  await store.rotate(credentials.family, credentials.refresh, op, proof);
  await owner.query(
    "UPDATE enrollment_spike.recovery SET expires_at=now()-interval '1 second' WHERE kind='rotate'",
  );
  await store.purgeExpired();
  expect(
    (await store.rotate(credentials.family, credentials.refresh, op, proof)).ok,
  ).toBe(false);
  expect(
    (await pool.query("SELECT revoked FROM enrollment_spike.family")).rows[0]
      .revoked,
  ).toBe(true);
});

test("global revoke races refresh and exchange; reactivation never revives old state", async () => {
  const credentials = await enrolled();
  const { op, proof } = await prepared(credentials.family, credentials.refresh);
  await Promise.all([
    store.rotate(credentials.family, credentials.refresh, op, proof),
    store.revokeAccount(account, true),
    store.exchange(request),
  ]);
  expect(await store.active(credentials.family, credentials.access)).toBe(
    false,
  );
  await store.revokeAccount(account, false);
  expect((await store.exchange(request)).ok).toBe(false);
  expect(
    (
      (await store.rotationChallenge(
        credentials.family,
        credentials.refresh,
        op,
      )) as Outcome
    ).ok,
  ).toBe(false);
  expect(
    (
      await pool.query(
        "SELECT count(*)::int AS n FROM enrollment_spike.recovery",
      )
    ).rows[0].n,
  ).toBe(0);
  expect(
    (await pool.query("SELECT access_epoch FROM enrollment_spike.account"))
      .rows[0].access_epoch,
  ).toBe("3");
});

for (const fault of [
  "before_commit",
  "after_commit",
  "after_receipt",
] as const) {
  test(`exchange process crash ${fault} recovers one family`, async () => {
    await crash(
      { kind: "exchange", request, fault },
      fault === "before_commit" ? 71 : fault === "after_commit" ? 72 : 73,
    );
    const credentials = await enrolled();
    expect(await store.active(credentials.family, credentials.access)).toBe(
      true,
    );
    expect(
      (
        await pool.query(
          "SELECT count(*)::int AS n FROM enrollment_spike.family",
        )
      ).rows[0].n,
    ).toBe(1);
  });
  test(`rotation process crash ${fault} never creates a second rotation`, async () => {
    const credentials = await enrolled();
    const { op, proof } = await prepared(
      credentials.family,
      credentials.refresh,
    );
    await crash(
      {
        kind: "rotate",
        family: credentials.family,
        token: credentials.refresh,
        operation: op,
        proof,
        fault,
      },
      fault === "before_commit" ? 71 : fault === "after_commit" ? 72 : 73,
    );
    const result = await store.rotate(
      credentials.family,
      credentials.refresh,
      op,
      proof,
    );
    const next = store.open(
      sealed(result),
      "rotate",
      credentials.family,
      op,
      account,
      credentials.refresh,
    );
    expect(await store.active(next.family, next.access)).toBe(true);
    expect(
      (
        await pool.query(
          "SELECT count(*)::int AS n FROM enrollment_spike.credential",
        )
      ).rows[0].n,
    ).toBe(2);
    expect(
      (await pool.query("SELECT rotation FROM enrollment_spike.family")).rows[0]
        .rotation,
    ).toBe(1);
  });
}

test("old pending approval cannot enroll after global revoke/reactivation", async () => {
  await store.revokeAccount(account, true);
  await store.revokeAccount(account, false);
  expect((await store.exchange(request)).ok).toBe(false);
  expect(
    (await pool.query("SELECT count(*)::int AS n FROM enrollment_spike.family"))
      .rows[0].n,
  ).toBe(0);
});

test("family SQL FK rejects an account different from the enrollment", async () => {
  const other = uuid();
  await owner.query("INSERT INTO enrollment_spike.account(id) VALUES($1)", [
    other,
  ]);
  await expect(
    owner.query(
      "INSERT INTO enrollment_spike.family(id,enrollment_id,account_id,access_epoch,access_hash,access_expires_at) VALUES($1,$2,$3,1,$4,now())",
      [uuid(), enrollment, other, Buffer.alloc(32)],
    ),
  ).rejects.toBeDefined();
});

test("unconfirmed exchange recovery expiry revokes its credential family", async () => {
  const credentials = await enrolled();
  await owner.query(
    "UPDATE enrollment_spike.recovery SET expires_at=now()-interval '1 second' WHERE kind='exchange'",
  );
  await store.purgeExpired();
  expect(await store.active(credentials.family, credentials.access)).toBe(
    false,
  );
  expect((await store.exchange(request)).ok).toBe(false);
});

test("rotation proof tamper leaves the existing credential usable", async () => {
  const credentials = await enrolled();
  const { op, proof } = await prepared(credentials.family, credentials.refresh);
  proof.challenge.audience += "-changed";
  await expect(
    store.rotate(credentials.family, credentials.refresh, op, proof),
  ).rejects.toBeDefined();
  expect(await store.active(credentials.family, credentials.access)).toBe(true);
  expect(
    (await pool.query("SELECT rotation FROM enrollment_spike.family")).rows[0]
      .rotation,
  ).toBe(0);
});

test("expired exchange receipt cannot be acknowledged with the longer-lived proof", async () => {
  const credentials = await enrolled();
  await owner.query(
    "UPDATE enrollment_spike.recovery SET expires_at=clock_timestamp()-interval '1 second' WHERE kind='exchange'",
  );
  expect(
    (await store.acknowledgeExchange(enrollment, operation, request.proof)).ok,
  ).toBe(false);
  await store.purgeExpired();
  expect(await store.active(credentials.family, credentials.access)).toBe(
    false,
  );
  expect(
    (await pool.query("SELECT confirmed,revoked FROM enrollment_spike.family"))
      .rows[0],
  ).toEqual({ confirmed: false, revoked: true });
  expect(
    (
      await pool.query(
        "SELECT count(*)::int AS n FROM enrollment_spike.recovery",
      )
    ).rows[0].n,
  ).toBe(0);
});

test("missing exchange receipt revokes unconfirmed family and denies acknowledgement", async () => {
  const credentials = await enrolled();
  await owner.query(
    "DELETE FROM enrollment_spike.recovery WHERE kind='exchange'",
  );
  expect(
    (await store.acknowledgeExchange(enrollment, operation, request.proof)).ok,
  ).toBe(false);
  expect(await store.active(credentials.family, credentials.access)).toBe(
    false,
  );
  expect(
    (await pool.query("SELECT confirmed,revoked FROM enrollment_spike.family"))
      .rows[0],
  ).toEqual({ confirmed: false, revoked: true });
});

test("acknowledgement and expired-receipt purge serialize to a revoked family", async () => {
  const credentials = await enrolled();
  await owner.query(
    "UPDATE enrollment_spike.recovery SET expires_at=clock_timestamp()-interval '1 second' WHERE kind='exchange'",
  );
  const [ack] = await Promise.all([
    store.acknowledgeExchange(enrollment, operation, request.proof),
    store.purgeExpired(),
    store.acknowledgeExchange(enrollment, operation, request.proof),
  ]);
  expect(ack.ok).toBe(false);
  expect(await store.active(credentials.family, credentials.access)).toBe(
    false,
  );
  expect(
    (await pool.query("SELECT confirmed,revoked FROM enrollment_spike.family"))
      .rows[0],
  ).toEqual({ confirmed: false, revoked: true });
});

test("a live acknowledgement survives purge and rejects duplicate or revoked acknowledgements", async () => {
  const credentials = await enrolled();
  const [ack] = await Promise.all([
    store.acknowledgeExchange(enrollment, operation, request.proof),
    store.purgeExpired(),
  ]);
  expect(ack.ok).toBe(true);
  expect(await store.active(credentials.family, credentials.access)).toBe(true);
  expect(
    (await store.acknowledgeExchange(enrollment, operation, request.proof)).ok,
  ).toBe(false);
  await store.revokeAccount(account, false);
  expect(
    (await store.acknowledgeExchange(enrollment, operation, request.proof)).ok,
  ).toBe(false);
});

test("acknowledgement checks expiry after an account-lock wait", async () => {
  const credentials = await enrolled();
  const blocker = await owner.connect();
  let pending: Promise<unknown> | undefined;
  try {
    await blocker.query("BEGIN");
    await blocker.query(
      "SELECT id FROM enrollment_spike.account WHERE id=$1 FOR UPDATE",
      [account],
    );
    pending = store.acknowledgeExchange(enrollment, operation, request.proof);
    // Wait for the competing transaction to reach the lock, not a timed sleep.
    let blocked = false;
    for (let i = 0; i < 100; i++) {
      const result = await owner.query(
        "SELECT 1 FROM pg_stat_activity WHERE usename='e0_runtime' AND wait_event_type='Lock' AND query LIKE 'SELECT * FROM enrollment_spike.account%' LIMIT 1",
      );
      if (result.rowCount === 1) {
        blocked = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(blocked).toBe(true);
    // The ack transaction already began while the original receipt was live.
    await blocker.query(
      "UPDATE enrollment_spike.recovery SET expires_at=clock_timestamp() WHERE kind='exchange'",
    );
    await blocker.query("COMMIT");
    const ack = (await pending) as { ok: boolean };
    expect(ack.ok).toBe(false);
    expect(await store.active(credentials.family, credentials.access)).toBe(
      false,
    );
  } finally {
    await blocker.query("ROLLBACK");
    blocker.release();
    await pending;
  }
});

test("already-revoked family in the current account epoch cannot acknowledge", async () => {
  const credentials = await enrolled();
  await owner.query(
    "UPDATE enrollment_spike.family SET revoked=true WHERE id=$1",
    [credentials.family],
  );
  expect(
    (await store.acknowledgeExchange(enrollment, operation, request.proof)).ok,
  ).toBe(false);
  expect(
    (await pool.query("SELECT confirmed FROM enrollment_spike.family")).rows[0]
      .confirmed,
  ).toBe(false);
});

test("noncanonical operation UUID never rotates or revokes; canonical exact retry recovers", async () => {
  const credentials = await enrolled();
  const op = "abcdefab-cdef-4abc-8def-abcdefabcdef";
  const { proof } = await prepared(credentials.family, credentials.refresh, op);
  await expect(
    store.rotationChallenge(
      credentials.family,
      credentials.refresh,
      op.toUpperCase(),
    ),
  ).rejects.toThrow("canonical lowercase UUID");
  await expect(
    store.rotate(
      credentials.family,
      credentials.refresh,
      op.toUpperCase(),
      proof,
    ),
  ).rejects.toThrow("canonical lowercase UUID");
  expect(
    (await pool.query("SELECT rotation,revoked FROM enrollment_spike.family"))
      .rows[0],
  ).toEqual({ rotation: 0, revoked: false });
  const first = await store.rotate(
    credentials.family,
    credentials.refresh,
    op,
    proof,
  );
  await expect(
    store.rotate(
      credentials.family,
      credentials.refresh,
      op.toUpperCase(),
      proof,
    ),
  ).rejects.toThrow("canonical lowercase UUID");
  expect(
    sealed(
      await store.rotate(credentials.family, credentials.refresh, op, proof),
    ),
  ).toBe(sealed(first));
  expect(
    (await pool.query("SELECT rotation,revoked FROM enrollment_spike.family"))
      .rows[0],
  ).toEqual({ rotation: 1, revoked: false });
});

test("all public store UUID scopes reject noncanonical text before effects", async () => {
  const credentials = await enrolled();
  const uppercase = "ABCDEFAB-CDEF-4ABC-8DEF-ABCDEFABCDEF";
  for (const bad of [
    uppercase,
    uppercase.toLowerCase().replaceAll("-", ""),
    ` ${operation}`,
  ]) {
    for (const field of [
      "enrollment",
      "operation",
      "bootstrapSession",
    ] as const)
      await expect(
        store.exchange({ ...request, [field]: bad }),
      ).rejects.toThrow("canonical lowercase UUID");
    await expect(
      store.rotationChallenge(bad, credentials.refresh, operation),
    ).rejects.toThrow("canonical lowercase UUID");
    await expect(
      store.rotate(bad, credentials.refresh, operation, request.proof),
    ).rejects.toThrow("canonical lowercase UUID");
    await expect(store.active(bad, credentials.access)).rejects.toThrow(
      "canonical lowercase UUID",
    );
    await expect(store.revokeAccount(bad, false)).rejects.toThrow(
      "canonical lowercase UUID",
    );
    await expect(
      store.acknowledgeExchange(bad, operation, request.proof),
    ).rejects.toThrow("canonical lowercase UUID");
    await expect(
      store.acknowledgeExchange(enrollment, bad, request.proof),
    ).rejects.toThrow("canonical lowercase UUID");
    const envelope = sealed(await store.exchange(request));
    expect(() =>
      store.open(envelope, "exchange", bad, operation, account),
    ).toThrow("canonical lowercase UUID");
    expect(() =>
      store.open(envelope, "exchange", enrollment, bad, account),
    ).toThrow("canonical lowercase UUID");
    expect(() =>
      store.open(envelope, "exchange", enrollment, operation, bad),
    ).toThrow("canonical lowercase UUID");
    expect(() => bytes(bad)).toThrow("canonical lowercase UUID");
  }
  expect(
    (
      await pool.query(
        "SELECT rotation,revoked,confirmed FROM enrollment_spike.family",
      )
    ).rows[0],
  ).toEqual({ rotation: 0, revoked: false, confirmed: false });
  expect(await store.active(credentials.family, credentials.access)).toBe(true);
  expect(
    (await store.acknowledgeExchange(enrollment, operation, request.proof)).ok,
  ).toBe(true);
});

async function behindAccountLock<T>(
  start: () => Promise<T>,
  expireSql: string,
  params: unknown[] = [],
): Promise<T> {
  const blocker = await owner.connect();
  let pending: Promise<T> | undefined;
  try {
    await blocker.query("BEGIN");
    await blocker.query(
      "SELECT id FROM enrollment_spike.account WHERE id=$1 FOR UPDATE",
      [account],
    );
    pending = start();
    let blocked = false;
    for (let i = 0; i < 100; i++) {
      const found = await owner.query(
        "SELECT 1 FROM pg_stat_activity WHERE usename='e0_runtime' AND wait_event_type='Lock' LIMIT 1",
      );
      if (found.rowCount === 1) {
        blocked = true;
        break;
      }
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    expect(blocked).toBe(true);
    await blocker.query(expireSql, params);
    await blocker.query("COMMIT");
    return await pending;
  } finally {
    await blocker.query("ROLLBACK");
    blocker.release();
    await pending;
  }
}

test("exchange replay cannot return a receipt that expires during account-lock wait", async () => {
  const credentials = await enrolled();
  const result = await behindAccountLock(
    () => store.exchange(request),
    "UPDATE enrollment_spike.recovery SET expires_at=clock_timestamp() WHERE kind='exchange'",
  );
  expect(result.ok).toBe(false);
  expect(await store.active(credentials.family, credentials.access)).toBe(
    false,
  );
});

for (const action of ["challenge", "rotate"] as const) {
  test(`expired credential after account-lock wait refuses ${action}`, async () => {
    const credentials = await enrolled();
    const { op, proof } = await prepared(
      credentials.family,
      credentials.refresh,
    );
    const result = await behindAccountLock(
      () =>
        action === "challenge"
          ? store.rotationChallenge(credentials.family, credentials.refresh, op)
          : store.rotate(credentials.family, credentials.refresh, op, proof),
      "UPDATE enrollment_spike.credential SET expires_at=clock_timestamp() WHERE family_id=$1",
      [credentials.family],
    );
    expect("ok" in result && result.ok === false).toBe(true);
    expect(
      (await pool.query("SELECT rotation FROM enrollment_spike.family")).rows[0]
        .rotation,
    ).toBe(0);
    expect(
      (
        await pool.query(
          "SELECT count(*)::int AS n FROM enrollment_spike.credential",
        )
      ).rows[0].n,
    ).toBe(1);
  });
}

test("purge checks current DB time after its account-lock wait", async () => {
  const credentials = await enrolled();
  await behindAccountLock(
    () => store.purgeExpired(),
    "UPDATE enrollment_spike.recovery SET expires_at=clock_timestamp() WHERE kind='exchange'",
  );
  expect(await store.active(credentials.family, credentials.access)).toBe(
    false,
  );
  expect(
    (
      await pool.query(
        "SELECT count(*)::int AS n FROM enrollment_spike.recovery",
      )
    ).rows[0].n,
  ).toBe(0);
});

for (const deadline of ["credential", "receipt"] as const) {
  for (const replay of [false, true]) {
    test(`${deadline} expiry after real proof verification blocks ${replay ? "replay" : "new rotation"}`, async () => {
      const credentials = await enrolled();
      const { op, proof } = await prepared(
        credentials.family,
        credentials.refresh,
      );
      if (replay)
        await store.rotate(credentials.family, credentials.refresh, op, proof);
      const gated = new Store(pool, key);
      // Test-only fault injection around the real canonical Rust verifier; no
      // production bypass or mock signature implementation is introduced.
      const seam = gated as unknown as {
        verify(
          proof: unknown,
          expected: unknown,
          account: string,
        ): Promise<void>;
      };
      const realVerify = seam.verify.bind(gated);
      seam.verify = async (...args) => {
        await realVerify(...args);
        if (deadline === "credential")
          await owner.query(
            "UPDATE enrollment_spike.credential SET expires_at=clock_timestamp() WHERE family_id=$1",
            [credentials.family],
          );
        else
          await owner.query(
            "UPDATE enrollment_spike.recovery SET expires_at=clock_timestamp() WHERE kind='rotate' AND subject_id=$1",
            [credentials.family],
          );
      };
      expect(
        (await gated.rotate(credentials.family, credentials.refresh, op, proof))
          .ok,
      ).toBe(false);
      expect(
        (
          await pool.query(
            "SELECT rotation,revoked FROM enrollment_spike.family",
          )
        ).rows[0],
      ).toEqual({ rotation: replay ? 1 : 0, revoked: true });
      expect(
        (
          await pool.query(
            "SELECT count(*)::int AS n FROM enrollment_spike.credential",
          )
        ).rows[0].n,
      ).toBe(replay ? 2 : 1);
    });
  }
}
