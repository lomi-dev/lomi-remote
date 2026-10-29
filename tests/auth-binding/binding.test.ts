import { afterAll, beforeEach, expect, test } from "bun:test";
import { randomBytes, randomUUID } from "node:crypto";
import {
  BindingProof,
  Pool,
  makeSignature,
  SECRET,
  post,
  fixture,
} from "../../packages/auth-binding-spike/auth.ts";
const owner = new Pool({
  connectionString: process.env.AUTH_BINDING_OWNER_URL,
  max: 2,
});
const runtime = new Pool({
  connectionString: process.env.AUTH_BINDING_RUNTIME_URL,
  max: 8,
});
const proof = new BindingProof(runtime);
const account = "ba_user_fixture_not_a_uuid";
const other = "ba_user_other_not_a_uuid";
let web: { id: string; token: string; cookie: string };
async function seedSession(user: string, kind: "web" | "mobile" | "desktop") {
  const id = `ba_session_${randomUUID()}`,
    token = `synthetic_${randomUUID()}`;
  await owner.query(
    'INSERT INTO ba_fixture.session(id,"userId",token,"expiresAt","createdAt","updatedAt") VALUES($1,$2,$3,clock_timestamp()+interval \'1 hour\',clock_timestamp(),clock_timestamp())',
    [id, user, token],
  );
  await owner.query(
    "INSERT INTO auth_binding.session_class(session_id,account_id,kind) VALUES($1,$2,$3)",
    [id, user, kind],
  );
  return {
    id,
    token,
    cookie: `better-auth.session_token=${token}.${await makeSignature(token, SECRET)}`,
  };
}
beforeEach(async () => {
  await owner.query('TRUNCATE ba_fixture."user" CASCADE');
  await owner.query('DELETE FROM ba_fixture."deviceCode"');
  for (const [id, remote] of [
    [account, "01010101-0101-0101-0101-010101010101"],
    [other, "03030303-0303-0303-0303-030303030303"],
  ]) {
    await owner.query(
      'INSERT INTO ba_fixture."user"(id,name,email,"emailVerified","createdAt","updatedAt") VALUES($1,\'Synthetic\',$2,true,clock_timestamp(),clock_timestamp())',
      [id, `${id}@example.invalid`],
    );
    await owner.query(
      "INSERT INTO auth_binding.policy(account_id,remote_account_id) VALUES($1,$2)",
      [id, remote],
    );
  }
  web = await seedSession(account, "web");
});
afterAll(async () => {
  await proof.db.destroy();
  await owner.end();
});
async function enrollment() {
  const initial = await fixture("pending-host");
  return proof.beginHost(initial.signed, initial.pin);
}
async function issued() {
  const e = await enrollment();
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  const response = await proof.redeem(e.device_code, "lomi-remote-host");
  expect(response.status).toBe(200);
  const body = (await response.json()) as { access_token: string };
  return { ...e, token: body.access_token };
}
async function ordinary(
  client = "lomi-desktop",
  extras: Record<string, unknown> = {},
) {
  const created = await proof.raw(
    post("/device/code", { client_id: client, ...extras }),
  );
  expect(created.status).toBe(200);
  const code = (await created.json()) as {
    device_code: string;
    user_code: string;
  };
  expect((await proof.approve(code.user_code, web.cookie)).status).toBe(200);
  const response = await proof.redeem(code.device_code, client, extras);
  expect(response.status).toBe(200);
  return ((await response.json()) as { access_token: string }).access_token;
}

test("actual Better Auth foundation issues one ordinary desktop session in a transaction", async () => {
  const created = await proof.raw(
    post("/device/code", { client_id: "lomi-desktop" }),
  );
  const code = (await created.json()) as {
    device_code: string;
    user_code: string;
  };
  expect((await proof.approve(code.user_code, web.cookie)).status).toBe(200);
  const results = await Promise.all([
    proof.redeem(code.device_code, "lomi-desktop"),
    proof.redeem(code.device_code, "lomi-desktop"),
  ]);
  expect(results.filter((r) => r.status === 200).length).toBe(1);
  expect(
    (
      await owner.query(
        "SELECT count(*)::int AS n FROM auth_binding.session_class WHERE kind='desktop'",
      )
    ).rows[0].n,
  ).toBe(1);
  expect(
    (
      await owner.query(
        'SELECT count(*)::int AS n FROM ba_fixture."deviceCode"',
      )
    ).rows[0].n,
  ).toBe(0);
});

test("public host clientId and class body cannot upgrade an ordinary account session", async () => {
  const token = await ordinary("lomi-remote-host", {
    clientClass: "bootstrap",
    kind: "bootstrap",
    host_id: "attacker",
  });
  expect((await proof.consumer(token)).length > 0).toBe(true);
  expect(
    (await owner.query("SELECT count(*)::int AS n FROM auth_binding.bootstrap"))
      .rows[0].n,
  ).toBe(0);
  await expect(proof.exchange(token, randomUUID(), {})).rejects.toThrow(
    "enrollment binding rejected",
  );
  expect(
    (
      await owner.query(
        "SELECT count(*)::int AS n FROM auth_binding.host_authorization",
      )
    ).rows[0].n,
  ).toBe(0);
});

test("host device redemption has one immutable UUID bootstrap mapped to opaque BA session", async () => {
  const e = await enrollment();
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  const replies = await Promise.all(
    Array.from({ length: 4 }, () =>
      proof.redeem(e.device_code, "lomi-remote-host", {
        kind: "desktop",
        sessionId: "forged",
      }),
    ),
  );
  expect(replies.filter((r) => r.status === 200).length).toBe(1);
  const token = (
    (await replies.find((r) => r.status === 200)!.json()) as {
      access_token: string;
    }
  ).access_token;
  const row = (await owner.query("SELECT * FROM auth_binding.bootstrap"))
    .rows[0];
  expect(row.id).toBe(e.bootstrap);
  expect(row.session_id.startsWith("ba_")).toBe(true);
  expect(row.session_id === e.bootstrap).toBe(false);
  expect(row.account_id).toBe(account);
  expect(row.kind).toBe("bootstrap");
  await expect(proof.consumer(token)).rejects.toThrow(
    "consumer class rejected",
  );
  await expect(
    owner.query("UPDATE auth_binding.bootstrap SET session_id=$1 WHERE id=$2", [
      web.id,
      e.bootstrap,
    ]),
  ).rejects.toBeDefined();
  await expect(
    owner.query("UPDATE auth_binding.enrollment SET host_id=$1 WHERE id=$2", [
      randomUUID(),
      e.enrollment,
    ]),
  ).rejects.toBeDefined();
});

test("session creation and bootstrap mapping roll back with consumed device code", async () => {
  const e = await enrollment();
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  await expect(
    proof.redeem(e.device_code, "lomi-remote-host", {}, true),
  ).rejects.toThrow("synthetic rollback");
  expect(
    (await owner.query("SELECT count(*)::int AS n FROM auth_binding.bootstrap"))
      .rows[0].n,
  ).toBe(0);
  expect(
    (
      await owner.query(
        "SELECT count(*)::int AS n FROM auth_binding.session_class WHERE kind='bootstrap'",
      )
    ).rows[0].n,
  ).toBe(0);
  expect(
    (
      await owner.query(
        'SELECT count(*)::int AS n FROM ba_fixture."deviceCode"',
      )
    ).rows[0].n,
  ).toBe(1);
  expect((await proof.redeem(e.device_code, "lomi-remote-host")).status).toBe(
    200,
  );
});

test("only the exactly bound bootstrap plus canonical PoP creates host authorization", async () => {
  const e = await issued();
  const c = await proof.challenge(e.enrollment);
  const signed = await fixture("sign", c);
  const otherSession = await seedSession(account, "desktop");
  await expect(
    proof.exchange(otherSession.token, e.operation, signed),
  ).rejects.toThrow("enrollment binding rejected");
  const bad = structuredClone(signed);
  bad.challenge.bootstrapSessionId[0] ^= 1;
  await expect(proof.exchange(e.token, e.operation, bad)).rejects.toThrow(
    "canonical proof rejected",
  );
  const different = await issued();
  await expect(
    proof.exchange(different.token, e.operation, signed),
  ).rejects.toThrow("enrollment binding rejected");
  const id = await proof.exchange(e.token, e.operation, signed);
  expect(await proof.hostAllowed(id)).toBe(true);
  await expect(
    proof.exchange(e.token, e.operation, signed),
  ).rejects.toBeDefined();
  expect(
    (
      await owner.query(
        "SELECT count(*)::int AS n FROM auth_binding.host_authorization",
      )
    ).rows[0].n,
  ).toBe(1);
});

test("approval cannot be stolen by another BA account or by a bootstrap session", async () => {
  const e = await enrollment();
  // First authenticated browser review pre-binds the plugin record to this account.
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  const stranger = await seedSession(other, "web");
  expect(
    (await proof.approve(e.user_code, stranger.cookie)).status === 200,
  ).toBe(false);
  const first = await issued();
  const bootstrap = (
    await owner.query(
      "SELECT s.id,s.token FROM ba_fixture.session s JOIN auth_binding.bootstrap b ON b.session_id=s.id WHERE b.id=$1",
      [first.bootstrap],
    )
  ).rows[0];
  const cookie = `better-auth.session_token=${bootstrap.token}.${await makeSignature(bootstrap.token, SECRET)}`;
  const next = await enrollment();
  expect((await proof.approve(next.user_code, cookie)).status).toBe(403);
});

test("typed consumer FKs reject cross-account, class forgery, multiple parents and reparenting", async () => {
  const consumer = await proof.consumer(web.token);
  const session = await seedSession(other, "web");
  await expect(
    runtime.query(
      "INSERT INTO auth_binding.consumer(id,account_id,kind,web_session_id,epoch) VALUES($1,$2,'web',$3,1)",
      [randomUUID(), account, session.id],
    ),
  ).rejects.toBeDefined();
  await expect(
    runtime.query(
      "INSERT INTO auth_binding.consumer(id,account_id,kind,desktop_session_id,epoch) VALUES($1,$2,'desktop',$3,1)",
      [randomUUID(), account, web.id],
    ),
  ).rejects.toBeDefined();
  const mobile = await seedSession(account, "mobile");
  const unboundWeb = await seedSession(account, "web");
  await expect(
    runtime.query(
      "INSERT INTO auth_binding.consumer(id,account_id,kind,web_session_id,mobile_session_id,epoch) VALUES($1,$2,'web',$3,$4,1)",
      [randomUUID(), account, unboundWeb.id, mobile.id],
    ),
  ).rejects.toBeDefined();
  await expect(
    owner.query("UPDATE auth_binding.consumer SET account_id=$1 WHERE id=$2", [
      other,
      consumer,
    ]),
  ).rejects.toBeDefined();
  await expect(
    owner.query(
      "UPDATE auth_binding.session_class SET kind='desktop' WHERE session_id=$1",
      [web.id],
    ),
  ).rejects.toBeDefined();
  expect((await proof.consumer(mobile.token)).length > 0).toBe(true);
});

test("two windows coexist; refresh retires only A; actual BA signout removes both", async () => {
  const consumer = await proof.consumer(web.token);
  const [a, b] = await Promise.all([
    proof.attach(consumer, randomBytes(32)),
    proof.attach(consumer, randomBytes(32)),
  ]);
  expect(await proof.windowAllowed(a)).toBe(true);
  expect(await proof.windowAllowed(b)).toBe(true);
  await expect(proof.attach(consumer, randomBytes(32))).rejects.toThrow();
  const fresh = await proof.refreshWindow(consumer, a, randomBytes(32));
  expect(await proof.windowAllowed(a)).toBe(false);
  expect(await proof.windowAllowed(fresh)).toBe(true);
  expect(await proof.windowAllowed(b)).toBe(true);
  expect((await proof.signOut(web.token)).status).toBe(200);
  expect(await proof.windowAllowed(fresh)).toBe(false);
  expect(await proof.windowAllowed(b)).toBe(false);
  await expect(proof.consumer(web.token)).rejects.toThrow(
    "account session required",
  );
});

test("window ownership cannot be rebound or revive a retired identity", async () => {
  const consumer = await proof.consumer(web.token);
  const a = await proof.attach(consumer, randomBytes(32));
  const second = await seedSession(account, "desktop");
  const otherConsumer = await proof.consumer(second.token);
  await expect(
    owner.query(
      "UPDATE auth_binding.window_key SET consumer_id=$1 WHERE id=$2",
      [otherConsumer, a],
    ),
  ).rejects.toBeDefined();
  await proof.refreshWindow(consumer, a, randomBytes(32));
  await expect(
    owner.query(
      "UPDATE auth_binding.window_key SET retired=false WHERE id=$1",
      [a],
    ),
  ).rejects.toBeDefined();
});

test("global revoke races redeem and PoP; suspend/reactivate cannot restore old bindings", async () => {
  const e = await issued();
  const signed = await fixture("sign", await proof.challenge(e.enrollment));
  const consumer = await proof.consumer(web.token);
  const window = await proof.attach(consumer, randomBytes(32));
  const pending = await enrollment();
  expect((await proof.approve(pending.user_code, web.cookie)).status).toBe(200);
  await Promise.allSettled([
    proof.exchange(e.token, e.operation, signed),
    proof.redeem(pending.device_code, "lomi-remote-host"),
    proof.globalRevoke(account, true),
  ]);
  expect(await proof.windowAllowed(window)).toBe(false);
  expect(
    (
      await owner.query(
        "SELECT count(*)::int AS n FROM auth_binding.host_authorization WHERE NOT revoked",
      )
    ).rows[0].n,
  ).toBe(0);
  await proof.globalRevoke(account, false);
  await expect(
    proof.exchange(e.token, e.operation, signed),
  ).rejects.toBeDefined();
  expect(
    (await proof.redeem(pending.device_code, "lomi-remote-host")).status ===
      200,
  ).toBe(false);
  await expect(proof.consumer(web.token)).rejects.toBeDefined();
});

test("runtime role is limited and cannot mutate server-owned class or schema", async () => {
  expect(
    (
      await runtime.query(
        "SELECT rolsuper,rolcreatedb,rolcreaterole FROM pg_roles WHERE rolname=current_user",
      )
    ).rows[0],
  ).toEqual({ rolsuper: false, rolcreatedb: false, rolcreaterole: false });
  await expect(
    runtime.query("CREATE TABLE public.auth_escape(id int)"),
  ).rejects.toBeDefined();
  await expect(
    runtime.query(
      "UPDATE auth_binding.session_class SET kind='bootstrap' WHERE session_id=$1",
      [web.id],
    ),
  ).rejects.toBeDefined();
  await expect(
    runtime.query(
      "DELETE FROM auth_binding.session_class WHERE session_id=$1",
      [web.id],
    ),
  ).rejects.toBeDefined();
  await expect(
    runtime.query(
      "INSERT INTO auth_binding.policy(account_id,remote_account_id) VALUES($1,$2)",
      ["fake", randomUUID()],
    ),
  ).rejects.toBeDefined();
});

test("direct concurrent limited-role inserts enforce the two-window SQL limit", async () => {
  const consumer = await proof.consumer(web.token);
  const results = await Promise.allSettled(
    Array.from({ length: 5 }, () =>
      runtime.query(
        "INSERT INTO auth_binding.window_key(id,consumer_id,fingerprint) VALUES($1,$2,$3)",
        [randomUUID(), consumer, randomBytes(32)],
      ),
    ),
  );
  expect(results.filter((r) => r.status === "fulfilled").length).toBe(2);
  expect(
    (
      await owner.query(
        "SELECT count(*)::int AS n FROM auth_binding.window_key WHERE NOT retired",
      )
    ).rows[0].n,
  ).toBe(2);
});

test("bootstrap UUID and account foreign keys reject a different ordinary session", async () => {
  const e = await enrollment();
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  const second = await seedSession(account, "desktop");
  await expect(
    runtime.query(
      "INSERT INTO auth_binding.bootstrap(id,enrollment_id,account_id,session_id) VALUES($1,$2,$3,$4)",
      [e.bootstrap, e.enrollment, account, second.id],
    ),
  ).rejects.toBeDefined();
  const foreign = await seedSession(other, "web");
  await expect(
    runtime.query(
      "INSERT INTO auth_binding.bootstrap(id,enrollment_id,account_id,session_id) VALUES($1,$2,$3,$4)",
      [e.bootstrap, e.enrollment, other, foreign.id],
    ),
  ).rejects.toBeDefined();
  expect(
    (await owner.query("SELECT count(*)::int AS n FROM auth_binding.bootstrap"))
      .rows[0].n,
  ).toBe(0);
});

test("host client mismatch and consumer request fields cannot change host classification", async () => {
  const e = await enrollment();
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  expect(
    (
      await proof.redeem(e.device_code, "lomi-desktop", {
        clientClass: "bootstrap",
      })
    ).status === 200,
  ).toBe(false);
  expect(
    (await owner.query("SELECT count(*)::int AS n FROM auth_binding.bootstrap"))
      .rows[0].n,
  ).toBe(0);
  expect(
    (
      await proof.redeem(e.device_code, "lomi-remote-host", {
        clientClass: "web",
      })
    ).status,
  ).toBe(200);
  expect(
    (
      await owner.query(
        "SELECT kind FROM auth_binding.session_class WHERE kind='bootstrap'",
      )
    ).rows[0].kind,
  ).toBe("bootstrap");
});

const remoteBytes = (id: string) =>
  Array.from(Buffer.from(id.replaceAll("-", ""), "hex"));
test("first device code has no account; approval binds the same committed keys before PoP", async () => {
  const initial = await fixture("pending-host");
  expect("accountId" in initial.signed.descriptor).toBe(false);
  expect("account_id" in initial.signed.descriptor).toBe(false);
  const e = await proof.beginHost(initial.signed, initial.pin);
  let row = (
    await owner.query("SELECT * FROM auth_binding.enrollment WHERE id=$1", [
      e.enrollment,
    ])
  ).rows[0];
  expect(row.account_id).toBeNull();
  expect(row.fingerprint).toBeNull();
  expect(row.epoch).toBeNull();
  expect(row.approved).toBe(false);
  expect(row.signed_key).toEqual(initial.signed);
  expect(Array.from(row.initial_commitment)).toEqual(initial.pin);
  await expect(proof.challenge(e.enrollment)).rejects.toThrow(
    "approved enrollment required",
  );
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  row = (
    await owner.query("SELECT * FROM auth_binding.enrollment WHERE id=$1", [
      e.enrollment,
    ])
  ).rows[0];
  const accountBytes = remoteBytes("01010101-0101-0101-0101-010101010101");
  const bound = await fixture("derive-host-binding", {
    signed: initial.signed,
    pin: initial.pin,
    account: accountBytes,
  });
  expect(Array.from(row.fingerprint)).toEqual(bound.fingerprint);
  expect(row.account_id).toBe(account);
  for (const [key, field] of [
    ["identityKey", "identity_key"],
    ["channelKey", "channel_key"],
    ["mailboxKey", "mailbox_key"],
  ])
    expect(bound.bundle[field]).toEqual(initial.signed.descriptor[key]);
  expect(row.signed_key).toEqual(initial.signed);
  expect(Array.from(row.initial_commitment)).toEqual(initial.pin);
  const reply = await proof.redeem(e.device_code, "lomi-remote-host");
  expect(reply.status).toBe(200);
  const token = ((await reply.json()) as { access_token: string }).access_token;
  const signed = await fixture("pending-sign", {
    pin: initial.pin,
    account: accountBytes,
    expected: await proof.challenge(e.enrollment),
  });
  const id = await proof.exchange(token, e.operation, signed);
  expect(await proof.hostAllowed(id)).toBe(true);
  await expect(
    proof.exchange(token, e.operation, signed),
  ).rejects.toBeDefined();
});

test("any init key, host identity, descriptor or commitment substitution fails before device-code effects", async () => {
  const initial = await fixture("pending-host");
  const variants = [];
  for (const field of ["identityKey", "channelKey", "mailboxKey", "hostId"]) {
    const changed = structuredClone(initial);
    changed.signed.descriptor[field][0] ^= 1;
    variants.push(changed);
  }
  for (const [field, value] of [
    ["version", 2],
    ["keyVersion", 2],
    ["role", "device"],
    ["accountId", Array(16).fill(1)],
  ] as const) {
    const changed = structuredClone(initial);
    changed.signed.descriptor[field] = value;
    variants.push(changed);
  }
  const wrongPin = structuredClone(initial);
  wrongPin.pin[0] ^= 1;
  variants.push(wrongPin);
  const wrongSignature = structuredClone(initial);
  wrongSignature.signed.signature[0] ^= 1;
  variants.push(wrongSignature);
  for (const changed of variants)
    await expect(proof.beginHost(changed.signed, changed.pin)).rejects.toThrow(
      "canonical proof rejected",
    );
  expect(
    (
      await owner.query(
        "SELECT count(*)::int AS n FROM auth_binding.enrollment",
      )
    ).rows[0].n,
  ).toBe(0);
  expect(
    (
      await owner.query(
        'SELECT count(*)::int AS n FROM ba_fixture."deviceCode"',
      )
    ).rows[0].n,
  ).toBe(0);
});

test("init commitment and descriptor are SQL immutable before and after approval", async () => {
  const initial = await fixture("pending-host");
  const e = await proof.beginHost(initial.signed, initial.pin);
  const changed = structuredClone(initial.signed);
  changed.descriptor.channelKey[0] ^= 1;
  await expect(
    runtime.query(
      "UPDATE auth_binding.enrollment SET signed_key=$1 WHERE id=$2",
      [changed, e.enrollment],
    ),
  ).rejects.toBeDefined();
  await expect(
    owner.query(
      "UPDATE auth_binding.enrollment SET initial_commitment=$1 WHERE id=$2",
      [randomBytes(32), e.enrollment],
    ),
  ).rejects.toBeDefined();
  await expect(
    owner.query(
      "UPDATE auth_binding.enrollment SET account_id=$1 WHERE id=$2",
      [other, e.enrollment],
    ),
  ).rejects.toBeDefined();
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  await expect(
    owner.query(
      "UPDATE auth_binding.enrollment SET fingerprint=$1 WHERE id=$2",
      [randomBytes(32), e.enrollment],
    ),
  ).rejects.toBeDefined();
  await expect(
    runtime.query(
      "UPDATE auth_binding.enrollment SET account_id=$1 WHERE id=$2",
      [other, e.enrollment],
    ),
  ).rejects.toBeDefined();
  expect(
    (
      await owner.query(
        "SELECT signed_key FROM auth_binding.enrollment WHERE id=$1",
        [e.enrollment],
      )
    ).rows[0].signed_key,
  ).toEqual(initial.signed);
});

test("a valid proof bound to a different account cannot replace the approved account", async () => {
  const initial = await fixture("pending-host");
  const e = await proof.beginHost(initial.signed, initial.pin);
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  const reply = await proof.redeem(e.device_code, "lomi-remote-host");
  const token = ((await reply.json()) as { access_token: string }).access_token;
  const expected = await proof.challenge(e.enrollment);
  const wrongAccount = remoteBytes("03030303-0303-0303-0303-030303030303");
  const wrongBound = await fixture("derive-host-binding", {
    signed: initial.signed,
    pin: initial.pin,
    account: wrongAccount,
  });
  const foreignProof = await fixture("pending-sign", {
    account: wrongAccount,
    pin: initial.pin,
    expected: { ...expected, hostKeyFingerprint: wrongBound.fingerprint },
  });
  await expect(
    proof.exchange(token, e.operation, foreignProof),
  ).rejects.toThrow("canonical proof rejected");
  expect(
    (
      await owner.query(
        "SELECT consumed FROM auth_binding.bootstrap WHERE id=$1",
        [e.bootstrap],
      )
    ).rows[0].consumed,
  ).toBe(false);
  const good = await fixture("pending-sign", {
    account: remoteBytes("01010101-0101-0101-0101-010101010101"),
    pin: initial.pin,
    expected,
  });
  await expect(
    proof.exchange(token, e.operation, { ...good, signedKey: initial.signed }),
  ).rejects.toThrow("canonical proof rejected");
  expect(
    await proof.hostAllowed(await proof.exchange(token, e.operation, good)),
  ).toBe(true);
});

test("the same account-independent init can finalize for the account actually approved later", async () => {
  const initial = await fixture("pending-host");
  const e = await proof.beginHost(initial.signed, initial.pin);
  const otherWeb = await seedSession(other, "web");
  expect((await proof.approve(e.user_code, otherWeb.cookie)).status).toBe(200);
  const row = (
    await owner.query(
      "SELECT account_id,fingerprint,signed_key,initial_commitment FROM auth_binding.enrollment WHERE id=$1",
      [e.enrollment],
    )
  ).rows[0];
  expect(row.account_id).toBe(other);
  expect(row.signed_key).toEqual(initial.signed);
  expect(Array.from(row.initial_commitment)).toEqual(initial.pin);
  const approvedAccount = remoteBytes("03030303-0303-0303-0303-030303030303");
  const bound = await fixture("derive-host-binding", {
    signed: initial.signed,
    pin: initial.pin,
    account: approvedAccount,
  });
  expect(Array.from(row.fingerprint)).toEqual(bound.fingerprint);
  expect(bound.bundle.account_id).toEqual(approvedAccount);
  const reply = await proof.redeem(e.device_code, "lomi-remote-host", {
    accountId: account,
    signedKey: { descriptor: { identityKey: Array(32).fill(0) } },
    initialCommitment: Array(32).fill(0),
    bundle: { account_id: Array(16).fill(1) },
  });
  expect(reply.status).toBe(200);
  const token = ((await reply.json()) as { access_token: string }).access_token;
  const signed = await fixture("pending-sign", {
    account: approvedAccount,
    pin: initial.pin,
    expected: await proof.challenge(e.enrollment),
  });
  expect(
    await proof.hostAllowed(await proof.exchange(token, e.operation, signed)),
  ).toBe(true);
  expect(
    (
      await owner.query(
        "SELECT account_id FROM auth_binding.host_authorization",
      )
    ).rows[0].account_id,
  ).toBe(other);
});

test("recreated pending seed cannot rebind an already approved init record to another account", async () => {
  const initial = await fixture("pending-host");
  const e = await proof.beginHost(initial.signed, initial.pin);
  expect((await proof.approve(e.user_code, web.cookie)).status).toBe(200);
  const otherWeb = await seedSession(other, "web");
  expect(
    (await proof.approve(e.user_code, otherWeb.cookie)).status === 200,
  ).toBe(false);
  const expected = await proof.challenge(e.enrollment);
  const accountB = remoteBytes("03030303-0303-0303-0303-030303030303");
  const bindingB = await fixture("derive-host-binding", {
    signed: initial.signed,
    pin: initial.pin,
    account: accountB,
  });
  // Each fixture invocation recreates the same pending seed. Crypto can derive
  // another mathematical binding; durable enrollment CAS must reject its reuse.
  const copiedSeedProof = await fixture("pending-sign", {
    account: accountB,
    pin: initial.pin,
    expected: { ...expected, hostKeyFingerprint: bindingB.fingerprint },
  });
  const reply = await proof.redeem(e.device_code, "lomi-remote-host");
  const token = ((await reply.json()) as { access_token: string }).access_token;
  await expect(
    proof.exchange(token, e.operation, copiedSeedProof),
  ).rejects.toThrow("canonical proof rejected");
  await expect(
    owner.query(
      "UPDATE auth_binding.enrollment SET account_id=$1,fingerprint=$2 WHERE id=$3",
      [other, Buffer.from(bindingB.fingerprint), e.enrollment],
    ),
  ).rejects.toBeDefined();
  const good = await fixture("pending-sign", {
    account: remoteBytes("01010101-0101-0101-0101-010101010101"),
    pin: initial.pin,
    expected,
  });
  expect(
    await proof.hostAllowed(await proof.exchange(token, e.operation, good)),
  ).toBe(true);
  await expect(
    owner.query(
      "UPDATE auth_binding.bootstrap SET consumed=false WHERE id=$1",
      [e.bootstrap],
    ),
  ).rejects.toBeDefined();
  await expect(
    proof.exchange(token, e.operation, copiedSeedProof),
  ).rejects.toBeDefined();
  expect(
    (
      await owner.query(
        "SELECT account_id FROM auth_binding.enrollment WHERE id=$1",
        [e.enrollment],
      )
    ).rows[0].account_id,
  ).toBe(account);
  expect(
    (
      await owner.query(
        "SELECT count(*)::int AS n FROM auth_binding.host_authorization",
      )
    ).rows[0].n,
  ).toBe(1);
});
