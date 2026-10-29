// Real PostgreSQL contention and actual baseline Bun relay. Synthetic data only.
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { observeDelivery, runFixtureLifecycle } from "./lifecycle.mjs";

const authRepo = process.env.AUTHORITY_FIXTURE_AUTH_REPO!;
const url = process.env.AUTHORITY_FIXTURE_DATABASE_URL!;
const output = process.env.AUTHORITY_FIXTURE_OUTPUT!;
assert(authRepo && url && output);
const moduleAt = (path: string) =>
  import(pathToFileURL(`${authRepo}/${path}`).href);
const { createDatabase } = await moduleAt("src/database.ts");
const { withGlobalAuthorizationLock } = await moduleAt("src/transactions.ts");
const { startRelay } = await moduleAt("src/remote/relay/server.ts");
const db = createDatabase(url);
const now = () => performance.now();
const sleep = (ms: number) => Bun.sleep(ms);
const stats: Record<string, unknown> = {
  fixture: true,
  productionQualified: false,
  baselineProtocolOnly: true,
  channels: 8 * (32 + 1),
  connections: 2 * 8 * (32 + 1),
  authoritySlots: 64,
  freshnessMs: 5000,
  samples: [],
  scenarios: [],
  passed: false,
  cleanupCompleted: false,
};
const sockets = new Set<WebSocket>();
const ticketMap = new Map<
  string,
  { channelId: string; role: "host" | "device" }
>();
const validationSamples: {
  queueMs: number;
  totalMs: number;
  failed: boolean;
}[] = [];
let relay: Awaited<ReturnType<typeof startRelay>> | undefined;
let authorityCalls = 0;
let maxConcurrent = 0;
let concurrent = 0;
let sqlReadsAfterCommit = 0;
let resultsDeliveredAfterCommit = 0;
let revoked = false;
let stopChurn = false;
let churnTask: Promise<void> | undefined;
let churnAttempts = 0;
let admissionRefusals = 0;
let epoch = 0;
let phase = "setup";
let overloadState: (() => unknown) | undefined;
let freshnessBoundary = 0;
let postDeadlineForwards = 0;
let experimentSignal: AbortSignal | undefined;
const owner = `fixture_${crypto.randomUUID().replaceAll("-", "")}`;

function ensureActive() {
  if (experimentSignal?.aborted) throw new Error("fixture stopped");
}

async function locked<T>(operation: (tx: any) => Promise<T>): Promise<T> {
  ensureActive();
  authorityCalls++;
  concurrent++;
  maxConcurrent = Math.max(maxConcurrent, concurrent);
  try {
    return await withGlobalAuthorizationLock(db.prisma, (tx: any) => {
      ensureActive();
      return operation(tx);
    });
  } finally {
    concurrent--;
  }
}

async function lease(claim: boolean) {
  return locked(async (tx) => {
    const rows = await tx.$queryRaw`
      UPDATE public.authority_fixture
      SET owner = ${owner},
          epoch = CASE WHEN ${claim} THEN epoch + 1 ELSE epoch END,
          expires_at = clock_timestamp() + interval '20 seconds'
      WHERE id = 1 AND
        ((${claim} AND (owner IS NULL OR expires_at < clock_timestamp())) OR
         (NOT ${claim} AND owner = ${owner} AND epoch = ${epoch}
          AND expires_at > clock_timestamp()))
      RETURNING epoch, (extract(epoch FROM expires_at) * 1000)::float8 AS expires
    `;
    assert.equal(rows.length, 1, "owner claim/renewal must be exclusive");
    epoch = rows[0].epoch;
    return { epoch, expiresAt: Math.floor(rows[0].expires) };
  });
}

const authority = {
  claim: () => lease(true),
  renew: () => lease(false),
  async consume(
    ticket: string,
    requestedOwner: string,
    requestedEpoch: number,
  ) {
    const binding = ticketMap.get(ticket);
    ticketMap.delete(ticket);
    assert(binding, "one-time synthetic ticket required");
    return locked(async (tx) => {
      const rows = await tx.$queryRaw`
        SELECT active FROM public.authority_fixture
        WHERE id = 1 AND owner = ${requestedOwner} AND epoch = ${requestedEpoch}
          AND expires_at > clock_timestamp()
      `;
      assert(rows[0]?.active, "revoked admission");
      return {
        ...binding,
        accountId: "fixture_account",
        ownerEpoch: epoch,
        expiresAt: Date.now() + 90_000,
      };
    });
  },
  async validate(
    _channel: string,
    requestedOwner: string,
    requestedEpoch: number,
  ) {
    const started = now();
    let acquired = started;
    let failed = true;
    try {
      const value = await observeDelivery(
        () =>
          locked(async (tx) => {
            acquired = now();
            const rows = await tx.$queryRaw`
          SELECT active FROM public.authority_fixture
          WHERE id = 1 AND owner = ${requestedOwner} AND epoch = ${requestedEpoch}
            AND expires_at > clock_timestamp()
        `;
            assert(rows[0]?.active, "authorization revoked");
            if (revoked) sqlReadsAfterCommit++;
            // Never lengthen the original ticket expiry during validation.
            return { valid: true as const, expiresAt: Date.now() + 30_000 };
          }),
        () => revoked,
        () => {
          resultsDeliveredAfterCommit++;
        },
      );
      failed = false;
      return value;
    } finally {
      if (validationSamples.length < 10_000)
        validationSamples.push({
          queueMs: acquired - started,
          totalMs: now() - started,
          failed,
        });
    }
  },
};

function ticket(channelId: string, role: "host" | "device") {
  assert(ticketMap.size < 2048);
  const value =
    crypto.randomUUID().replaceAll("-", "") +
    crypto.randomUUID().replaceAll("-", "");
  ticketMap.set(value, { channelId, role });
  return value;
}

async function connectOnce(channelId: string, role: "host" | "device") {
  ensureActive();
  const value = ticket(channelId, role);
  const ws = new WebSocket(`ws://127.0.0.1:${relay!.server.port}/v1/relay`, {
    headers: { origin: "http://fixture.invalid" },
  });
  sockets.add(ws);
  ws.binaryType = "arraybuffer";
  let done = false;
  let received = 0;
  const finished = new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => finish(false), 6000);
    function finish(value: boolean) {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(value);
    }
    ws.addEventListener("open", () =>
      ws.send(JSON.stringify({ type: "authenticate", ticket: value })),
    );
    ws.addEventListener("message", (event) => {
      if (typeof event.data === "string") {
        const data = JSON.parse(event.data);
        if (data.type === "authenticated") finish(true);
      } else {
        received++;
        if (
          freshnessBoundary &&
          event.data.byteLength === 8 &&
          new DataView(event.data).getFloat64(0, true) >= freshnessBoundary
        )
          postDeadlineForwards++;
      }
    });
    ws.addEventListener("close", () => {
      sockets.delete(ws);
      finish(false);
    });
    ws.addEventListener("error", () => finish(false));
  });
  const accepted = await finished;
  ticketMap.delete(value);
  ensureActive();
  if (!accepted) admissionRefusals++;
  if (!accepted) ws.close();
  return { ws, accepted, received: () => received };
}

async function connect(
  channelId: string,
  role: "host" | "device",
  requireSuccess = true,
) {
  const until = now() + 5000;
  do {
    const peer = await connectOnce(channelId, role);
    if (peer.accepted || !requireSuccess) return peer;
    // A busy one-time ticket is discarded. Only fresh admission is retried;
    // no application input, operation, or old ticket is ever replayed.
    await sleep(50);
  } while (now() < until);
  throw new Error("bounded fresh admission retries exhausted");
}

type Peer = Awaited<ReturnType<typeof connect>>;
async function fill(count: number, prefix: string) {
  const pairs: { host: Peer; consumer: Peer }[] = [];
  for (let batch = 0; batch < count; batch += 8) {
    ensureActive();
    pairs.push(
      ...(await Promise.all(
        Array.from({ length: Math.min(8, count - batch) }, async (_, i) => {
          const channel = `${prefix}_${batch + i}`;
          const [host, consumer] = await Promise.all([
            connect(channel, "host"),
            connect(channel, "device"),
          ]);
          return { host, consumer };
        }),
      )),
    );
  }
  return pairs;
}

async function waitFor(condition: () => boolean, timeout: number) {
  const until = now() + timeout;
  while (!condition() && now() < until) await sleep(10);
  assert(condition(), "bounded wait expired");
}

function percentile(values: number[], fraction: number) {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted.length
    ? Math.round(
        sorted[
          Math.min(sorted.length - 1, Math.floor(sorted.length * fraction))
        ]! * 1000,
      ) / 1000
    : null;
}

async function runExperiment(signal: AbortSignal) {
  experimentSignal = signal;
  relay = await startRelay(
    {
      hostname: "127.0.0.1",
      port: 0,
      enabled: true,
      browserOrigin: "http://fixture.invalid",
      apiOrigin: "http://127.0.0.1",
      serviceSecret: "synthetic-unused-secret-not-a-credential",
      ownerId: owner,
      trustedProxyIps: [],
      maxConnections: 1024,
      maxPendingConnections: 64,
      maxPendingConnectionsPerSource: 64,
      maxAdmissionsPerMinute: 6000,
      maxAdmissionsPerSourcePerMinute: 6000,
      maxAuthorityRequests: 64,
      maxFrameBytes: 65535,
      maxBufferedBytes: 131072,
      authenticationTimeoutMs: 5000,
    },
    authority,
  );
  ensureActive();
  // A second real relay must not claim the same live authority lease.
  await assert.rejects(() =>
    startRelay(
      { enabled: true, maxAuthorityRequests: 64, ownerId: "other_owner" },
      authority,
    ),
  );
  (stats.scenarios as unknown[]).push({
    name: "second-owner-rejected",
    passed: true,
  });

  const count = stats.channels as number;
  phase = "full-budget-baseline";
  const pairs = await fill(count, "baseline");
  await sleep(6500); // Multiple real 2s validation cycles, no virtual timers.
  ensureActive();
  assert.equal(
    relay.connectionCount(),
    count * 2,
    "full budget must survive baseline freshness",
  );
  for (const pair of pairs) pair.host.ws.send(new Uint8Array([0, 1, 2, 3]));
  await waitFor(
    () => pairs.every((pair) => pair.consumer.received() === 1),
    1500,
  );
  const baseline = validationSamples.splice(0);
  (stats.scenarios as unknown[]).push({
    name: "full-budget-baseline",
    passed: true,
    validations: baseline.length,
    queueP95Ms: percentile(
      baseline.map((s) => s.queueMs),
      0.95,
    ),
    totalP95Ms: percentile(
      baseline.map((s) => s.totalMs),
      0.95,
    ),
  });

  const revokeStarted = now();
  phase = "revoke-full-budget";
  await locked(
    (tx) =>
      tx.$executeRaw`UPDATE public.authority_fixture SET active = false WHERE id = 1`,
  );
  revoked = true;
  const committed = now();
  await waitFor(() => relay!.connectionCount() === 0, 5000);
  ensureActive();
  assert.equal(
    sqlReadsAfterCommit,
    0,
    "serialized SQL read must not authorize after committed revoke",
  );
  (stats.scenarios as unknown[]).push({
    name: "revoke-full-budget",
    passed: true,
    commitLatencyMs: Math.round(committed - revokeStarted),
    closeAfterCommitMs: Math.round(now() - committed),
  });
  revoked = false;
  await locked(
    (tx) =>
      tx.$executeRaw`UPDATE public.authority_fixture SET active = true WHERE id = 1`,
  );

  const overloadedPairs = await fill(count, "overload");
  phase = "lock-delay-and-churn";
  overloadState = () => ({
    relayConnections: relay!.connectionCount(),
    peerStates: [0, 1, 2, 3].map(
      (state) =>
        overloadedPairs
          .flatMap((p) => [p.host, p.consumer])
          .filter((p) => p.ws.readyState === state).length,
    ),
  });
  let acquired!: () => void;
  const held = new Promise<void>((resolve) => {
    acquired = resolve;
  });
  const blocker = locked(async (tx) => {
    acquired();
    await tx.$queryRaw`SELECT 1 AS held FROM pg_sleep(6)`;
  });
  // Keep a rejection observed while the independent client closure proof runs;
  // the awaited result below still makes any holder failure fail the proof.
  void blocker.catch(() => {});
  await held;
  const overloaded = now();
  freshnessBoundary = overloaded + 5000;
  let postDeadlineAttempts = 0;
  const staleFrameProbe = (async () => {
    await sleep(5001);
    if (signal.aborted) return;
    const payload = new ArrayBuffer(8);
    new DataView(payload).setFloat64(0, now(), true);
    for (const pair of overloadedPairs) {
      if (pair.host.ws.readyState === WebSocket.OPEN) {
        postDeadlineAttempts++;
        pair.host.ws.send(payload);
      }
    }
    await sleep(50);
    assert.equal(
      postDeadlineForwards,
      0,
      "frames sent after freshness deadline must not forward",
    );
  })();
  void staleFrameProbe.catch(() => {});
  churnTask = (async () => {
    await Promise.all(
      Array.from({ length: 8 }, async () => {
        while (!stopChurn && churnAttempts < 80) {
          churnAttempts++;
          const peer = await connect(`churn_${churnAttempts}`, "device", false);
          peer.ws.close();
          await sleep(10);
        }
      }),
    );
  })();
  void churnTask.catch(() => {});
  await waitFor(
    () =>
      overloadedPairs.every(
        (pair) =>
          pair.host.ws.readyState === WebSocket.CLOSED &&
          pair.consumer.ws.readyState === WebSocket.CLOSED,
      ),
    5300,
  );
  const closedAt = now();
  await staleFrameProbe;
  stopChurn = true;
  await churnTask;
  await blocker;
  ensureActive();
  (stats.scenarios as unknown[]).push({
    name: "lock-delay-and-churn-fail-closed",
    passed: true,
    lockDelayMs: 6000,
    closeMs: Math.round(closedAt - overloaded),
    churnAttempts,
    postDeadlineAttempts,
    postDeadlineForwards,
    socketCloseSchedulingBudgetMs: 300,
    availabilityQualified: false,
  });
}

const passed = await runFixtureLifecycle({
  report: stats,
  phase: () => phase,
  run: runExperiment,
  cleanup: [
    {
      name: "churn",
      timeoutMs: 7000,
      run: async () => {
        stopChurn = true;
        if (churnTask) await churnTask;
      },
    },
    {
      name: "relay",
      timeoutMs: 2000,
      run: async () => {
        if (relay) await relay.stop();
      },
    },
    {
      name: "sockets",
      timeoutMs: 3000,
      run: async () => {
        for (const ws of sockets) ws.close();
        await waitFor(() => sockets.size === 0, 2000);
      },
    },
    {
      name: "authority-requests",
      timeoutMs: 13_000,
      run: async () => {
        await waitFor(() => concurrent === 0, 12_000);
      },
    },
    {
      name: "prisma",
      timeoutMs: 5000,
      run: async () => {
        await db.prisma.$disconnect();
      },
    },
    {
      name: "pool",
      timeoutMs: 5000,
      run: async () => {
        await db.pool.end();
      },
    },
  ],
  writeReport: async () => {
    ticketMap.clear();
    stats.authorityCalls = authorityCalls;
    stats.admissionRefusals = admissionRefusals;
    stats.maxConcurrent = maxConcurrent;
    stats.delayedValidations = validationSamples.length;
    stats.delayedValidationFailures = validationSamples.filter(
      (s) => s.failed,
    ).length;
    stats.sqlReadsAfterCommit = sqlReadsAfterCommit;
    stats.resultsDeliveredAfterCommit = resultsDeliveredAfterCommit;
    if (!stats.passed) stats.failureState = overloadState?.();
    await writeFile(output, JSON.stringify(stats, null, 2) + "\n", {
      mode: 0o600,
    });
  },
});
if (!passed) {
  // Evidence is already flushed and all bounded cleanup steps were attempted.
  // Do not let a failed socket/server cleanup keep the fixture alive forever.
  process.exit(1);
}
