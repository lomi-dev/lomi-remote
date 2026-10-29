import assert from "node:assert/strict";
import test from "node:test";
import { observeDelivery, runFixtureLifecycle } from "./lifecycle.mjs";

test("delivery after revoke is observed even when SQL read completed before it", async () => {
  let release;
  let revoked = false;
  let late = 0;
  const read = Promise.resolve({ valid: true });
  const gate = new Promise((resolve) => {
    release = resolve;
  });
  const delivered = observeDelivery(
    async () => {
      const value = await read;
      await gate;
      return value;
    },
    () => revoked,
    () => {
      late++;
    },
  );
  await read;
  revoked = true;
  release();
  assert.deepEqual(await delivered, { valid: true });
  assert.equal(late, 1);
});

test("prompt delivery before revoke is not counted as late", async () => {
  let late = 0;
  assert.equal(
    await observeDelivery(
      async () => 17,
      () => false,
      () => {
        late++;
      },
    ),
    17,
  );
  assert.equal(late, 0);
});

test("a rejected churn cleanup still attempts every later resource and writes failure", async () => {
  const attempted = [];
  const report = { passed: true, cleanupCompleted: true };
  let recorded;
  const okay = await runFixtureLifecycle({
    report,
    phase: () => "churn",
    run: async () => {},
    cleanup: ["churn", "relay", "sockets", "database"].map((name) => ({
      name,
      timeoutMs: 50,
      run: async () => {
        attempted.push(name);
        if (name === "churn") throw new Error("synthetic");
      },
    })),
    writeReport: async () => {
      recorded = structuredClone(report);
    },
  });
  assert.equal(okay, false);
  assert.deepEqual(attempted, ["churn", "relay", "sockets", "database"]);
  assert.equal(recorded.passed, false);
  assert.equal(recorded.cleanupCompleted, false);
  assert.deepEqual(recorded.cleanupErrors, ["churn"]);
  assert.equal(recorded.failure.phase, "churn");
});

test("deadline aborts the experiment and records its phase after all cleanup", async () => {
  const attempted = [];
  const report = {};
  let aborted = false;
  const okay = await runFixtureLifecycle({
    report,
    phase: () => "held-lock",
    timeoutMs: 10,
    settleMs: 50,
    run: (signal) =>
      new Promise((resolve) => {
        signal.addEventListener(
          "abort",
          () => {
            aborted = true;
            resolve();
          },
          { once: true },
        );
      }),
    cleanup: [
      {
        name: "database",
        timeoutMs: 50,
        run: async () => {
          attempted.push("database");
        },
      },
    ],
    writeReport: async () => {
      attempted.push("report");
    },
  });
  assert.equal(okay, false);
  assert.equal(aborted, true);
  assert.deepEqual(attempted, ["database", "report"]);
  assert.deepEqual(report.failure, {
    phase: "held-lock",
    errorClass: "FixtureDeadline",
  });
  assert.equal(report.cleanupCompleted, true);
  assert.equal(report.passed, false);
});

test("unsettled work and hung first cleanup stay failed while later cleanup runs", async () => {
  const report = {};
  const attempted = [];
  const okay = await runFixtureLifecycle({
    report,
    phase: () => "stuck",
    timeoutMs: 10,
    settleMs: 10,
    run: async () => new Promise(() => {}),
    cleanup: [
      {
        name: "hung-relay",
        timeoutMs: 10,
        run: async () => new Promise(() => {}),
      },
      {
        name: "database",
        timeoutMs: 10,
        run: async () => {
          attempted.push("database");
        },
      },
    ],
    writeReport: async () => {
      attempted.push("report");
    },
  });
  assert.equal(okay, false);
  assert.deepEqual(report.cleanupErrors, ["experiment-settle", "hung-relay"]);
  assert.deepEqual(attempted, ["database", "report"]);
  assert.equal(report.cleanupCompleted, false);
});
