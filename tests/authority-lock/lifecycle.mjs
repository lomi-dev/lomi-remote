// Bounded fixture lifecycle; no production authorization policy is implemented.
export async function observeDelivery(
  operation,
  isRevoked,
  deliveredAfterRevoke,
) {
  const value = await operation();
  if (isRevoked()) deliveredAfterRevoke();
  return value;
}

async function within(promise, milliseconds, label) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const error = new Error(label);
          error.name = "FixtureDeadline";
          reject(error);
        }, milliseconds);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

export async function runFixtureLifecycle({
  report,
  phase,
  run,
  cleanup,
  writeReport,
  timeoutMs = 90_000,
  settleMs = 12_000,
}) {
  const controller = new AbortController();
  const errors = [];
  let success = false;
  let settled = false;
  const experiment = Promise.resolve().then(() => run(controller.signal));
  // Observe errors immediately, including when the deadline wins the race.
  void experiment.then(
    () => {
      settled = true;
    },
    () => {
      settled = true;
    },
  );
  try {
    await within(experiment, timeoutMs, "experiment");
    success = true;
  } catch (error) {
    report.failure = {
      phase: phase(),
      errorClass: error instanceof Error ? error.name : "unknown",
    };
  } finally {
    controller.abort();
    if (!settled) {
      try {
        await within(
          experiment.catch(() => {}),
          settleMs,
          "experiment-settle",
        );
      } catch {
        errors.push("experiment-settle");
      }
    }
    try {
      for (const step of cleanup) {
        try {
          await within(
            Promise.resolve().then(step.run),
            step.timeoutMs,
            step.name,
          );
        } catch {
          // Keep only fixed step names, never error bodies or fixture payloads.
          errors.push(step.name);
        }
      }
    } finally {
      report.cleanupErrors = errors;
      report.cleanupCompleted = errors.length === 0;
      report.passed = success && report.cleanupCompleted;
      if (!report.passed && !report.failure)
        report.failure = {
          phase: phase(),
          errorClass: "FixtureCleanupFailure",
        };
      await writeReport();
    }
  }
  return report.passed;
}
