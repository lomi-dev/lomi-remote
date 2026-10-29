import { describe, expect, test } from "bun:test";
import { boundedSetup, deadline, WindowsStdio, type RetainedChild } from "./windows-stdio";

const encoder = new TextEncoder();
const reply = '{"ok":true,"result":[]}\n';
function fixture(onWrite: (wire: string, fake: ReturnType<typeof child>) => void) {
  const fake = child(onWrite);
  return { fake, adapter: new WindowsStdio(fake.process) };
}
function child(onWrite: (wire: string, fake: ReturnType<typeof child>) => void) {
  let out!: ReadableStreamDefaultController<Uint8Array>;
  let err!: ReadableStreamDefaultController<Uint8Array>;
  let resolveExit!: (code: number) => void;
  let exited = false;
  const writes: string[] = [];
  const fake = {
    writes,
    kills: 0,
    keepStdoutOpen: false,
    keepStderrOpen: false,
    stderrErrored: false,
    failStderr() { fake.stderrErrored = true; err.error(new Error("synthetic private diagnostic")); },
    emit(value: string | Uint8Array) { out.enqueue(typeof value === "string" ? encoder.encode(value) : value); },
    stderr(value: Uint8Array) { err.enqueue(value); },
    exit(code = 0) {
      if (exited) return;
      exited = true;
      if (!fake.keepStdoutOpen) out.close();
      if (!fake.keepStderrOpen && !fake.stderrErrored) err.close();
      resolveExit(code);
    },
    process: undefined as unknown as RetainedChild,
  };
  fake.process = {
    stdout: new ReadableStream({ start(controller) { out = controller; } }),
    stderr: new ReadableStream({ start(controller) { err = controller; } }),
    exited: new Promise<number>(resolve => { resolveExit = resolve; }),
    stdin: {
      write(bytes) {
        const wire = new TextDecoder().decode(bytes);
        writes.push(wire);
        if (JSON.parse(wire).op === "shutdown") {
          fake.emit(reply);
          setTimeout(() => fake.exit(), 0);
        } else onWrite(wire, fake);
        return bytes.length;
      },
      flush() { return 0; },
      end() { return 0; },
    },
    kill() { fake.kills++; fake.exit(1); },
  };
  return fake;
}
const command = { op: "write", slot: "test" };
async function failedPermanently(adapter: WindowsStdio) {
  await expect(adapter.command(command)).rejects.toThrow("WINDOWS_STDIO_FAILED");
  const cleanup = await adapter.close();
  expect(cleanup.directChildExited).toBe(true);
  expect(cleanup.graceful).toBe(false);
}

// Prepared source only. Run on the pinned Windows Bun inside the native Job harness.
describe.skipIf(process.platform !== "win32" || Bun.version !== "1.4.2")("Windows binary stdio boundary", () => {
  test("sequential commands and explicit shutdown confirm exit", async () => {
    const { fake, adapter } = fixture((_wire, fake) => fake.emit(reply));
    expect(await adapter.command(command)).toEqual([]);
    expect(await adapter.command(command)).toEqual([]);
    expect(await adapter.close()).toEqual({ confirmed: true, directChildExited: true, graceful: true, exitCode: 0 });
    expect(fake.writes.map(wire => JSON.parse(wire).op)).toEqual(["write", "write", "shutdown"]);
    expect(fake.kills).toBe(0);
  });
  test("fragmented UTF-8 bytes and LF", async () => {
    const bytes = encoder.encode('{"ok":true,"result":"ą"}\n');
    const { adapter } = fixture((_wire, fake) => {
      for (const byte of bytes) fake.emit(new Uint8Array([byte]));
    });
    expect(await adapter.command(command)).toBe("ą");
    expect((await adapter.close()).graceful).toBe(true);
  });
  for (const [name, bytes] of [
    ["coalesced extra response", encoder.encode(reply + reply)],
    ["oversize line", encoder.encode("x".repeat(128 * 1024) + "\n")],
    ["full line without LF", encoder.encode("x".repeat(128 * 1024))],
    ["invalid UTF-8", new Uint8Array([0xff, 10])],
    ["malformed JSON", encoder.encode("{\n")],
    ["rejected helper operation", encoder.encode('{"ok":false,"error":"secret"}\n')],
  ] as const) {
    test(name, async () => {
      const { fake, adapter } = fixture((_wire, fake) => fake.emit(bytes));
      await failedPermanently(adapter);
      expect(fake.writes.length).toBe(1);
    });
  }
  test("short unterminated line followed by EOF", async () => {
    const { adapter } = fixture((_wire, fake) => { fake.emit("{"); fake.exit(1); });
    await failedPermanently(adapter);
  });
  test("early exit", async () => {
    const { adapter } = fixture((_wire, fake) => fake.exit(2));
    await failedPermanently(adapter);
  });
  test("command total deadline and no retry", async () => {
    const { fake, adapter } = fixture(() => {});
    await failedPermanently(adapter);
    expect(fake.writes.length).toBe(1);
  }, 12_000);
  test("stderr within 64 KiB is discarded while stdout completes", async () => {
    const { adapter } = fixture((_wire, fake) => {
      for (let index = 0; index < 16; index++) fake.stderr(new Uint8Array(4096));
      fake.emit(reply);
    });
    expect(await adapter.command(command)).toEqual([]);
    expect((await adapter.close()).graceful).toBe(true);
  });
  test("stderr flood over 64 KiB permanently fails without another command", async () => {
    const { fake, adapter } = fixture((_wire, fake) => {
      fake.stderr(new Uint8Array(64 * 1024 + 1));
    });
    await failedPermanently(adapter);
    expect(fake.writes.length).toBe(1);
  });
  for (const accepted of ["short", "zero"] as const) test(`${accepted} write fails without resending`, async () => {
    const { fake, adapter } = fixture(() => {});
    fake.process.stdin.write = bytes => { fake.writes.push("short write"); return accepted === "zero" ? 0 : bytes.length - 1; };
    await failedPermanently(adapter);
    expect(fake.writes.length).toBe(1);
  });
  for (const stream of ["keepStdoutOpen", "keepStderrOpen"] as const) {
    test(`${stream} leaves cleanup uncertain after positive child exit`, async () => {
      const { fake, adapter } = fixture((_wire, fake) => fake.emit(reply));
      fake[stream] = true;
      await adapter.command(command);
      expect(await adapter.close()).toEqual({
        confirmed: false, directChildExited: true, graceful: false, exitCode: 0,
      });
    }, 16_000);
  }
  test("stderr reader failure during shutdown prevents cleanup certification", async () => {
    const { fake, adapter } = fixture((_wire, fake) => fake.emit(reply));
    fake.keepStderrOpen = true;
    await adapter.command(command);
    const cleanup = adapter.close();
    setTimeout(() => fake.failStderr(), 10);
    expect(await cleanup).toEqual({
      confirmed: false, directChildExited: true, graceful: false, exitCode: 0,
    });
  });
  test("elapsed completion fails before the timer callback can run", async () => {
    let clock = 100;
    let factoryCalls = 0;
    let timerFired = false;
    const laterTimer = setTimeout(() => { timerFired = true; }, 0);
    try {
      const result = deadline(async () => {
        factoryCalls++;
        clock = 5_101; // Simulate a stall inside the first I/O call.
        return "late response";
      }, 5_000, () => clock);
      await expect(result).rejects.toThrow("WINDOWS_STDIO_FAILED");
      expect(factoryCalls).toBe(1);
      expect(timerFired).toBe(false); // Promise completion runs before timers.
    } finally { clearTimeout(laterTimer); }
  });
  test("budget is captured before invoking the first I/O factory", async () => {
    let reads = 0;
    let factoryCalls = 0;
    const result = deadline(async () => { factoryCalls++; return []; }, 5_000,
      () => ++reads === 1 ? 100 : 5_101);
    await expect(result).rejects.toThrow("WINDOWS_STDIO_FAILED");
    expect(factoryCalls).toBe(0);
  });
  test("timed-out setup cannot late-spawn after delayed work or a clock rollback", async () => {
    let release!: () => void;
    const gate = new Promise<void>(resolve => { release = resolve; });
    let wouldSpawn = 0;
    let clock = 100;
    let completed!: () => void;
    const workDone = new Promise<void>(resolve => { completed = resolve; });
    const setup = boundedSetup(async check => {
      try { await gate; check(); wouldSpawn++; } finally { completed(); }
    }, 10, () => clock);
    await expect(setup).rejects.toThrow("WINDOWS_STDIO_FAILED");
    clock = 0; // Sticky cancellation must survive any clock movement.
    release();
    await workDone;
    expect(wouldSpawn).toBe(0);
  });
  test("extra response in a later chunk before next command poisons boundary", async () => {
    const { fake, adapter } = fixture((_wire, fake) => fake.emit(reply));
    await adapter.command(command);
    fake.emit(reply);
    await new Promise(resolve => setTimeout(resolve, 0));
    await failedPermanently(adapter);
    expect(fake.writes.length).toBe(1);
  });
  test("extra pending response while flush is blocked fails permanently", async () => {
    const { fake, adapter } = fixture((_wire, fake) => fake.emit(reply));
    fake.process.stdin.flush = async () => {
      fake.emit(reply);
      await new Promise(resolve => setTimeout(resolve, 0));
      return 0;
    };
    await failedPermanently(adapter);
  });
  test("concurrent command fails closed without a second write", async () => {
    const { fake, adapter } = fixture(() => {});
    const first = adapter.command(command);
    const firstRejected = expect(first).rejects.toThrow("WINDOWS_STDIO_FAILED");
    await expect(adapter.command(command)).rejects.toThrow("WINDOWS_STDIO_FAILED");
    await firstRejected;
    await failedPermanently(adapter);
    expect(fake.writes.length).toBe(1);
  });
  test("cleanup uncertainty is explicit if retained child never confirms exit", async () => {
    const { fake, adapter } = fixture(() => {});
    fake.process.kill = () => { fake.kills++; };
    await expect(adapter.command(command)).rejects.toThrow("WINDOWS_STDIO_FAILED");
    expect(await adapter.close()).toEqual({ confirmed: false, directChildExited: false, graceful: false });
  }, 16_000);
});
