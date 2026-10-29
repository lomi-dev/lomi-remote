/** Windows test fixture only. Requires a native parent-owned kill-on-close Job. */
import { win32 as path } from "node:path";
import { lstat, realpath } from "node:fs/promises";

const MAX_LINE = 128 * 1024; // Includes LF, matching transport_authority.rs.
const COMMAND_MS = 5_000;
const IDLE_MS = 60_000;
const MAX_STDERR = 64 * 1024;
const OPS = new Set([
  "init", "sign_enrollment", "sign_window", "sign_grant", "sign_context",
  "start", "read", "write", "finish", "seal", "open", "dispose", "shutdown",
]);
export type Command = { op: string; [key: string]: unknown };
export type Cleanup = { confirmed: boolean; directChildExited: boolean; graceful: boolean; exitCode?: number };
// Structural seam for byte-stream tests; production retains the actual Bun.Subprocess.
export interface RetainedChild {
  stdin: { write(bytes: Uint8Array): number | Promise<number>; flush(): number | Promise<number>; end(): number | Promise<number> };
  stdout: ReadableStream<Uint8Array>;
  stderr: ReadableStream<Uint8Array>;
  exited: Promise<number>;
  kill(): void;
}
function fault(): Error { return new Error("WINDOWS_STDIO_FAILED"); }
/** Clock injection is a test seam; production always uses monotonic performance.now. */
export function deadline<T>(work: () => Promise<T>, ms: number,
  now: () => number = () => performance.now()): Promise<T> {
  const expiresAt = now() + ms; // Capture before invoking any I/O factory.
  let expired = false;
  return new Promise((resolve, reject) => {
    const cancel = () => { expired = true; clearTimeout(timer); reject(fault()); };
    const timer = setTimeout(cancel, ms);
    try {
      if (now() >= expiresAt) { cancel(); return; }
      // Install the timer before invoking work; write/flush/reply share one budget.
      Promise.resolve(work()).then(value => {
        if (expired || now() >= expiresAt) { cancel(); return; }
        clearTimeout(timer);
        resolve(value);
      }, cancel);
    } catch { cancel(); }
  });
}

/** Test seam for cancellation only; never accepts a process-spawn override. */
export function boundedSetup<T>(work: (check: () => void) => Promise<T>, ms = COMMAND_MS,
  now: () => number = () => performance.now()): Promise<T> {
  const started = now();
  let cancelled = false;
  return new Promise((resolve, reject) => {
    const cancel = () => { cancelled = true; reject(fault()); };
    const timer = setTimeout(cancel, ms);
    const check = () => {
      if (cancelled || now() - started >= ms) { cancelled = true; throw fault(); }
    };
    Promise.resolve().then(() => { check(); return work(check); }).then(value => {
      clearTimeout(timer);
      if (!cancelled) resolve(value);
    }, () => { clearTimeout(timer); cancel(); });
  });
}

/** Test seam. Call openWindowsStdio for real processes. Never retries a command. */
export class WindowsStdio {
  private failed = false;
  private closing = false;
  private ended = false;
  private stdoutEof = false;
  private stderrEof = false;
  private readerFailed = false;
  private stdinClosed = false;
  private inputDone: Promise<void> | undefined;
  private exitCode: number | undefined;
  private count = 0;
  private idle: ReturnType<typeof setTimeout> | undefined;
  private pending: { resolve(value: unknown): void; reject(error: Error): void; seen: boolean } | undefined;
  private bytes = new Uint8Array(MAX_LINE);
  private used = 0;
  private closeResult: Promise<Cleanup> | undefined;
  private readonly exit: Promise<number>;
  private readonly outputDone: Promise<void>;
  private readonly stderrDone: Promise<void>;
  constructor(private readonly child: RetainedChild) {
    this.exit = child.exited.then(code => {
      this.ended = true;
      this.exitCode = code;
      // During shutdown, pipe readers still validate buffered output after exit.
      if (!this.closing) this.fail();
      return code;
    }, () => { this.fail(); throw fault(); });
    void this.exit.catch(() => {});
    this.outputDone = this.readStdout();
    this.stderrDone = this.drainStderr();
    this.armIdle();
  }
  private armIdle(): void {
    clearTimeout(this.idle);
    if (!this.failed && !this.closing) this.idle = setTimeout(() => this.fail(), IDLE_MS);
  }
  private fail(): void {
    if (this.failed) return;
    this.failed = true;
    clearTimeout(this.idle);
    this.pending?.reject(fault());
    this.bytes.fill(0);
    this.used = 0;
    void this.endInput().catch(() => {});
    try { this.child.kill(); } catch { /* close() reports uncertainty */ }
  }
  private endInput(): Promise<void> {
    if (this.inputDone) return this.inputDone;
    try {
      this.inputDone = Promise.resolve(this.child.stdin.end()).then(() => {
        this.stdinClosed = true;
      }, () => { this.fail(); throw fault(); });
    } catch { this.inputDone = Promise.reject(fault()); }
    return this.inputDone;
  }
  private async drainStderr(): Promise<void> {
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let total = 0;
    try {
      reader = this.child.stderr.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) { this.stderrEof = true; return; }
        // Saturating byte count, no retained contents, continue draining after failure.
        total = Math.min(MAX_STDERR + 1, total + value.byteLength);
        if (total > MAX_STDERR) this.fail();
      }
    } catch { this.readerFailed = true; this.fail(); }
    finally { reader?.releaseLock(); }
  }
  private async readStdout(): Promise<void> {
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    try {
      reader = this.child.stdout.getReader();
      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          this.stdoutEof = true;
          if (this.used || (this.pending && !this.pending.seen) || !this.closing) this.fail();
          return;
        }
        if (this.failed) continue; // Drain until exit without retaining more bytes.
        let response: unknown;
        let complete = false;
        for (const byte of value) {
          if (!this.pending || this.pending.seen || complete || this.used >= MAX_LINE) throw fault();
          this.bytes[this.used++] = byte;
          if (byte !== 10) continue;
          const line = new TextDecoder("utf-8", { fatal: true }).decode(this.bytes.subarray(0, this.used - 1));
          this.bytes.fill(0, 0, this.used);
          this.used = 0;
          const parsed = JSON.parse(line);
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw fault();
          const keys = Object.keys(parsed).sort().join(",");
          if (parsed.ok !== true || keys !== "ok,result") throw fault();
          response = parsed.result;
          complete = true;
        }
        // Validate the entire chunk before releasing the one waiting command.
        if (complete) {
          this.pending!.seen = true;
          this.pending!.resolve(response);
        }
        if (this.used === MAX_LINE) throw fault(); // No room for a required LF.
      }
    } catch { this.readerFailed = true; this.fail(); } finally { reader?.releaseLock(); }
  }
  async command(command: Command): Promise<unknown> {
    if (this.failed || this.closing || this.ended || this.pending) { this.fail(); throw fault(); }
    if (command.op === "shutdown") { this.fail(); throw fault(); } // close owns shutdown.
    return this.exchange(command);
  }
  private async exchange(command: Command): Promise<unknown> {
    clearTimeout(this.idle);
    let wire: Uint8Array;
    try {
      if (!OPS.has(command.op) || ++this.count > 8192) throw fault();
      wire = new TextEncoder().encode(JSON.stringify(command) + "\n");
      if (wire.length > MAX_LINE) throw fault();
    } catch { this.fail(); throw fault(); }
    const response = new Promise<unknown>((resolve, reject) => {
      this.pending = { resolve, reject, seen: false };
    });
    // Attach immediately, including when write/flush fails before awaiting response.
    void response.catch(() => {});
    try {
      const result = await deadline(async () => {
        if (this.failed) throw fault();
        const written = await this.child.stdin.write(wire);
        // Fail rather than resend an ambiguous short write of a stateful command.
        if (written !== wire.byteLength) throw fault();
        await this.child.stdin.flush();
        return await response;
      }, COMMAND_MS);
      if (this.failed) throw fault();
      return result;
    } catch { this.fail(); throw fault(); }
    finally { wire.fill(0); this.pending = undefined; this.armIdle(); }
  }
  close(): Promise<Cleanup> {
    return this.closeResult ??= this.finishClose();
  }
  private async finishClose(): Promise<Cleanup> {
    this.closing = true;
    clearTimeout(this.idle);
    let graceful = false;
    if (this.pending) this.fail();
    if (!this.failed && !this.ended) {
      try {
        await deadline(async () => {
          await this.exchange({ op: "shutdown" });
          await this.endInput();
          const code = await this.exit;
          if (code !== 0) throw fault();
          await Promise.all([this.outputDone, this.stderrDone]);
        }, COMMAND_MS);
        graceful = !this.failed;
      } catch { this.fail(); }
    }
    if (!graceful) {
      if (!this.ended) {
        try { this.child.kill(); } catch { /* await positive exit below */ }
      }
      try {
        await deadline(() => Promise.all([this.exit, this.outputDone, this.stderrDone, this.endInput()]), COMMAND_MS);
      } catch { /* exit or stream cleanup remains uncertain */ }
    }
    const confirmed = this.ended && this.stdinClosed && this.stdoutEof && this.stderrEof && !this.readerFailed;
    return { confirmed, directChildExited: this.ended, graceful: graceful && confirmed,
      ...(this.ended ? { exitCode: this.exitCode } : {}) };
  }
}

export type WindowsConfig = Readonly<{
  executable: string;
  sha256: string;
  privateWorkingDirectory: string;
  systemRoot: string;
}>;
function absoluteLocal(value: string): boolean {
  return /^[A-Za-z]:\\/.test(value) && path.normalize(value) === value && !value.includes("\0")
    && !value.slice(2).includes(":");
}
/** Config comes from the trusted native controller, never from operator environment. */
export async function openWindowsStdio(config: WindowsConfig): Promise<WindowsStdio> {
  if (process.platform !== "win32" || Bun.version !== "1.4.2") throw fault();
  return boundedSetup(async check => {
    if (!absoluteLocal(config.executable) || !absoluteLocal(config.privateWorkingDirectory)
      || !absoluteLocal(config.systemRoot) || !/^[a-f0-9]{64}$/.test(config.sha256)
      || path.basename(config.executable) !== "transport_authority.exe") throw fault();
    for (const target of [config.executable, config.privateWorkingDirectory, config.systemRoot]) {
      if ((await lstat(target)).isSymbolicLink() || (await realpath(target)).toLowerCase() !== target.toLowerCase()) throw fault();
    }
    if (!(await lstat(config.executable)).isFile()
      || !(await lstat(config.privateWorkingDirectory)).isDirectory()
      || !(await lstat(config.systemRoot)).isDirectory()) throw fault();
    const hasher = new Bun.CryptoHasher("sha256");
    const reader = Bun.file(config.executable).stream().getReader();
    try {
      while (true) {
        const chunk = await reader.read();
        if (chunk.done) break;
        check();
        hasher.update(chunk.value);
      }
    } finally { reader.releaseLock(); }
    if (hasher.digest("hex") !== config.sha256) throw fault();
    check();
    // No await between final deadline check and spawn: timed-out setup cannot spawn later.
    const child = Bun.spawn([config.executable], {
      cwd: config.privateWorkingDirectory,
      env: { SystemRoot: config.systemRoot, TEMP: config.privateWorkingDirectory, TMP: config.privateWorkingDirectory },
      stdin: "pipe", stdout: "pipe", stderr: "pipe",
    });
    return new WindowsStdio(child);
  });
}
