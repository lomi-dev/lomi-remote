/** Bounded assembler for Rust-validated terminal stream frames. */

const MAX_TOTAL = 8 * 1024 * 1024;
const MAX_CHUNK = 16_384;
const MAX_CHUNKS = 1024;
const MAX_FRAME = 1024 * 1024;
const MAX_U64 = 18_446_744_073_709_551_615n;
const MAX_DIAGNOSTIC_COUNT = 1_000_000;

export type TerminalStreamErrorOrigin = "STREAM_VALIDATION" | "HOST_RESYNC" | "EARLY_BUFFER";
export type TerminalStreamDiagnosticPhase =
  | "IDLE"
  | "FRAME_RECEIVED"
  | "SNAPSHOT_METADATA"
  | "DELTA_METADATA"
  | "SNAPSHOT_CHUNK"
  | "DELTA_CHUNK"
  | "SNAPSHOT_COMPLETE"
  | "DELTA_COMPLETE"
  | "SNAPSHOT_VALIDATED"
  | "DELTA_VALIDATED"
  | "DIRECT_DELTA_VALIDATED"
  | "ACK_VALIDATED"
  | "HOST_RESYNC"
  | "EARLY_BUFFER"
  | "STREAM_VALIDATION_FAILED";

export type TerminalStreamDiagnostics = {
  phase: TerminalStreamDiagnosticPhase;
  frameCount: number;
  snapshotMetadataCount: number;
  deltaMetadataCount: number;
  chunkExpected: number;
  chunkReceived: number;
  snapshotCompleteCount: number;
  deltaCompleteCount: number;
  snapshotValidatedCount: number;
  deltaValidatedCount: number;
};

function incrementDiagnosticCount(value: number): number {
  return value < MAX_DIAGNOSTIC_COUNT ? value + 1 : MAX_DIAGNOSTIC_COUNT;
}

export class TerminalStreamResyncError extends Error {
  readonly name = "TerminalStreamResyncError";
  readonly origin: TerminalStreamErrorOrigin;
  constructor(
    message: string,
    readonly reason = "snapshot_invalid",
    origin: TerminalStreamErrorOrigin = "STREAM_VALIDATION",
  ) {
    super(message);
    this.origin = origin === "HOST_RESYNC" || origin === "EARLY_BUFFER" ? origin : "STREAM_VALIDATION";
    Object.defineProperty(this, "origin", { value: this.origin, enumerable: true, writable: false, configurable: false });
  }
}

type Obj = Record<string, unknown>;
export type AssembledTerminalValue = {
  kind: "snapshot" | "delta" | "event";
  terminal: Obj;
  subscriptionId: string;
  throughSeq: string;
  outputOffset?: string;
  workingDirectory?: string | null;
  value: unknown;
};

function bad(message: string): never { throw new TerminalStreamResyncError(message); }
function obj(v: unknown, name: string): Obj {
  if (!v || typeof v !== "object" || Array.isArray(v)) bad(`${name} must be an object`);
  return v as Obj;
}
function exact(v: Obj, keys: string[], name: string): void {
  const a = Object.keys(v).sort(), b = [...keys].sort();
  if (a.length !== b.length || a.some((x, i) => x !== b[i])) bad(`${name} has invalid shape`);
}
function dec(v: unknown, name: string): string {
  if (typeof v !== "string" || !/^(0|[1-9][0-9]*)$/.test(v) || BigInt(v) > MAX_U64) bad(`${name} is invalid`);
  return v;
}
function workingDirectory(v: unknown): string | null {
  if (v === null) return null;
  if (
    typeof v !== "string" ||
    v.length === 0 ||
    v.length > 4096 ||
    /[\x00-\x1f\x7f-\x9f]/.test(v)
  ) bad("workingDirectory is invalid");
  const posix = v.startsWith("/") && !v.startsWith("//");
  const windows = /^[A-Za-z]:[\\/]/.test(v);
  if (
    (!posix && !windows) ||
    v.startsWith("\\\\") ||
    v.split(/[\\/]/).some((part) => part === "." || part === "..")
  ) bad("workingDirectory must be an absolute local path");
  return v;
}
function context(v: unknown): Obj {
  const t = obj(v, "terminal"); exact(t, ["paneId", "profile", "sessionEpoch", "sessionId", "workspace"], "terminal");
  for (const k of ["paneId", "sessionId"] as const) if (typeof t[k] !== "string" || !(t[k] as string).length) bad(`terminal.${k} is invalid`);
  if (t.profile !== "lomi-rust-grid-v1-experimental") bad("terminal profile is unsupported");
  if (typeof t.sessionEpoch !== "string" || !/^[0-9a-f-]{36}$/.test(t.sessionEpoch)) bad("session epoch is invalid");
  const w = obj(t.workspace, "workspace"); exact(w, ["grantRevision", "hostAccessEpoch", "runtimeGeneration", "runtimeId", "workspaceEpoch", "workspaceId"], "workspace");
  for (const k of ["grantRevision", "hostAccessEpoch", "runtimeGeneration"]) dec(w[k], k);
  for (const k of ["runtimeId", "workspaceEpoch", "workspaceId"]) if (typeof w[k] !== "string" || !(w[k] as string).length) bad(`${k} is invalid`);
  return t;
}
function stable(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(stable);
  if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, stable((v as Obj)[k])]));
  return v;
}
function same(a: unknown, b: unknown): boolean { return JSON.stringify(stable(a)) === JSON.stringify(stable(b)); }
function bytes(v: unknown): Uint8Array {
  if (!Array.isArray(v) || v.length === 0 || v.length > MAX_CHUNK) bad("chunk bytes are empty, invalid, or oversized");
  const out = new Uint8Array(v.length);
  for (let i = 0; i < v.length; i++) {
    if (!Number.isInteger(v[i]) || (v[i] as number) < 0 || (v[i] as number) > 255) { out.fill(0); bad("chunk byte is invalid"); }
    out[i] = v[i] as number;
  }
  return out;
}

export class TerminalStreamAssembler {
  private current?: { kind: "snapshot" | "delta"; terminal: Obj; sub: string; through: string; offset?: string; rows?: number; columns?: number; count: number; total: number; previous?: string; workingDirectory: string | null; parts: Uint8Array[]; received: number };

  private diagnostics: TerminalStreamDiagnostics = {
    phase: "IDLE",
    frameCount: 0,
    snapshotMetadataCount: 0,
    deltaMetadataCount: 0,
    chunkExpected: 0,
    chunkReceived: 0,
    snapshotCompleteCount: 0,
    deltaCompleteCount: 0,
    snapshotValidatedCount: 0,
    deltaValidatedCount: 0,
  };

  private readonly expectedTerminal: Obj;

  constructor(expectedTerminal: unknown, private readonly expectedSubscriptionId: string) {
    this.expectedTerminal = JSON.parse(JSON.stringify(context(expectedTerminal))) as Obj;
    if (typeof expectedSubscriptionId !== "string" || expectedSubscriptionId.length === 0) bad("expected subscriptionId is invalid");
  }

  /** Seeds the assembly from the metadata returned by terminal.attach. */
  static fromSnapshotMetadata(
    expectedTerminal: unknown,
    expectedSubscriptionId: string,
    metadata: unknown,
  ): TerminalStreamAssembler {
    const stream = new TerminalStreamAssembler(expectedTerminal, expectedSubscriptionId);
    stream.acceptMetadata("snapshotMetadata", metadata);
    return stream;
  }

  private assertTarget(terminalValue: unknown, subscriptionValue: unknown): Obj {
    const actual = context(terminalValue);
    if (!same(actual, this.expectedTerminal) || subscriptionValue !== this.expectedSubscriptionId) bad("frame target or subscription mismatch");
    return actual;
  }

  private acceptMetadata(type: "snapshotMetadata" | "deltaMetadata", value: unknown): void {
    if (this.current) bad("interleaved terminal stream assembly");
    const d = obj(value, "metadata");
    const snap = type === "snapshotMetadata";
    exact(d, snap ? ["chunkCount", "columns", "outputOffset", "rows", "subscriptionId", "terminal", "throughSeq", "totalBytes", "workingDirectory"] : ["chunkCount", "previousSeq", "subscriptionId", "terminal", "throughSeq", "totalBytes", "workingDirectory"], "metadata");
    const count = d.chunkCount, total = Number(dec(d.totalBytes, "totalBytes"));
    if (!Number.isInteger(count) || (count as number) < 1 || (count as number) > MAX_CHUNKS || total < 1 || total > MAX_TOTAL || total > (count as number) * MAX_CHUNK) bad("assembly limits exceeded");
    if (typeof d.subscriptionId !== "string" || !d.subscriptionId) bad("subscriptionId invalid");
    const terminal = this.assertTarget(d.terminal, d.subscriptionId), through = dec(d.throughSeq, "throughSeq");
    let offset: string | undefined;
    let previous: string | undefined;
    if (snap) { offset = dec(d.outputOffset, "outputOffset"); if (!Number.isInteger(d.rows) || (d.rows as number) < 2 || (d.rows as number) > 256 || !Number.isInteger(d.columns) || (d.columns as number) < 2 || (d.columns as number) > 512) bad("snapshot geometry invalid"); }
    else { previous = dec(d.previousSeq, "previousSeq"); if (BigInt(through) !== BigInt(previous) + 1n) bad("delta sequence range is invalid"); }
    this.current = { kind: snap ? "snapshot" : "delta", terminal, sub: d.subscriptionId, through, offset, rows: snap ? d.rows as number : undefined, columns: snap ? d.columns as number : undefined, previous, workingDirectory: workingDirectory(d.workingDirectory), count: count as number, total, parts: [], received: 0 };
    this.diagnostics = {
      ...this.diagnostics,
      phase: snap ? "SNAPSHOT_METADATA" : "DELTA_METADATA",
      snapshotMetadataCount: snap ? incrementDiagnosticCount(this.diagnostics.snapshotMetadataCount) : this.diagnostics.snapshotMetadataCount,
      deltaMetadataCount: snap ? this.diagnostics.deltaMetadataCount : incrementDiagnosticCount(this.diagnostics.deltaMetadataCount),
      chunkExpected: count as number,
      chunkReceived: 0,
    };
  }

  getDiagnostics(): TerminalStreamDiagnostics { return { ...this.diagnostics }; }

  push(input: Uint8Array | string): AssembledTerminalValue | null {
    this.diagnostics = {
      ...this.diagnostics,
      phase: "FRAME_RECEIVED",
      frameCount: incrementDiagnosticCount(this.diagnostics.frameCount),
    };
    try {
      const inputLength = typeof input === "string" ? new TextEncoder().encode(input).byteLength : input.byteLength;
      if (inputLength > MAX_FRAME) bad("terminal frame exceeds 1 MiB limit");
      const raw = typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: true }).decode(input);
      const frame = obj(JSON.parse(raw), "frame"); exact(frame, ["type", "data"], "frame");
      if (typeof frame.type !== "string") bad("frame type is invalid");
      const d = obj(frame.data, "frame data");
      if (frame.type === "resyncRequired") {
        exact(d, ["reason", "subscriptionId", "terminal"], "resync");
        this.assertTarget(d.terminal, d.subscriptionId);
        if (typeof d.reason !== "string") bad("resync signal is invalid");
        this.diagnostics = { ...this.diagnostics, phase: "HOST_RESYNC" };
        this.clear(); throw new TerminalStreamResyncError("terminal stream requested resync", d.reason, "HOST_RESYNC");
      }
      if (frame.type === "snapshotMetadata" || frame.type === "deltaMetadata") {
        this.acceptMetadata(frame.type, d);
        return null;
      }
      if (frame.type === "snapshotChunk" || frame.type === "deltaChunk") {
        const c = this.current; if (!c || (frame.type === "snapshotChunk") !== (c.kind === "snapshot")) bad("unexpected chunk");
        exact(d, ["bytes", "index", "subscriptionId", "terminal"], "chunk");
        this.assertTarget(d.terminal, d.subscriptionId);
        if (d.subscriptionId !== c.sub || !same(context(d.terminal), c.terminal)) bad("chunk context mismatch");
        if (d.index !== c.parts.length || c.parts.length >= c.count) bad("chunk index is out of order");
        const b = bytes(d.bytes); if (c.received + b.length > c.total || c.received + b.length > MAX_TOTAL) { b.fill(0); bad("chunk total exceeds metadata"); }
        c.parts.push(b); c.received += b.length;
        this.diagnostics = {
          ...this.diagnostics,
          phase: c.kind === "snapshot" ? "SNAPSHOT_CHUNK" : "DELTA_CHUNK",
          chunkReceived: Math.min(MAX_CHUNKS, c.parts.length),
        };
        return null;
      }
      if (frame.type === "snapshotComplete" || frame.type === "deltaComplete") {
        const c = this.current; if (!c || (frame.type === "snapshotComplete") !== (c.kind === "snapshot")) bad("unexpected completion");
        exact(d, c.kind === "snapshot" ? ["outputOffset", "subscriptionId", "terminal", "throughSeq"] : ["subscriptionId", "terminal", "throughSeq"], "completion");
        this.assertTarget(d.terminal, d.subscriptionId);
        if (d.subscriptionId !== c.sub || !same(context(d.terminal), c.terminal) || dec(d.throughSeq, "throughSeq") !== c.through || (c.kind === "snapshot" && dec(d.outputOffset, "outputOffset") !== c.offset)) bad("completion binding mismatch");
        this.diagnostics = {
          ...this.diagnostics,
          phase: c.kind === "snapshot" ? "SNAPSHOT_COMPLETE" : "DELTA_COMPLETE",
          snapshotCompleteCount: c.kind === "snapshot" ? incrementDiagnosticCount(this.diagnostics.snapshotCompleteCount) : this.diagnostics.snapshotCompleteCount,
          deltaCompleteCount: c.kind === "snapshot" ? this.diagnostics.deltaCompleteCount : incrementDiagnosticCount(this.diagnostics.deltaCompleteCount),
        };
        if (c.parts.length !== c.count || c.received !== c.total) bad("incomplete or inconsistent assembly");
        const joined = new Uint8Array(c.total); let at = 0;
        for (const p of c.parts) { joined.set(p, at); at += p.length; p.fill(0); }
        this.current = undefined;
        try {
          const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(joined));
          const value = obj(parsed, "assembled payload");
          if (c.kind === "snapshot") {
            exact(value, ["profile", "version", "sessionEpoch", "sequence", "outputOffset", "rows", "cols", "active", "normal", "alternate", "modes", "title", "cursorStyle", "colors"], "snapshot payload");
            if (value.profile !== c.terminal.profile || value.sessionEpoch !== c.terminal.sessionEpoch || value.sequence !== c.through || value.outputOffset !== c.offset || value.rows !== c.rows || value.cols !== c.columns) bad("snapshot payload binding mismatch");
          } else {
            exact(value, ["profile", "version", "format", "sessionEpoch", "previousSequence", "sequence", "outputOffset", "rows", "cols", "update"], "patch payload");
            if (value.profile !== c.terminal.profile || value.sessionEpoch !== c.terminal.sessionEpoch || value.format !== "grid-patch-v1" || value.sequence !== c.through || value.previousSequence !== c.previous) bad("patch payload binding mismatch");
          }
          this.diagnostics = {
            ...this.diagnostics,
            phase: c.kind === "snapshot" ? "SNAPSHOT_VALIDATED" : "DELTA_VALIDATED",
            snapshotValidatedCount: c.kind === "snapshot" ? incrementDiagnosticCount(this.diagnostics.snapshotValidatedCount) : this.diagnostics.snapshotValidatedCount,
            deltaValidatedCount: c.kind === "snapshot" ? this.diagnostics.deltaValidatedCount : incrementDiagnosticCount(this.diagnostics.deltaValidatedCount),
          };
          return { kind: c.kind, terminal: c.terminal, subscriptionId: c.sub, throughSeq: c.through, outputOffset: c.offset, workingDirectory: c.workingDirectory, value };
        } finally { joined.fill(0); }
      }
      if (frame.type === "delta") {
        if (this.current) bad("direct delta interleaved with assembly");
        exact(d, ["change", "seq", "subscriptionId", "terminal"], "delta");
        const subscriptionId = d.subscriptionId;
        if (typeof subscriptionId !== "string" || !subscriptionId) bad("subscriptionId invalid");
        const terminal = this.assertTarget(d.terminal, subscriptionId), seq = dec(d.seq, "seq");
        const change = obj(d.change, "change");
        if (change.kind === "grid") {
          exact(change, ["kind", "data"], "grid change");
          const rawBytes = bytes(change.data);
          let parsed: unknown;
          try { parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(rawBytes)); }
          finally { rawBytes.fill(0); }
          const patch = obj(parsed, "grid event patch");
          if (patch.format !== "grid-patch-v1" || patch.sequence !== seq || patch.sessionEpoch !== terminal.sessionEpoch) bad("direct grid event binding mismatch");
          this.diagnostics = { ...this.diagnostics, phase: "DIRECT_DELTA_VALIDATED" };
          return { kind: "event", terminal, subscriptionId, throughSeq: seq, value: patch };
        }
        if (change.kind === "resize") {
          exact(change, ["kind", "data"], "resize change"); const size = obj(change.data, "resize"); exact(size, ["columns", "rows"], "resize");
          if (!Number.isInteger(size.columns) || (size.columns as number) < 2 || (size.columns as number) > 512 || !Number.isInteger(size.rows) || (size.rows as number) < 2 || (size.rows as number) > 256) bad("resize geometry invalid");
        } else if (change.kind === "exit") {
          const e = obj(change.data, "exit"); exact(e, Object.hasOwn(e, "exitCode") ? ["exitCode"] : [], "exit");
          if (e.exitCode !== undefined && e.exitCode !== null && (!Number.isInteger(e.exitCode) || (e.exitCode as number) < -2147483648 || (e.exitCode as number) > 2147483647)) bad("exit code invalid");
        } else if (change.kind === "controlChanged") {
          exact(change, ["kind", "data"], "control change"); const control = obj(change.data, "control change"); exact(control, ["controlled", "leaseVersion", "terminal"], "control change");
          if (typeof control.controlled !== "boolean" || dec(control.leaseVersion, "leaseVersion") === "") bad("control change invalid");
          if (!same(context(control.terminal), terminal)) bad("control terminal mismatch");
        } else bad("unknown terminal change kind");
        this.diagnostics = { ...this.diagnostics, phase: "DIRECT_DELTA_VALIDATED" };
        return { kind: "event", terminal, subscriptionId, throughSeq: seq, value: d };
      }
      if (frame.type === "ack") {
        exact(d, ["subscriptionId", "terminal", "throughSeq"], "ack");
        this.assertTarget(d.terminal, d.subscriptionId);
        dec(d.throughSeq, "throughSeq");
        this.diagnostics = { ...this.diagnostics, phase: "ACK_VALIDATED" };
        return null;
      }
      bad("unsupported terminal frame");
    } catch (e) {
      this.clear();
      const origin = e instanceof TerminalStreamResyncError ? e.origin : "STREAM_VALIDATION";
      this.diagnostics = {
        ...this.diagnostics,
        phase: origin === "HOST_RESYNC" ? "HOST_RESYNC" : origin === "EARLY_BUFFER" ? "EARLY_BUFFER" : "STREAM_VALIDATION_FAILED",
      };
      if (e instanceof TerminalStreamResyncError) throw e;
      throw new TerminalStreamResyncError("malformed terminal stream frame");
    }
  }

  dispose(): void { this.clear(); }
  private clear(): void { if (this.current) for (const part of this.current.parts) part.fill(0); this.current = undefined; }
}
