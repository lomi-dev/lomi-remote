/** Bounded workspace assembly shared by the browser, desktop, and phone.
 * Validation is supplied by the canonical Rust codec (WASM or native bridge).
 * The caller applies the returned state/event before sending its ACK.
 */
type ObjectValue = Record<string, unknown>;
export type WorkspaceFrameValidator = (json: string) => void | Promise<void>;
export interface WorkspaceStreamAckValue {
  type: "ack";
  data: { context: ObjectValue; subscriptionId: string; throughSeq: string; cursor: string };
}
export interface AssembledWorkspaceValue {
  state?: ObjectValue;
  event?: ObjectValue;
  ack: WorkspaceStreamAckValue;
}
const MAX_BYTES = 8 * 1024 * 1024;
const MAX_FRAME = 1024 * 1024;
const MAX_U64 = 18_446_744_073_709_551_615n;
const ASSEMBLY_MS = 30_000;
function bad(): never { throw new Error("WORKSPACE_STREAM_INVALID"); }
function object(value: unknown): ObjectValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) bad();
  return value as ObjectValue;
}
function decimal(value: unknown): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value) || BigInt(value) > MAX_U64) bad();
  return value;
}
function stable(value: unknown): string {
  const record = object(value);
  return JSON.stringify(Object.fromEntries(Object.keys(record).sort().map(key => [key, record[key]])));
}
function monotonic(): number {
  const value = globalThis.performance?.now();
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) bad();
  return value;
}

export class WorkspaceStreamAssembler {
  private readonly context: ObjectValue;
  private readonly metadata: ObjectValue;
  private readonly metadataJson: string;
  private readonly deadline = monotonic() + ASSEMBLY_MS;
  private readonly id: string;
  private readonly count: number;
  private readonly total: number;
  private cursor: string;
  private sequence: string;
  private revision: string;
  private parts: Uint8Array[] = [];
  private received = 0;
  private ready = false;
  private metadataValidated = false;
  private busy = false;
  private disposed = false;

  constructor(expectedContext: unknown, metadata: unknown, private readonly validate: WorkspaceFrameValidator) {
    this.context = JSON.parse(JSON.stringify(object(expectedContext))) as ObjectValue;
    this.metadata = JSON.parse(JSON.stringify(object(metadata))) as ObjectValue;
    const value = this.metadata;
    if (stable(value.context) !== stable(this.context) || typeof value.subscriptionId !== "string"
      || !/^[A-Za-z0-9_-]{1,128}$/.test(value.subscriptionId)
      || typeof value.cursor !== "string" || !value.cursor.length || value.cursor.length > 512
      || typeof validate !== "function") bad();
    this.id = value.subscriptionId;
    this.cursor = value.cursor;
    this.sequence = decimal(value.throughSeq);
    this.revision = decimal(value.domainRevision);
    this.count = Number(value.chunkCount);
    this.total = Number(decimal(value.totalBytes));
    if (!Number.isSafeInteger(this.count) || this.count < 1 || this.count > 1024
      || this.total < 1 || this.total > MAX_BYTES || this.total > this.count * 16_384) bad();
    this.metadataJson = JSON.stringify({ type: "snapshotMetadata", data: value });
  }

  private check(): void {
    if (this.disposed || !this.ready && monotonic() >= this.deadline) bad();
  }
  private ack(): WorkspaceStreamAckValue {
    return { type: "ack", data: { context: { ...this.context }, subscriptionId: this.id,
      throughSeq: this.sequence, cursor: this.cursor } };
  }
  /** The caller serializes push/apply/ACK. Concurrent pushes fail closed. */
  async push(input: Uint8Array | string): Promise<AssembledWorkspaceValue | null> {
    try {
      this.check();
      if (this.busy) bad();
      this.busy = true;
      if (!this.metadataValidated) {
        await this.validate(this.metadataJson);
        this.check();
        this.metadataValidated = true;
      }
      if ((typeof input === "string" ? new TextEncoder().encode(input).byteLength : input.byteLength) > MAX_FRAME) bad();
      const raw = typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: true }).decode(input);
      await this.validate(raw);
      this.check();
      const frame = object(JSON.parse(raw)), data = object(frame.data);
      if (data.subscriptionId !== this.id) bad();
      if (frame.type === "resyncRequired") throw new Error("WORKSPACE_STREAM_RESYNC_REQUIRED");
      if (frame.type === "snapshotChunk") {
        if (this.ready || data.index !== this.parts.length || this.parts.length >= this.count || !Array.isArray(data.bytes)
          || data.bytes.length < 1 || data.bytes.length > 16_384 || this.received + data.bytes.length > this.total) bad();
        const bytes = Uint8Array.from(data.bytes as number[]);
        this.parts.push(bytes); this.received += bytes.byteLength;
        return null;
      }
      if (frame.type === "snapshotComplete") {
        if (this.ready || this.parts.length !== this.count || this.received !== this.total
          || data.cursor !== this.cursor || data.throughSeq !== this.sequence) bad();
        const joined = new Uint8Array(this.total);
        let offset = 0;
        for (const part of this.parts) { joined.set(part, offset); offset += part.byteLength; part.fill(0); }
        this.parts = [];
        try {
          const state = object(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(joined)));
          // Reuse Rust's WorkspaceChanged validation, including full layout
          // uniqueness/session invariants, for the assembled snapshot too.
          // A valid state has <=32 tabs/32 panes total and <=33 text values
          // of 4096 UTF-8 bytes. Canonical reserialization fits below the 1 MiB
          // control-frame limit even if the raw 8 MiB snapshot had whitespace.
          await this.validate(JSON.stringify({ type: "event", data: {
            context: this.context, subscriptionId: this.id, eventSeq: "1", cursor: this.cursor,
            data: { kind: "workspace.changed", data: { domainRevision: this.revision, operationId: null, state } },
          } }));
          this.check();
          if (stable(state.context) !== stable(this.context) || state.domainRevision !== this.revision) bad();
          this.ready = true;
          return { state, ack: this.ack() };
        } finally { joined.fill(0); }
      }
      if (frame.type !== "event" || !this.ready || stable(data.context) !== stable(this.context)
        || BigInt(decimal(data.eventSeq)) !== BigInt(this.sequence) + 1n
        || typeof data.cursor !== "string" || !data.cursor.length || data.cursor.length > 512) bad();
      const event = object(data.data);
      let state: ObjectValue | undefined;
      if (event.kind === "workspace.changed") {
        const change = object(event.data);
        state = object(change.state);
        const revision = decimal(change.domainRevision);
        if (BigInt(revision) <= BigInt(this.revision) || state.domainRevision !== revision || stable(state.context) !== stable(this.context)) bad();
        this.revision = revision;
      }
      this.sequence = decimal(data.eventSeq);
      this.cursor = data.cursor;
      return { state, event, ack: this.ack() };
    } catch (error) {
      this.dispose();
      throw error instanceof Error ? error : new Error("WORKSPACE_STREAM_INVALID");
    } finally { this.busy = false; }
  }

  expire(): void { try { this.check(); } catch (error) { this.dispose(); throw error; } }
  dispose(): void { this.disposed = true; for (const part of this.parts) part.fill(0); this.parts = []; this.received = 0; }
}
