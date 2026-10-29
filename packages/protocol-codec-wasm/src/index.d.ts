export function initializeProtocolCodec(moduleOrBytes: BufferSource | WebAssembly.Module): void;
export function isProtocolCodecInitialized(): boolean;
export function protocolValidateWire(kind: string, rawJson: string): void;
export function protocolValidateResponseFor(rawRequestJson: string, rawResponseJson: string): void;

/** 1 RPC request, 2 RPC response, 3 workspace, 4 terminal, 5 file watch. */
export type ProtocolMessageKind = 1 | 2 | 3 | 4 | 5;
export interface ProtocolCompletedMessage {
  kind: ProtocolMessageKind;
  /** Canonical decimal u64; never convert to Number. */
  id: string;
  /** Owned opaque bytes. Decode UTF-8/JSON only after completion. */
  bytes: Uint8Array;
}
/** Every input error permanently disposes the instance. */
export class ProtocolMessageEncoder {
  constructor();
  /** Takes a bounded copy into Rust; returns the exact decimal message ID. */
  begin(kind: ProtocolMessageKind, bytes: Uint8Array): string;
  /** One bounded frame at a time. Caller must apply backpressure. */
  nextFrame(): Uint8Array | null;
  dispose(): void;
}
/** Every input error permanently disposes the instance. */
export class ProtocolMessageAssembler {
  constructor();
  /** nowMs is a canonical decimal u64 from a monotonic caller clock. */
  push(frame: Uint8Array, nowMs: string): ProtocolCompletedMessage | null;
  /** Schedule even while waiting without incoming frames. */
  expire(nowMs: string): void;
  dispose(): void;
}
