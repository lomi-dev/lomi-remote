import { validateShape } from '@lomi/remote-contracts';
import type {
  ContractName,
  FileWatchFrameContract,
  RpcRequestContract,
  RpcResponseContract,
  WorkspaceStreamFrameContract,
} from '../generated/index.js';

export type RemoteV2MessageKind = 1 | 2 | 3 | 4 | 5;
export type RemoteV2StreamKind = 3 | 4 | 5;

export const REMOTE_V2_RPC_DEFAULT_TIMEOUT_MS = 10_000;
export const REMOTE_V2_RPC_MAX_TIMEOUT_MS = 60_000;
export const REMOTE_V2_RPC_MAX_PENDING = 32;
const REMOTE_V2_RPC_MAX_STREAM_LISTENERS = 32;
export const REMOTE_V2_RPC_MAX_LOGICAL_BYTES = 1024 * 1024;
export const REMOTE_V2_RPC_MAX_INBOX_MESSAGES = 256;
export const REMOTE_V2_RPC_MAX_INBOX_BYTES = 2 * REMOTE_V2_RPC_MAX_LOGICAL_BYTES;

/** A request is rejected before the transport starts framing it. */
export class RemoteV2PreSendError extends Error {
  readonly code = 'REMOTE_V2_PRE_SEND';

  constructor(message: string) {
    super(message);
    this.name = 'RemoteV2PreSendError';
  }
}

/** A request may have reached the peer, so its operation outcome is unknown. */
export class RemoteV2OutcomeUnknownError extends Error {
  readonly code = 'REMOTE_V2_OUTCOME_UNKNOWN';

  constructor(message = 'The channel ended before the request outcome was confirmed.') {
    super(message);
    this.name = 'RemoteV2OutcomeUnknownError';
  }
}

export interface RemoteV2RpcTransport {
  /**
   * Copies bytes before returning or awaiting. `onStart` runs immediately
   * before the first irreversible framing step. A false guard before that
   * point must reject with RemoteV2PreSendError; after it, failure is unknown.
   * Returning false from `onStart` refuses to begin framing.
   */
  send(
    message: { kind: RemoteV2MessageKind; bytes: Uint8Array },
    sendGuard?: () => boolean,
    onStart?: () => boolean | void,
  ): Promise<void>;
  close(reason?: Error): void;
}

export interface RemoteV2RpcCodec {
  validateRequest(rawJson: string): void | Promise<void>;
  validateResponseFor(requestJson: string, responseJson: string): void | Promise<void>;
  validateStream(kind: RemoteV2StreamKind, rawJson: string): void | Promise<void>;
}

export interface RemoteV2StreamEvent {
  kind: RemoteV2StreamKind;
  id: string;
  /** Each receiver owns an independent copy and must clear it when finished. */
  bytes: Uint8Array;
}

export interface RemoteV2RpcCoreOptions {
  transport: RemoteV2RpcTransport;
  codec: RemoteV2RpcCodec;
  onStream?(event: RemoteV2StreamEvent): void;
  randomUUID?(): string;
  setTimer?(callback: () => void, delayMs: number): ReturnType<typeof setTimeout>;
  clearTimer?(timer: ReturnType<typeof setTimeout>): void;
  now?(): number;
  maxPending?: number;
}

/** Allows platform wrappers to retain a method/params call API. The runtime
 * generated contract guard still validates the assembled RPC envelope. */
export type RemoteV2RpcCallInput =
  | RpcRequestContract['call']
  | {
      method: string;
      params: Record<string, unknown>;
    };

interface PendingRpc {
  requestJson: string;
  requestBytes: Uint8Array;
  deadlineAt: number;
  timer?: ReturnType<typeof setTimeout>;
  started: boolean;
  resolve(value: RpcResponseContract): void;
  reject(error: Error): void;
}

interface InboundMessage {
  kind: RemoteV2MessageKind;
  id: string;
  bytes: Uint8Array;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function errorMessage(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}

function timeoutMessageForRequest(requestJson: string): string {
  let method: unknown;
  try {
    const request = JSON.parse(requestJson) as { call?: { method?: unknown } };
    method = request.call?.method;
  } catch {
    return 'The request timed out after it may have been sent.';
  }
  switch (method) {
    case 'terminal.renew':
      return 'TERMINAL_RPC_RENEW_TIMED_OUT';
    case 'terminal.resize':
      return 'TERMINAL_RPC_RESIZE_TIMED_OUT';
    case 'terminal.input':
      return 'TERMINAL_RPC_INPUT_TIMED_OUT';
    case 'terminal.ack':
      return 'TERMINAL_RPC_ACK_TIMED_OUT';
    case 'terminal.claim':
      return 'TERMINAL_RPC_CLAIM_TIMED_OUT';
    default:
      return 'The request timed out after it may have been sent.';
  }
}

function streamContract(kind: RemoteV2StreamKind): ContractName {
  switch (kind) {
    case 3:
      return 'workspace-stream-frame';
    case 4:
      return 'terminal-stream-frame';
    case 5:
      return 'file-watch-frame';
  }
}

function decodeJson(bytes: Uint8Array): { raw: string; value: unknown } {
  const raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const encoded = new TextEncoder().encode(raw);
  const oversized = encoded.byteLength > REMOTE_V2_RPC_MAX_LOGICAL_BYTES;
  encoded.fill(0);
  if (oversized) {
    throw new Error('RESOURCE_EXHAUSTED');
  }
  return { raw, value: JSON.parse(raw) as unknown };
}

/** Shared RPC envelope, correlation, deadline, stream and bounded inbox logic. */
export class RemoteV2RpcCore {
  private readonly transport: RemoteV2RpcTransport;
  private readonly codec: RemoteV2RpcCodec;
  private readonly uuid: () => string;
  private readonly setTimer: NonNullable<RemoteV2RpcCoreOptions['setTimer']>;
  private readonly clearTimer: NonNullable<RemoteV2RpcCoreOptions['clearTimer']>;
  private readonly now: NonNullable<RemoteV2RpcCoreOptions['now']>;
  private readonly maxPending: number;
  private readonly onStream?: RemoteV2RpcCoreOptions['onStream'];
  private readonly pending = new Map<string, PendingRpc>();
  private readonly listeners = new Set<(event: RemoteV2StreamEvent) => void>();
  private readonly inbox: InboundMessage[] = [];
  private inboxMessages = 0;
  private inboxBytes = 0;
  private activeInbound?: Uint8Array;
  private processingInbox = false;
  private closedError?: Error;

  constructor(options: RemoteV2RpcCoreOptions) {
    this.transport = options.transport;
    this.codec = options.codec;
    this.uuid = options.randomUUID ?? (() => crypto.randomUUID());
    this.setTimer = options.setTimer ?? ((callback, delay) => setTimeout(callback, delay));
    this.clearTimer = options.clearTimer ?? ((timer) => clearTimeout(timer));
    this.now = options.now ?? (() => performance.now());
    this.maxPending = options.maxPending ?? REMOTE_V2_RPC_MAX_PENDING;
    this.onStream = options.onStream;
    if (!Number.isInteger(this.maxPending) || this.maxPending < 1 || this.maxPending > 256) {
      throw new Error('INVALID_LIMIT');
    }
  }

  call(
    call: RemoteV2RpcCallInput,
    timeoutMs = REMOTE_V2_RPC_DEFAULT_TIMEOUT_MS,
    sendGuard?: () => boolean,
  ): Promise<RpcResponseContract> {
    if (this.closedError) return Promise.reject(new RemoteV2PreSendError('RPC_PEER_CLOSED'));
    if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > REMOTE_V2_RPC_MAX_TIMEOUT_MS) {
      return Promise.reject(new RemoteV2PreSendError('INVALID_TIMEOUT'));
    }
    if (this.pending.size >= this.maxPending) {
      return Promise.reject(new RemoteV2PreSendError('REQUEST_QUEUE_FULL'));
    }

    let deadlineAt: number;
    try {
      const startedAt = this.now();
      deadlineAt = startedAt + timeoutMs;
      if (!Number.isFinite(startedAt) || startedAt < 0 || !Number.isFinite(deadlineAt)) {
        throw new Error('INVALID_MONOTONIC_CLOCK');
      }
    } catch {
      return Promise.reject(new RemoteV2PreSendError('INVALID_MONOTONIC_CLOCK'));
    }

    let requestId: string;
    let requestJson: string;
    let requestBytes: Uint8Array;
    try {
      requestId = this.uuid();
      if (!UUID.test(requestId) || this.pending.has(requestId)) throw new Error('INVALID_REQUEST_ID');
      const candidate: unknown = { call, requestId, timeoutMs, type: 'request', v: 2 };
      if (!validateShape('rpc-request', candidate)) throw new Error('INVALID_RPC_REQUEST');
      const request: RpcRequestContract = candidate;
      requestJson = JSON.stringify(request);
      requestBytes = new TextEncoder().encode(requestJson);
      if (requestBytes.byteLength > REMOTE_V2_RPC_MAX_LOGICAL_BYTES) {
        requestBytes.fill(0);
        throw new Error('RESOURCE_EXHAUSTED');
      }
    } catch (error) {
      return Promise.reject(new RemoteV2PreSendError(errorMessage(error, 'INVALID_RPC_REQUEST')));
    }

    return new Promise((resolve, reject) => {
      const pending: PendingRpc = {
        requestJson,
        requestBytes,
        deadlineAt,
        started: false,
        resolve,
        reject,
      };
      this.pending.set(requestId, pending);
      try {
        this.armDeadlineTimer(requestId, pending);
      } catch {
        this.pending.delete(requestId);
        this.clearPending(pending);
        reject(new RemoteV2PreSendError('RPC_TIMER_UNAVAILABLE'));
        return;
      }
      void this.sendRequest(requestId, pending, sendGuard);
    });
  }

  sendWorkspaceFrame(frame: WorkspaceStreamFrameContract): Promise<void> {
    return this.sendStreamFrame(3, 'workspace-stream-frame', frame);
  }

  sendFileWatchFrame(frame: FileWatchFrameContract): Promise<void> {
    return this.sendStreamFrame(5, 'file-watch-frame', frame);
  }

  receive(message: { kind: number; id: string; bytes: Uint8Array }): void {
    if (this.closedError) return;
    if (
      !message ||
      ![2, 3, 4, 5].includes(message.kind) ||
      !(message.bytes instanceof Uint8Array) ||
      message.bytes.byteLength < 1 ||
      message.bytes.byteLength > REMOTE_V2_RPC_MAX_LOGICAL_BYTES ||
      typeof message.id !== 'string'
    ) {
      this.fail(new Error('INVALID_PROTOCOL_MESSAGE'));
      return;
    }
    if (
      this.inboxMessages >= REMOTE_V2_RPC_MAX_INBOX_MESSAGES ||
      this.inboxBytes + message.bytes.byteLength > REMOTE_V2_RPC_MAX_INBOX_BYTES
    ) {
      this.fail(new Error('RELAY_QUEUE_LIMIT'));
      return;
    }
    const bytes = new Uint8Array(message.bytes);
    this.inbox.push({ kind: message.kind as RemoteV2MessageKind, id: message.id, bytes });
    this.inboxMessages += 1;
    this.inboxBytes += bytes.byteLength;
    void this.processInbox();
  }

  subscribe(listener: (event: RemoteV2StreamEvent) => void): () => void {
    if (this.closedError) throw this.closedError;
    if (!this.listeners.has(listener) && this.listeners.size >= REMOTE_V2_RPC_MAX_STREAM_LISTENERS) {
      throw new RemoteV2PreSendError('STREAM_LISTENER_LIMIT');
    }
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  close(reason = new Error('RPC_PEER_CLOSED'), closeTransport = true): void {
    this.shutdown(reason, closeTransport);
  }

  private async sendRequest(requestId: string, pending: PendingRpc, sendGuard?: () => boolean): Promise<void> {
    try {
      await this.codec.validateRequest(pending.requestJson);
      if (!this.pendingBeforeDeadline(requestId, pending)) return;
      if (!this.guardAllows(sendGuard)) throw new RemoteV2PreSendError('SEND_CANCELLED');
      await this.transport.send(
        { kind: 1, bytes: pending.requestBytes },
        () => this.pendingBeforeDeadline(requestId, pending) && !this.closedError && this.guardAllows(sendGuard),
        () => {
          if (!this.pendingBeforeDeadline(requestId, pending) || !this.guardAllows(sendGuard)) return false;
          pending.started = true;
          return true;
        },
      );
      this.pendingBeforeDeadline(requestId, pending);
    } catch (error) {
      if (this.pending.get(requestId) !== pending) return;
      if (!this.isBeforeDeadline(pending)) {
        this.expirePending(requestId, pending);
        return;
      }
      this.pending.delete(requestId);
      this.clearPending(pending);
      const failure =
        error instanceof RemoteV2OutcomeUnknownError || pending.started
          ? new RemoteV2OutcomeUnknownError(errorMessage(error, 'RPC_SEND_FAILED'))
          : new RemoteV2PreSendError(errorMessage(error, 'RPC_SEND_REJECTED'));
      pending.reject(failure);
    }
  }

  private async sendStreamFrame(
    kind: 3 | 5,
    contract: 'workspace-stream-frame' | 'file-watch-frame',
    frame: WorkspaceStreamFrameContract | FileWatchFrameContract,
  ): Promise<void> {
    if (this.closedError) throw new RemoteV2OutcomeUnknownError();
    if (!validateShape(contract, frame) || frame.type !== 'ack') {
      throw new RemoteV2PreSendError('INVALID_STREAM_FRAME');
    }
    let bytes: Uint8Array;
    let encoded: Uint8Array | undefined;
    try {
      const raw = JSON.stringify(frame);
      encoded = new TextEncoder().encode(raw);
      if (encoded.byteLength > REMOTE_V2_RPC_MAX_LOGICAL_BYTES) {
        encoded.fill(0);
        encoded = undefined;
        throw new Error('RESOURCE_EXHAUSTED');
      }
      await this.codec.validateStream(kind, raw);
      if (this.closedError) throw new RemoteV2PreSendError('RPC_PEER_CLOSED');
      if (!encoded) throw new Error('INVALID_STREAM_FRAME');
      bytes = encoded;
      encoded = undefined;
    } catch (error) {
      encoded?.fill(0);
      throw new RemoteV2PreSendError(errorMessage(error, 'INVALID_STREAM_FRAME'));
    }
    let started = false;
    try {
      await this.transport.send({ kind, bytes }, undefined, () => {
        started = true;
      });
    } catch (error) {
      throw error instanceof RemoteV2OutcomeUnknownError || started
        ? new RemoteV2OutcomeUnknownError(errorMessage(error, 'STREAM_SEND_FAILED'))
        : new RemoteV2PreSendError(errorMessage(error, 'STREAM_SEND_REJECTED'));
    } finally {
      bytes.fill(0);
    }
  }

  private async processInbox(): Promise<void> {
    if (this.processingInbox || this.closedError) return;
    this.processingInbox = true;
    try {
      while (this.inbox.length > 0 && !this.closedError) {
        const message = this.inbox.shift();
        if (!message) continue;
        this.activeInbound = message.bytes;
        try {
          const { raw, value } = decodeJson(message.bytes);
          message.bytes.fill(0);
          if (message.kind === 2) await this.processResponse(value, raw);
          else await this.processStream(message, raw, value);
        } finally {
          message.bytes.fill(0);
          if (this.activeInbound === message.bytes) {
            this.activeInbound = undefined;
            this.inboxMessages -= 1;
            this.inboxBytes -= message.bytes.byteLength;
          }
        }
      }
    } catch (error) {
      this.fail(error instanceof Error ? error : new Error('INVALID_REMOTE_MESSAGE'));
    } finally {
      this.processingInbox = false;
      if (this.inbox.length > 0 && !this.closedError) void this.processInbox();
    }
  }

  private async processResponse(value: unknown, raw: string): Promise<void> {
    if (!validateShape('rpc-response', value)) throw new Error('INVALID_RPC_RESPONSE');
    const requestId = value.requestId;
    const pending = this.pending.get(requestId);
    if (!pending) throw new Error('UNMATCHED_RPC_RESPONSE');
    if (!this.pendingBeforeDeadline(requestId, pending)) return;
    try {
      await this.codec.validateResponseFor(pending.requestJson, raw);
    } catch (error) {
      if (!this.pendingBeforeDeadline(requestId, pending)) return;
      throw error;
    }
    if (!this.pendingBeforeDeadline(requestId, pending)) return;
    this.pending.delete(requestId);
    this.clearPending(pending);
    pending.resolve(value);
  }

  private async processStream(message: InboundMessage, raw: string, value: unknown): Promise<void> {
    const kind = message.kind as RemoteV2StreamKind;
    if (!validateShape(streamContract(kind), value)) throw new Error('INVALID_STREAM_FRAME');
    await this.codec.validateStream(kind, raw);
    if (this.closedError) return;
    const subscribers = [...this.listeners];
    const receiverCount = subscribers.length + (this.onStream ? 1 : 0);
    if (receiverCount === 0) return;
    const serialized = new TextEncoder().encode(raw);
    if (serialized.byteLength > REMOTE_V2_RPC_MAX_LOGICAL_BYTES) {
      serialized.fill(0);
      throw new Error('RESOURCE_EXHAUSTED');
    }
    const events: RemoteV2StreamEvent[] = [];
    try {
      for (let index = 0; index < receiverCount; index += 1) {
        events.push({ kind, id: message.id, bytes: new Uint8Array(serialized) });
      }
    } catch (error) {
      for (const event of events) event.bytes.fill(0);
      throw error;
    } finally {
      serialized.fill(0);
    }

    let eventIndex = 0;
    const wipeUndelivered = (): void => {
      for (; eventIndex < events.length; eventIndex += 1) events[eventIndex]!.bytes.fill(0);
    };
    const deliver = (listener: (event: RemoteV2StreamEvent) => void): void => {
      const event = events[eventIndex]!;
      eventIndex += 1;
      try {
        listener(event);
      } catch (error) {
        event.bytes.fill(0);
        wipeUndelivered();
        throw error;
      }
      if (this.closedError) wipeUndelivered();
    };

    try {
      if (this.onStream) deliver(this.onStream);
      for (const listener of subscribers) {
        if (this.closedError) {
          wipeUndelivered();
          return;
        }
        if (!this.listeners.has(listener)) {
          events[eventIndex]!.bytes.fill(0);
          eventIndex += 1;
          continue;
        }
        deliver(listener);
      }
    } catch (error) {
      throw error;
    }
  }

  private guardAllows(sendGuard?: () => boolean): boolean {
    if (!sendGuard) return true;
    try {
      return sendGuard();
    } catch {
      return false;
    }
  }

  private clearPending(pending: PendingRpc): void {
    if (pending.timer !== undefined) this.clearTimer(pending.timer);
    pending.timer = undefined;
    pending.requestBytes.fill(0);
  }

  private isBeforeDeadline(pending: PendingRpc): boolean {
    try {
      const now = this.now();
      return Number.isFinite(now) && now < pending.deadlineAt;
    } catch {
      return false;
    }
  }

  private pendingBeforeDeadline(requestId: string, pending: PendingRpc): boolean {
    if (this.closedError || this.pending.get(requestId) !== pending) return false;
    if (this.isBeforeDeadline(pending)) return true;
    this.expirePending(requestId, pending);
    return false;
  }

  private armDeadlineTimer(requestId: string, pending: PendingRpc): void {
    let remaining = 0;
    try {
      remaining = Math.max(0, pending.deadlineAt - this.now());
    } catch {
      remaining = 0;
    }
    pending.timer = this.setTimer(() => {
      pending.timer = undefined;
      if (this.pending.get(requestId) !== pending) return;
      if (this.isBeforeDeadline(pending)) {
        this.armDeadlineTimer(requestId, pending);
        return;
      }
      this.expirePending(requestId, pending);
    }, remaining);
  }

  private expirePending(requestId: string, pending: PendingRpc): void {
    if (this.pending.get(requestId) !== pending) return;
    this.pending.delete(requestId);
    this.clearPending(pending);
    pending.reject(
      pending.started
        ? new RemoteV2OutcomeUnknownError(timeoutMessageForRequest(pending.requestJson))
        : new RemoteV2PreSendError('RPC_DEADLINE_BEFORE_SEND'),
    );
  }

  private fail(error: Error): void {
    this.shutdown(error, true);
  }

  private shutdown(reason: Error, closeTransport: boolean): void {
    if (this.closedError) return;
    this.closedError = reason;
    for (const pending of this.pending.values()) {
      this.clearPending(pending);
      pending.reject(
        pending.started
          ? new RemoteV2OutcomeUnknownError(reason.message)
          : new RemoteV2PreSendError('RPC_CLOSED_BEFORE_SEND'),
      );
    }
    this.pending.clear();
    for (const message of this.inbox.splice(0)) message.bytes.fill(0);
    this.activeInbound?.fill(0);
    this.activeInbound = undefined;
    this.inboxMessages = 0;
    this.inboxBytes = 0;
    this.listeners.clear();
    if (closeTransport) {
      try {
        this.transport.close(reason);
      } catch {
        /* already closed */
      }
    }
  }
}
