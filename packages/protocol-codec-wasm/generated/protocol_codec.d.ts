/* tslint:disable */
/* eslint-disable */

export class BrowserCompletedMessage {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    id(): string;
    kind(): number;
    /**
     * Transfer the owned payload once; repeated access never copies it again.
     */
    takeBytes(): Uint8Array;
}

export class BrowserMessageAssembler {
    free(): void;
    [Symbol.dispose](): void;
    dispose(): void;
    expire(now_ms: string): void;
    constructor();
    push(frame: Uint8Array, now_ms: string): BrowserCompletedMessage | undefined;
}

export class BrowserMessageEncoder {
    free(): void;
    [Symbol.dispose](): void;
    begin(kind: number, bytes: Uint8Array): string;
    dispose(): void;
    constructor();
    nextFrame(): Uint8Array | undefined;
}

export function protocol_validate_response_for(request_json: string, response_json: string): void;

export function protocol_validate_wire(kind: string, json: string): void;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_browsercompletedmessage_free: (a: number, b: number) => void;
    readonly __wbg_browsermessageassembler_free: (a: number, b: number) => void;
    readonly __wbg_browsermessageencoder_free: (a: number, b: number) => void;
    readonly browsercompletedmessage_id: (a: number) => [number, number];
    readonly browsercompletedmessage_kind: (a: number) => number;
    readonly browsercompletedmessage_takeBytes: (a: number) => [number, number, number, number];
    readonly browsermessageassembler_dispose: (a: number) => void;
    readonly browsermessageassembler_expire: (a: number, b: number, c: number) => [number, number];
    readonly browsermessageassembler_new: () => number;
    readonly browsermessageassembler_push: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly browsermessageencoder_begin: (a: number, b: number, c: number, d: number) => [number, number, number, number];
    readonly browsermessageencoder_dispose: (a: number) => void;
    readonly browsermessageencoder_new: () => number;
    readonly browsermessageencoder_nextFrame: (a: number) => [number, number, number, number];
    readonly protocol_validate_response_for: (a: number, b: number, c: number, d: number) => [number, number];
    readonly protocol_validate_wire: (a: number, b: number, c: number, d: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
