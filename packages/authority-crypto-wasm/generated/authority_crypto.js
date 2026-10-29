/* @ts-self-types="./authority_crypto.d.ts" */

export class BrowserChannel {
    static __wrap(ptr) {
        const obj = Object.create(BrowserChannel.prototype);
        obj.__wbg_ptr = ptr;
        BrowserChannelFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserChannelFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browserchannel_free(ptr, 0);
    }
    dispose() {
        wasm.browserchannel_dispose(this.__wbg_ptr);
    }
    /**
     * @param {Uint8Array} routing
     * @param {string} frame_json
     * @returns {Uint8Array}
     */
    open(routing, frame_json) {
        const ptr0 = passArray8ToWasm0(routing, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(frame_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.browserchannel_open(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * @param {Uint8Array} routing
     * @param {Uint8Array} frame
     * @returns {Uint8Array}
     */
    open_binary(routing, frame) {
        const ptr0 = passArray8ToWasm0(routing, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(frame, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.browserchannel_open_binary(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * @param {Uint8Array} routing
     * @param {Uint8Array} plaintext
     * @returns {string}
     */
    seal(routing, plaintext) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passArray8ToWasm0(routing, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.browserchannel_seal(this.__wbg_ptr, ptr0, len0, ptr1, len1);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
    /**
     * @param {Uint8Array} routing
     * @param {Uint8Array} plaintext
     * @returns {Uint8Array}
     */
    seal_binary(routing, plaintext) {
        const ptr0 = passArray8ToWasm0(routing, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(plaintext, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.browserchannel_seal_binary(this.__wbg_ptr, ptr0, len0, ptr1, len1);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v3 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v3;
    }
    /**
     * @returns {Uint8Array}
     */
    transcript_hash() {
        const ret = wasm.browserchannel_transcript_hash(this.__wbg_ptr);
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) BrowserChannel.prototype[Symbol.dispose] = BrowserChannel.prototype.free;

export class BrowserHandshake {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserHandshakeFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browserhandshake_free(ptr, 0);
    }
    dispose() {
        wasm.browserhandshake_dispose(this.__wbg_ptr);
    }
    /**
     * @returns {BrowserChannel}
     */
    finish() {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.browserhandshake_finish(ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BrowserChannel.__wrap(ret[0]);
    }
    /**
     * @param {boolean} initiator
     * @param {BrowserIdentity} identity
     * @param {string} context_json
     * @param {string} peer_json
     * @param {Uint8Array} pinned_peer
     */
    constructor(initiator, identity, context_json, peer_json, pinned_peer) {
        _assertClass(identity, BrowserIdentity);
        const ptr0 = passStringToWasm0(context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(peer_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(pinned_peer, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.browserhandshake_new(initiator, identity.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        BrowserHandshakeFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {Uint8Array} message
     */
    read(message) {
        const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browserhandshake_read(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    write() {
        const ret = wasm.browserhandshake_write(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) BrowserHandshake.prototype[Symbol.dispose] = BrowserHandshake.prototype.free;

export class BrowserHandshakeV3 {
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserHandshakeV3Finalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browserhandshakev3_free(ptr, 0);
    }
    dispose() {
        wasm.browserhandshakev3_dispose(this.__wbg_ptr);
    }
    /**
     * @returns {BrowserChannel}
     */
    finish() {
        const ptr = this.__destroy_into_raw();
        const ret = wasm.browserhandshakev3_finish(ptr);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BrowserChannel.__wrap(ret[0]);
    }
    /**
     * Expected context, current membership, endpoint pins and now are independent
     * trusted inputs supplied by the caller's authority adapter. Never derive
     * them from the signed JSON received over the channel.
     * @param {boolean} initiator
     * @param {BrowserIdentity} identity
     * @param {string} signed_json
     * @param {string} expected_json
     * @param {string} authority_json
     * @param {Uint8Array} host_pin
     * @param {Uint8Array} consumer_pin
     * @param {bigint} now
     */
    constructor(initiator, identity, signed_json, expected_json, authority_json, host_pin, consumer_pin, now) {
        _assertClass(identity, BrowserIdentity);
        const ptr0 = passStringToWasm0(signed_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(expected_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(authority_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(host_pin, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(consumer_pin, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.browserhandshakev3_new(initiator, identity.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, now);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        BrowserHandshakeV3Finalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {Uint8Array} message
     */
    read(message) {
        const ptr0 = passArray8ToWasm0(message, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.browserhandshakev3_read(this.__wbg_ptr, ptr0, len0);
        if (ret[1]) {
            throw takeFromExternrefTable0(ret[0]);
        }
    }
    /**
     * @returns {Uint8Array}
     */
    write() {
        const ret = wasm.browserhandshakev3_write(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
}
if (Symbol.dispose) BrowserHandshakeV3.prototype[Symbol.dispose] = BrowserHandshakeV3.prototype.free;

/**
 * Rust-held identity with a one-time seed-blob bridge for immediate WebCrypto
 * encryption. JavaScript copies remain outside Rust zeroization guarantees.
 */
export class BrowserIdentity {
    static __wrap(ptr) {
        const obj = Object.create(BrowserIdentity.prototype);
        obj.__wbg_ptr = ptr;
        BrowserIdentityFinalization.register(obj, obj.__wbg_ptr, obj);
        return obj;
    }
    __destroy_into_raw() {
        const ptr = this.__wbg_ptr;
        this.__wbg_ptr = 0;
        BrowserIdentityFinalization.unregister(this);
        return ptr;
    }
    free() {
        const ptr = this.__destroy_into_raw();
        wasm.__wbg_browseridentity_free(ptr, 0);
    }
    dispose() {
        wasm.browseridentity_dispose(this.__wbg_ptr);
    }
    /**
     * @returns {Uint8Array}
     */
    fingerprint() {
        const ret = wasm.browseridentity_fingerprint(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * @param {Uint8Array} account_id
     * @param {Uint8Array} subject_id
     * @param {boolean} host
     * @param {number} key_version
     */
    constructor(account_id, subject_id, host, key_version) {
        const ptr0 = passArray8ToWasm0(account_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(subject_id, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ret = wasm.browseridentity_new(ptr0, len0, ptr1, len1, host, key_version);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        this.__wbg_ptr = ret[0];
        BrowserIdentityFinalization.register(this, this.__wbg_ptr, this);
        return this;
    }
    /**
     * @param {string} envelope_json
     * @param {string} sender_json
     * @param {Uint8Array} pinned_sender
     * @param {string} policy_json
     * @param {bigint} now
     * @returns {Uint8Array}
     */
    open_mailbox(envelope_json, sender_json, pinned_sender, policy_json, now) {
        const ptr0 = passStringToWasm0(envelope_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(sender_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(pinned_sender, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(policy_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.browseridentity_open_mailbox(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, now);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v5 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v5;
    }
    /**
     * @returns {string}
     */
    public_bundle() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.browseridentity_public_bundle(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Bounded public EnrollmentProof carrier; contains no secret key material.
     * @returns {string}
     */
    public_identity_wire() {
        let deferred2_0;
        let deferred2_1;
        try {
            const ret = wasm.browseridentity_public_identity_wire(this.__wbg_ptr);
            var ptr1 = ret[0];
            var len1 = ret[1];
            if (ret[3]) {
                ptr1 = 0; len1 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred2_0 = ptr1;
            deferred2_1 = len1;
            return getStringFromWasm0(ptr1, len1);
        } finally {
            wasm.__wbindgen_free(deferred2_0, deferred2_1, 1);
        }
    }
    /**
     * Restore only from a browser-decrypted seed blob and an exact public
     * bundle previously persisted beside it. The requested scope is checked
     * in Rust before the keys are reconstructed.
     * @param {Uint8Array} account_id
     * @param {Uint8Array} subject_id
     * @param {Uint8Array} seed_blob
     * @param {string} expected_bundle_json
     * @returns {BrowserIdentity}
     */
    static restore(account_id, subject_id, seed_blob, expected_bundle_json) {
        const ptr0 = passArray8ToWasm0(account_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(subject_id, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(seed_blob, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(expected_bundle_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.browseridentity_restore(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        if (ret[2]) {
            throw takeFromExternrefTable0(ret[1]);
        }
        return BrowserIdentity.__wrap(ret[0]);
    }
    /**
     * @param {string} recipient_json
     * @param {Uint8Array} pinned_recipient
     * @param {string} policy_json
     * @param {bigint} now
     * @param {bigint} expires_at
     * @param {Uint8Array} payload
     * @returns {string}
     */
    seal_mailbox(recipient_json, pinned_recipient, policy_json, now, expires_at, payload) {
        let deferred6_0;
        let deferred6_1;
        try {
            const ptr0 = passStringToWasm0(recipient_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passArray8ToWasm0(pinned_recipient, wasm.__wbindgen_malloc);
            const len1 = WASM_VECTOR_LEN;
            const ptr2 = passStringToWasm0(policy_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len2 = WASM_VECTOR_LEN;
            const ptr3 = passArray8ToWasm0(payload, wasm.__wbindgen_malloc);
            const len3 = WASM_VECTOR_LEN;
            const ret = wasm.browseridentity_seal_mailbox(this.__wbg_ptr, ptr0, len0, ptr1, len1, ptr2, len2, now, expires_at, ptr3, len3);
            var ptr5 = ret[0];
            var len5 = ret[1];
            if (ret[3]) {
                ptr5 = 0; len5 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred6_0 = ptr5;
            deferred6_1 = len5;
            return getStringFromWasm0(ptr5, len5);
        } finally {
            wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
        }
    }
    /**
     * Returns the seed blob once so the caller can encrypt it with WebCrypto.
     * Callers must zero the returned JavaScript buffer immediately.
     * @returns {Uint8Array}
     */
    seed_blob_for_encryption() {
        const ret = wasm.browseridentity_seed_blob_for_encryption(this.__wbg_ptr);
        if (ret[3]) {
            throw takeFromExternrefTable0(ret[2]);
        }
        var v1 = getArrayU8FromWasm0(ret[0], ret[1]).slice();
        wasm.__wbindgen_free(ret[0], ret[1] * 1, 1);
        return v1;
    }
    /**
     * Sign only an exact native-decoded canonical window challenge. Identity
     * binding and disposal checks remain in the native signer.
     * @param {Uint8Array} canonical_cbor
     * @returns {string}
     */
    sign_consumer_window_proof(canonical_cbor) {
        let deferred3_0;
        let deferred3_1;
        try {
            const ptr0 = passArray8ToWasm0(canonical_cbor, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ret = wasm.browseridentity_sign_consumer_window_proof(this.__wbg_ptr, ptr0, len0);
            var ptr2 = ret[0];
            var len2 = ret[1];
            if (ret[3]) {
                ptr2 = 0; len2 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred3_0 = ptr2;
            deferred3_1 = len2;
            return getStringFromWasm0(ptr2, len2);
        } finally {
            wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
        }
    }
    /**
     * @param {Uint8Array} canonical_cbor
     * @param {string} expected_json
     * @param {bigint} now
     * @returns {string}
     */
    sign_consumer_window_proof_bound(canonical_cbor, expected_json, now) {
        let deferred4_0;
        let deferred4_1;
        try {
            const ptr0 = passArray8ToWasm0(canonical_cbor, wasm.__wbindgen_malloc);
            const len0 = WASM_VECTOR_LEN;
            const ptr1 = passStringToWasm0(expected_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            const ret = wasm.browseridentity_sign_consumer_window_proof_bound(this.__wbg_ptr, ptr0, len0, ptr1, len1, now);
            var ptr3 = ret[0];
            var len3 = ret[1];
            if (ret[3]) {
                ptr3 = 0; len3 = 0;
                throw takeFromExternrefTable0(ret[2]);
            }
            deferred4_0 = ptr3;
            deferred4_1 = len3;
            return getStringFromWasm0(ptr3, len3);
        } finally {
            wasm.__wbindgen_free(deferred4_0, deferred4_1, 1);
        }
    }
}
if (Symbol.dispose) BrowserIdentity.prototype[Symbol.dispose] = BrowserIdentity.prototype.free;

/**
 * @returns {boolean}
 */
export function live_production_qualified() {
    const ret = wasm.live_production_qualified();
    return ret !== 0;
}

/**
 * @param {Uint8Array} account_id
 * @param {Uint8Array} host_id
 * @param {Uint8Array} device_id
 * @param {Uint8Array} host_fingerprint
 * @param {Uint8Array} device_fingerprint
 * @param {Uint8Array} pairing_nonce
 * @returns {string}
 */
export function pairing_fingerprint(account_id, host_id, device_id, host_fingerprint, device_fingerprint, pairing_nonce) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passArray8ToWasm0(account_id, wasm.__wbindgen_malloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(host_id, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(device_id, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(host_fingerprint, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(device_fingerprint, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(pairing_nonce, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.pairing_fingerprint(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

/**
 * Context is assembled from a saved server row; grant is the stored approval.
 * @param {string} trusted_context_json
 * @param {string} stored_grant_wire_json
 * @param {string} host_wire_json
 * @param {string} consumer_wire_json
 * @param {Uint8Array} host_pin
 * @param {Uint8Array} consumer_pin
 * @param {string} authority_json
 * @param {bigint} now
 * @returns {string}
 */
export function prepare_channel_context_v3(trusted_context_json, stored_grant_wire_json, host_wire_json, consumer_wire_json, host_pin, consumer_pin, authority_json, now) {
    let deferred9_0;
    let deferred9_1;
    try {
        const ptr0 = passStringToWasm0(trusted_context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(stored_grant_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(host_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(consumer_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(host_pin, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(consumer_pin, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(authority_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ret = wasm.prepare_channel_context_v3(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, now);
        var ptr8 = ret[0];
        var len8 = ret[1];
        if (ret[3]) {
            ptr8 = 0; len8 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred9_0 = ptr8;
        deferred9_1 = len8;
        return getStringFromWasm0(ptr8, len8);
    } finally {
        wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
    }
}

/**
 * Context is independently retained authority state. Returns JSON
 * {challenge, canonicalCbor}, with canonicalCbor encoded as lowercase hex.
 * @param {string} wire_json
 * @param {Uint8Array} approved_account_id
 * @param {string} context_json
 * @returns {string}
 */
export function prepare_consumer_window_challenge(wire_json, approved_account_id, context_json) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(approved_account_id, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.prepare_consumer_window_challenge(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Trusted grant is assembled from independently retained authority rows.
 * @param {string} trusted_grant_json
 * @param {string} host_wire_json
 * @param {string} consumer_wire_json
 * @param {Uint8Array} approved_account
 * @param {Uint8Array} host_pin
 * @param {Uint8Array} consumer_pin
 * @returns {string}
 */
export function prepare_grant_proposal_v3(trusted_grant_json, host_wire_json, consumer_wire_json, approved_account, host_pin, consumer_pin) {
    let deferred8_0;
    let deferred8_1;
    try {
        const ptr0 = passStringToWasm0(trusted_grant_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(host_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(consumer_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(approved_account, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(host_pin, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(consumer_pin, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ret = wasm.prepare_grant_proposal_v3(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5);
        var ptr7 = ret[0];
        var len7 = ret[1];
        if (ret[3]) {
            ptr7 = 0; len7 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred8_0 = ptr7;
        deferred8_1 = len7;
        return getStringFromWasm0(ptr7, len7);
    } finally {
        wasm.__wbindgen_free(deferred8_0, deferred8_1, 1);
    }
}

/**
 * Derive host claims from the retained init record and authenticated approval.
 * Context IDs and nonce must come from independently stored authority state.
 * @param {string} committed_json
 * @param {Uint8Array} initial_commitment
 * @param {Uint8Array} approved_account_id
 * @param {string} context_json
 * @returns {string}
 */
export function prepare_host_enrollment_challenge(committed_json, initial_commitment, approved_account_id, context_json) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(committed_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(initial_commitment, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(approved_account_id, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.prepare_host_enrollment_challenge(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}

/**
 * @returns {boolean}
 */
export function production_qualified() {
    const ret = wasm.production_qualified();
    return ret !== 0;
}

/**
 * @returns {boolean}
 */
export function remote_v3_production_qualified() {
    const ret = wasm.remote_v3_production_qualified();
    return ret !== 0;
}

/**
 * The approval must first be verified against trusted host and grant state.
 * @param {string} context_json
 * @param {string} approval_json
 */
export function validate_channel_approval(context_json, approval_json) {
    const ptr0 = passStringToWasm0(context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(approval_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.validate_channel_approval(ptr0, len0, ptr1, len1);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * Cross-runtime diagnostic over already verified admission, not a signing API.
 * @param {string} signed_json
 * @param {string} expected_json
 * @param {string} authority_json
 * @param {Uint8Array} host_pin
 * @param {Uint8Array} consumer_pin
 * @param {bigint} now
 * @returns {string}
 */
export function verified_v3_artifacts(signed_json, expected_json, authority_json, host_pin, consumer_pin, now) {
    let deferred7_0;
    let deferred7_1;
    try {
        const ptr0 = passStringToWasm0(signed_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(expected_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(authority_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(host_pin, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(consumer_pin, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ret = wasm.verified_v3_artifacts(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, now);
        var ptr6 = ret[0];
        var len6 = ret[1];
        if (ret[3]) {
            ptr6 = 0; len6 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred7_0 = ptr6;
        deferred7_1 = len6;
        return getStringFromWasm0(ptr6, len6);
    } finally {
        wasm.__wbindgen_free(deferred7_0, deferred7_1, 1);
    }
}

/**
 * Expected CBOR, stored approval, pins and current authority are independent state.
 * Result is the verified AdmissionInput JSON accepted by BrowserHandshakeV3.
 * @param {string} submitted_wire_json
 * @param {string} expected_cbor_hex
 * @param {string} stored_grant_wire_json
 * @param {string} host_wire_json
 * @param {string} consumer_wire_json
 * @param {Uint8Array} host_pin
 * @param {Uint8Array} consumer_pin
 * @param {string} authority_json
 * @param {bigint} now
 * @returns {string}
 */
export function verify_channel_admission_v3(submitted_wire_json, expected_cbor_hex, stored_grant_wire_json, host_wire_json, consumer_wire_json, host_pin, consumer_pin, authority_json, now) {
    let deferred10_0;
    let deferred10_1;
    try {
        const ptr0 = passStringToWasm0(submitted_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(expected_cbor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(stored_grant_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(host_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passStringToWasm0(consumer_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(host_pin, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passArray8ToWasm0(consumer_pin, wasm.__wbindgen_malloc);
        const len6 = WASM_VECTOR_LEN;
        const ptr7 = passStringToWasm0(authority_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len7 = WASM_VECTOR_LEN;
        const ret = wasm.verify_channel_admission_v3(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, ptr7, len7, now);
        var ptr9 = ret[0];
        var len9 = ret[1];
        if (ret[3]) {
            ptr9 = 0; len9 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred10_0 = ptr9;
        deferred10_1 = len9;
        return getStringFromWasm0(ptr9, len9);
    } finally {
        wasm.__wbindgen_free(deferred10_0, deferred10_1, 1);
    }
}

/**
 * Returns JSON {identity: SignedBundle, fingerprint: number[32]}. The account
 * and window ID must come from authenticated authority state.
 * @param {string} wire_json
 * @param {Uint8Array} approved_account_id
 * @param {Uint8Array} window_id
 * @returns {string}
 */
export function verify_consumer_window_identity(wire_json, approved_account_id, window_id) {
    let deferred5_0;
    let deferred5_1;
    try {
        const ptr0 = passStringToWasm0(wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passArray8ToWasm0(approved_account_id, wasm.__wbindgen_malloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(window_id, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ret = wasm.verify_consumer_window_identity(ptr0, len0, ptr1, len1, ptr2, len2);
        var ptr4 = ret[0];
        var len4 = ret[1];
        if (ret[3]) {
            ptr4 = 0; len4 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred5_0 = ptr4;
        deferred5_1 = len4;
        return getStringFromWasm0(ptr4, len4);
    } finally {
        wasm.__wbindgen_free(deferred5_0, deferred5_1, 1);
    }
}

/**
 * Expected challenge and approved account are independently retained server
 * state. The authority also owns atomic single use of the operation and nonce.
 * @param {string} proof_json
 * @param {string} expected_json
 * @param {string} identity_wire_json
 * @param {Uint8Array} approved_account_id
 * @param {bigint} now
 */
export function verify_consumer_window_proof(proof_json, expected_json, identity_wire_json, approved_account_id, now) {
    const ptr0 = passStringToWasm0(proof_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(expected_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(identity_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(approved_account_id, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.verify_consumer_window_proof(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, now);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * Maximum CBOR, endpoint pins and current authority are independent stored state.
 * @param {string} submitted_wire_json
 * @param {string} maximum_cbor_hex
 * @param {string} host_wire_json
 * @param {string} consumer_wire_json
 * @param {Uint8Array} host_pin
 * @param {Uint8Array} consumer_pin
 * @param {string} authority_json
 * @param {bigint} now
 * @returns {string}
 */
export function verify_grant_proposal_v3(submitted_wire_json, maximum_cbor_hex, host_wire_json, consumer_wire_json, host_pin, consumer_pin, authority_json, now) {
    let deferred9_0;
    let deferred9_1;
    try {
        const ptr0 = passStringToWasm0(submitted_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(maximum_cbor_hex, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passStringToWasm0(host_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passStringToWasm0(consumer_wire_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len3 = WASM_VECTOR_LEN;
        const ptr4 = passArray8ToWasm0(host_pin, wasm.__wbindgen_malloc);
        const len4 = WASM_VECTOR_LEN;
        const ptr5 = passArray8ToWasm0(consumer_pin, wasm.__wbindgen_malloc);
        const len5 = WASM_VECTOR_LEN;
        const ptr6 = passStringToWasm0(authority_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len6 = WASM_VECTOR_LEN;
        const ret = wasm.verify_grant_proposal_v3(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, ptr5, len5, ptr6, len6, now);
        var ptr8 = ret[0];
        var len8 = ret[1];
        if (ret[3]) {
            ptr8 = 0; len8 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred9_0 = ptr8;
        deferred9_1 = len8;
        return getStringFromWasm0(ptr8, len8);
    } finally {
        wasm.__wbindgen_free(deferred9_0, deferred9_1, 1);
    }
}

/**
 * Trusted arguments must come from independent authority storage, never from
 * the proof request. The caller must atomically consume enrollment state.
 * @param {string} proof_json
 * @param {string} expected_json
 * @param {string} committed_json
 * @param {Uint8Array} initial_commitment
 * @param {Uint8Array} approved_account_id
 * @param {bigint} now
 */
export function verify_host_enrollment_proof(proof_json, expected_json, committed_json, initial_commitment, approved_account_id, now) {
    const ptr0 = passStringToWasm0(proof_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(expected_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passStringToWasm0(committed_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(initial_commitment, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passArray8ToWasm0(approved_account_id, wasm.__wbindgen_malloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.verify_host_enrollment_proof(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4, now);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * Verify preapproval possession only. The authority independently retains the
 * result; a public client ID grants neither account approval nor class.
 * @param {string} request_json
 * @returns {string}
 */
export function verify_host_key_initiation(request_json) {
    let deferred3_0;
    let deferred3_1;
    try {
        const ptr0 = passStringToWasm0(request_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ret = wasm.verify_host_key_initiation(ptr0, len0);
        var ptr2 = ret[0];
        var len2 = ret[1];
        if (ret[3]) {
            ptr2 = 0; len2 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred3_0 = ptr2;
        deferred3_1 = len2;
        return getStringFromWasm0(ptr2, len2);
    } finally {
        wasm.__wbindgen_free(deferred3_0, deferred3_1, 1);
    }
}

/**
 * All context is independently retained authority state, never request claims.
 * @param {string} proof_json
 * @param {string} committed_json
 * @param {Uint8Array} initial_commitment
 * @param {Uint8Array} approved_account_id
 * @param {string} context_json
 */
export function verify_host_refresh_proof(proof_json, committed_json, initial_commitment, approved_account_id, context_json) {
    const ptr0 = passStringToWasm0(proof_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(committed_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(initial_commitment, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passArray8ToWasm0(approved_account_id, wasm.__wbindgen_malloc);
    const len3 = WASM_VECTOR_LEN;
    const ptr4 = passStringToWasm0(context_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len4 = WASM_VECTOR_LEN;
    const ret = wasm.verify_host_refresh_proof(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, ptr4, len4);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * @param {string} approval_json
 * @param {string} host_json
 * @param {Uint8Array} pin
 * @param {string} expected_json
 * @param {bigint} now
 * @param {bigint} current_epoch
 */
export function verify_peer_approval(approval_json, host_json, pin, expected_json, now, current_epoch) {
    const ptr0 = passStringToWasm0(approval_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passStringToWasm0(host_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len1 = WASM_VECTOR_LEN;
    const ptr2 = passArray8ToWasm0(pin, wasm.__wbindgen_malloc);
    const len2 = WASM_VECTOR_LEN;
    const ptr3 = passStringToWasm0(expected_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len3 = WASM_VECTOR_LEN;
    const ret = wasm.verify_peer_approval(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3, now, current_epoch);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * @param {string} bundle_json
 * @param {Uint8Array} pin
 */
export function verify_public_bundle(bundle_json, pin) {
    const ptr0 = passStringToWasm0(bundle_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
    const len0 = WASM_VECTOR_LEN;
    const ptr1 = passArray8ToWasm0(pin, wasm.__wbindgen_malloc);
    const len1 = WASM_VECTOR_LEN;
    const ret = wasm.verify_public_bundle(ptr0, len0, ptr1, len1);
    if (ret[1]) {
        throw takeFromExternrefTable0(ret[0]);
    }
}

/**
 * Returns JSON {identity: SignedBundle, fingerprint: number[32]}. Commitment,
 * pin and approved account must come from independently retained server state.
 * @param {string} proof_json
 * @param {string} committed_json
 * @param {Uint8Array} initial_commitment
 * @param {Uint8Array} approved_account_id
 * @returns {string}
 */
export function verify_registered_host_identity(proof_json, committed_json, initial_commitment, approved_account_id) {
    let deferred6_0;
    let deferred6_1;
    try {
        const ptr0 = passStringToWasm0(proof_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len0 = WASM_VECTOR_LEN;
        const ptr1 = passStringToWasm0(committed_json, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
        const len1 = WASM_VECTOR_LEN;
        const ptr2 = passArray8ToWasm0(initial_commitment, wasm.__wbindgen_malloc);
        const len2 = WASM_VECTOR_LEN;
        const ptr3 = passArray8ToWasm0(approved_account_id, wasm.__wbindgen_malloc);
        const len3 = WASM_VECTOR_LEN;
        const ret = wasm.verify_registered_host_identity(ptr0, len0, ptr1, len1, ptr2, len2, ptr3, len3);
        var ptr5 = ret[0];
        var len5 = ret[1];
        if (ret[3]) {
            ptr5 = 0; len5 = 0;
            throw takeFromExternrefTable0(ret[2]);
        }
        deferred6_0 = ptr5;
        deferred6_1 = len5;
        return getStringFromWasm0(ptr5, len5);
    } finally {
        wasm.__wbindgen_free(deferred6_0, deferred6_1, 1);
    }
}
function __wbg_get_imports() {
    const import0 = {
        __proto__: null,
        __wbg_String_b25d814ea6bd03b7: function(arg0, arg1) {
            const ret = String(arg1);
            const ptr1 = passStringToWasm0(ret, wasm.__wbindgen_malloc, wasm.__wbindgen_realloc);
            const len1 = WASM_VECTOR_LEN;
            getDataViewMemory0().setInt32(arg0 + 4 * 1, len1, true);
            getDataViewMemory0().setInt32(arg0 + 4 * 0, ptr1, true);
        },
        __wbg___wbindgen_is_bigint_2f76dc55065b4273: function(arg0) {
            const ret = typeof(arg0) === 'bigint';
            return ret;
        },
        __wbg___wbindgen_throw_344f42d3211c4765: function(arg0, arg1) {
            throw new Error(getStringFromWasm0(arg0, arg1));
        },
        __wbg_getRandomValues_3f44b700395062e5: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbg_getRandomValues_cc7f052a444bb2ce: function() { return handleError(function (arg0, arg1) {
            globalThis.crypto.getRandomValues(getArrayU8FromWasm0(arg0, arg1));
        }, arguments); },
        __wbindgen_cast_0000000000000001: function(arg0, arg1) {
            // Cast intrinsic for `Ref(String) -> Externref`.
            const ret = getStringFromWasm0(arg0, arg1);
            return ret;
        },
        __wbindgen_init_externref_table: function() {
            const table = wasm.__wbindgen_externrefs;
            const offset = table.grow(4);
            table.set(0, undefined);
            table.set(offset + 0, undefined);
            table.set(offset + 1, null);
            table.set(offset + 2, true);
            table.set(offset + 3, false);
        },
    };
    return {
        __proto__: null,
        "./authority_crypto_bg.js": import0,
    };
}

const BrowserChannelFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browserchannel_free(ptr, 1));
const BrowserHandshakeFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browserhandshake_free(ptr, 1));
const BrowserHandshakeV3Finalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browserhandshakev3_free(ptr, 1));
const BrowserIdentityFinalization = (typeof FinalizationRegistry === 'undefined')
    ? { register: () => {}, unregister: () => {} }
    : new FinalizationRegistry(ptr => wasm.__wbg_browseridentity_free(ptr, 1));

function addToExternrefTable0(obj) {
    const idx = wasm.__externref_table_alloc();
    wasm.__wbindgen_externrefs.set(idx, obj);
    return idx;
}

function _assertClass(instance, klass) {
    if (!(instance instanceof klass)) {
        throw new Error(`expected instance of ${klass.name}`);
    }
}

function getArrayU8FromWasm0(ptr, len) {
    ptr = ptr >>> 0;
    return getUint8ArrayMemory0().subarray(ptr / 1, ptr / 1 + len);
}

let cachedDataViewMemory0 = null;
function getDataViewMemory0() {
    if (cachedDataViewMemory0 === null || cachedDataViewMemory0.buffer.detached === true || (cachedDataViewMemory0.buffer.detached === undefined && cachedDataViewMemory0.buffer !== wasm.memory.buffer)) {
        cachedDataViewMemory0 = new DataView(wasm.memory.buffer);
    }
    return cachedDataViewMemory0;
}

function getStringFromWasm0(ptr, len) {
    return decodeText(ptr >>> 0, len);
}

let cachedUint8ArrayMemory0 = null;
function getUint8ArrayMemory0() {
    if (cachedUint8ArrayMemory0 === null || cachedUint8ArrayMemory0.byteLength === 0) {
        cachedUint8ArrayMemory0 = new Uint8Array(wasm.memory.buffer);
    }
    return cachedUint8ArrayMemory0;
}

function handleError(f, args) {
    try {
        return f.apply(this, args);
    } catch (e) {
        const idx = addToExternrefTable0(e);
        wasm.__wbindgen_exn_store(idx);
    }
}

function passArray8ToWasm0(arg, malloc) {
    const ptr = malloc(arg.length * 1, 1) >>> 0;
    getUint8ArrayMemory0().set(arg, ptr / 1);
    WASM_VECTOR_LEN = arg.length;
    return ptr;
}

function passStringToWasm0(arg, malloc, realloc) {
    if (realloc === undefined) {
        const buf = cachedTextEncoder.encode(arg);
        const ptr = malloc(buf.length, 1) >>> 0;
        getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
        WASM_VECTOR_LEN = buf.length;
        return ptr;
    }

    let len = arg.length;
    let ptr = malloc(len, 1) >>> 0;

    const mem = getUint8ArrayMemory0();

    let offset = 0;

    for (; offset < len; offset++) {
        const code = arg.charCodeAt(offset);
        if (code > 0x7F) break;
        mem[ptr + offset] = code;
    }
    if (offset !== len) {
        if (offset !== 0) {
            arg = arg.slice(offset);
        }
        ptr = realloc(ptr, len, len = offset + arg.length * 3, 1) >>> 0;
        const view = getUint8ArrayMemory0().subarray(ptr + offset, ptr + len);
        const ret = cachedTextEncoder.encodeInto(arg, view);

        offset += ret.written;
        ptr = realloc(ptr, len, offset, 1) >>> 0;
    }

    WASM_VECTOR_LEN = offset;
    return ptr;
}

function takeFromExternrefTable0(idx) {
    const value = wasm.__wbindgen_externrefs.get(idx);
    wasm.__externref_table_dealloc(idx);
    return value;
}

let cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
cachedTextDecoder.decode();
const MAX_SAFARI_DECODE_BYTES = 2146435072;
let numBytesDecoded = 0;
function decodeText(ptr, len) {
    numBytesDecoded += len;
    if (numBytesDecoded >= MAX_SAFARI_DECODE_BYTES) {
        cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
        cachedTextDecoder.decode();
        numBytesDecoded = len;
    }
    return cachedTextDecoder.decode(getUint8ArrayMemory0().subarray(ptr, ptr + len));
}

const cachedTextEncoder = new TextEncoder();

if (!('encodeInto' in cachedTextEncoder)) {
    cachedTextEncoder.encodeInto = function (arg, view) {
        const buf = cachedTextEncoder.encode(arg);
        view.set(buf);
        return {
            read: arg.length,
            written: buf.length
        };
    };
}

let WASM_VECTOR_LEN = 0;

let wasmModule, wasmInstance, wasm;
function __wbg_finalize_init(instance, module) {
    wasmInstance = instance;
    wasm = instance.exports;
    wasmModule = module;
    cachedDataViewMemory0 = null;
    cachedUint8ArrayMemory0 = null;
    wasm.__wbindgen_start();
    return wasm;
}

async function __wbg_load(module, imports) {
    if (typeof Response === 'function' && module instanceof Response) {
        if (typeof WebAssembly.instantiateStreaming === 'function') {
            try {
                return await WebAssembly.instantiateStreaming(module, imports);
            } catch (e) {
                const validResponse = module.ok && expectedResponseType(module.type);

                if (validResponse && module.headers.get('Content-Type') !== 'application/wasm') {
                    console.warn("`WebAssembly.instantiateStreaming` failed because your server does not serve Wasm with `application/wasm` MIME type. Falling back to `WebAssembly.instantiate` which is slower. Original error:\n", e);

                } else { throw e; }
            }
        }

        const bytes = await module.arrayBuffer();
        return await WebAssembly.instantiate(bytes, imports);
    } else {
        const instance = await WebAssembly.instantiate(module, imports);

        if (instance instanceof WebAssembly.Instance) {
            return { instance, module };
        } else {
            return instance;
        }
    }

    function expectedResponseType(type) {
        switch (type) {
            case 'basic': case 'cors': case 'default': return true;
        }
        return false;
    }
}

function initSync(module) {
    if (wasm !== undefined) return wasm;


    if (module !== undefined) {
        if (Object.getPrototypeOf(module) === Object.prototype) {
            ({module} = module)
        } else {
            console.warn('using deprecated parameters for `initSync()`; pass a single object instead')
        }
    }

    const imports = __wbg_get_imports();
    if (!(module instanceof WebAssembly.Module)) {
        module = new WebAssembly.Module(module);
    }
    const instance = new WebAssembly.Instance(module, imports);
    return __wbg_finalize_init(instance, module);
}

async function __wbg_init(module_or_path) {
    if (wasm !== undefined) return wasm;


    if (module_or_path !== undefined) {
        if (Object.getPrototypeOf(module_or_path) === Object.prototype) {
            ({module_or_path} = module_or_path)
        } else {
            console.warn('using deprecated parameters for the initialization function; pass a single object instead')
        }
    }

    if (module_or_path === undefined) {
        module_or_path = new URL('authority_crypto_bg.wasm', import.meta.url);
    }
    const imports = __wbg_get_imports();

    if (typeof module_or_path === 'string' || (typeof Request === 'function' && module_or_path instanceof Request) || (typeof URL === 'function' && module_or_path instanceof URL)) {
        module_or_path = fetch(module_or_path);
    }

    const { instance, module } = await __wbg_load(await module_or_path, imports);

    return __wbg_finalize_init(instance, module);
}

export { initSync, __wbg_init as default };
