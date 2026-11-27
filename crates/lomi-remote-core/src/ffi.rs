//! C ABI (iOS static library, tests) and JNI (Android `.so`) over [`crate::bridge`].
//! Ownership: the result of `lomi_core_call` belongs to the caller and must be released
//! with `lomi_core_bytes_free(ptr, len)`; inputs stay owned by the caller.

use crate::bridge;
use std::ffi::{CStr, c_char};
use std::panic::catch_unwind;

fn into_raw(v: Vec<u8>, len: *mut usize) -> *mut u8 {
    let b = v.into_boxed_slice();
    // SAFETY: `len` is a valid out pointer per the contract of the exported functions.
    unsafe { *len = b.len() };
    Box::into_raw(b).cast()
}

/// # Safety
/// `op` is a NUL-terminated string; `args`/`payload` point to `*_len` readable bytes (or are
/// null with length 0); `out_len` is writable. Returns null on a panic or invalid `op`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lomi_core_call(
    handle: u32,
    op: *const c_char,
    args: *const u8,
    args_len: usize,
    payload: *const u8,
    payload_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let slice = |p: *const u8, n: usize| {
        if n == 0 {
            &[][..]
        } else {
            // SAFETY: guaranteed by the caller.
            unsafe { std::slice::from_raw_parts(p, n) }
        }
    };
    // SAFETY: `op` is NUL-terminated per the contract.
    let Ok(op) = unsafe { CStr::from_ptr(op) }.to_str() else {
        return std::ptr::null_mut();
    };
    let (args, payload) = (slice(args, args_len), slice(payload, payload_len));
    match catch_unwind(|| bridge::call(handle, op, args, payload)) {
        Ok(v) => into_raw(v, out_len),
        Err(_) => std::ptr::null_mut(),
    }
}

/// # Safety
/// `ptr`/`len` must be exactly a result of `lomi_core_call`, released once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn lomi_core_bytes_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() {
        // SAFETY: reverses `into_raw`.
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn lomi_core_free(handle: u32) {
    let _ = catch_unwind(|| bridge::free(handle));
}

/// Kotlin: `dev.lomi.core.LomiRemoteCoreModule` declares
/// `external fun nativeCall(handle: Int, op: String, args: ByteArray, payload: ByteArray): ByteArray?`
/// and `external fun nativeFree(handle: Int)`.
#[cfg(target_os = "android")]
mod android {
    use super::*;
    use jni::JNIEnv;
    use jni::objects::{JByteArray, JClass, JString};
    use jni::sys::{jbyteArray, jint};

    fn run(
        env: &mut JNIEnv,
        handle: jint,
        op: &JString,
        args: &JByteArray,
        payload: &JByteArray,
    ) -> Option<jbyteArray> {
        let op: String = env.get_string(op).ok()?.into();
        let args = env.convert_byte_array(args).ok()?;
        let payload = env.convert_byte_array(payload).ok()?;
        let out = catch_unwind(|| bridge::call(handle as u32, &op, &args, &payload)).ok()?;
        Some(env.byte_array_from_slice(&out).ok()?.into_raw())
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_dev_lomi_core_LomiRemoteCoreModule_nativeCall(
        mut env: JNIEnv,
        _: JClass,
        handle: jint,
        op: JString,
        args: JByteArray,
        payload: JByteArray,
    ) -> jbyteArray {
        run(&mut env, handle, &op, &args, &payload).unwrap_or(std::ptr::null_mut())
    }

    #[unsafe(no_mangle)]
    pub extern "system" fn Java_dev_lomi_core_LomiRemoteCoreModule_nativeFree(
        _: JNIEnv,
        _: JClass,
        handle: jint,
    ) {
        let _ = catch_unwind(|| bridge::free(handle as u32));
    }
}
