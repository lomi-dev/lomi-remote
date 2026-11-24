//! Tauri-independent Chat AI backend: thread storage, settings, HTTP and CLI providers.
pub mod acp;
pub mod attachments;
pub mod checkpoint;
pub mod cli;
pub mod cli_bin;
pub mod codex_server;
pub mod engine;
pub mod http;
pub mod session;
pub mod settings;
pub mod storage;
pub mod store;

/// The user's home directory; falls back to `/` when no variable is set.
pub fn home() -> std::path::PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("/"))
}
