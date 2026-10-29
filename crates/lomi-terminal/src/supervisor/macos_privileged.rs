//! Trusted macOS primitives for a separate per-PTY root launchd job.
//! This module owns only cohort capability checks and the post-drop child
//! entry point; the service broker owns job creation and lifecycle.

pub(super) use super::Error;

mod broker;
mod capability;
mod child;
mod client;
mod controller;
mod journal;
mod manager;
mod wire;

pub(super) use client::Worker;
pub(crate) use client::spawn;

pub(crate) fn run_admin(registration: &std::path::Path, drain: bool) -> i32 {
    client::admin(registration, drain)
}

pub(crate) fn run_broker(registration: &std::path::Path) -> i32 {
    broker::run_broker(registration)
}

pub(crate) fn run_controller(registration: &std::path::Path, generation: &std::path::Path) -> i32 {
    controller::run_controller(registration, generation)
}

pub(crate) fn run_child(control_fd: i32) -> i32 {
    child::run(control_fd)
}
