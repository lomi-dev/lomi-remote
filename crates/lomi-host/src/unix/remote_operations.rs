//! Typed Store-derived disclosure proofs for remote operation status/cancel.
//!
//! The implementations live beside SharedOwner's private Store/Domain access;
//! this module is the narrow namespace consumed by remote ingress and channel
//! gates. No RPC payload can construct any of these values.

pub(super) use super::shared_owner::{RemoteOperationAuthorization, RemoteOperationDisclosure};
