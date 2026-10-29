use super::Error;
use std::mem::size_of;

#[repr(C)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
pub(super) struct Identity {
    pid: i32,
    pidversion: u32,
    audit: [u32; 8],
    resource: u64,
    jetsam: u64,
}

const _: () = assert!(size_of::<Identity>() == 56);

impl Identity {
    pub(super) fn from_parts(
        pid: i32,
        pidversion: u32,
        audit: [u32; 8],
        resource: u64,
        jetsam: u64,
    ) -> Result<Self, Error> {
        if pid <= 0 || pidversion == 0 || resource == 0 || jetsam == 0 {
            return Err(Error::CleanupFailed);
        }
        Ok(Self {
            pid,
            pidversion,
            audit,
            resource,
            jetsam,
        })
    }

    pub(super) fn pid(self) -> i32 {
        self.pid
    }

    pub(super) fn pidversion(self) -> u32 {
        self.pidversion
    }

    pub(super) fn resource(self) -> u64 {
        self.resource
    }

    pub(super) fn jetsam(self) -> u64 {
        self.jetsam
    }

    pub(super) fn audit(self) -> [u32; 8] {
        self.audit
    }

    /// Credential changes update the audit token's UID fields but retain this
    /// exact task incarnation and its two cohort memberships.
    pub(super) fn same_task_and_cohorts(self, other: Self) -> bool {
        self.pid == other.pid
            && self.pidversion == other.pidversion
            && self.resource == other.resource
            && self.jetsam == other.jetsam
    }

    pub(super) fn same_cohorts(self, other: Self) -> bool {
        self.resource == other.resource && self.jetsam == other.jetsam
    }

    pub(super) fn same_identity(self, other: Self) -> bool {
        self == other
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PrivilegeProbe {
    NonPrivileged,
    Privileged,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DrainResult {
    Empty,
    MembersRemain,
}

unsafe extern "C" {
    fn lomi_privileged_current_cohorts(result: *mut Identity) -> libc::c_int;
    fn lomi_privileged_identity_from_audit_token(
        audit: *const u32,
        result: *mut Identity,
    ) -> libc::c_int;
    fn lomi_privileged_count(
        controller: *const Identity,
        members_excluding_controller: *mut u64,
    ) -> libc::c_int;
    fn lomi_privileged_drain(
        controller: *const Identity,
        signal_number: libc::c_int,
    ) -> libc::c_int;
    fn lomi_privileged_available() -> libc::c_int;
    fn lomi_privileged_probe() -> libc::c_int;
}

pub(super) fn current_cohorts() -> Result<Identity, Error> {
    let mut result = Identity::default();
    if unsafe { lomi_privileged_current_cohorts(&mut result) } != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(result)
}

pub(super) fn identity_from_audit(audit: &[u32; 8]) -> Result<Identity, Error> {
    let mut result = Identity::default();
    if unsafe { lomi_privileged_identity_from_audit_token(audit.as_ptr(), &mut result) } != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(result)
}

pub(super) fn count(controller: &Identity) -> Result<u64, Error> {
    let mut members = 0;
    if unsafe { lomi_privileged_count(controller, &mut members) } != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(members)
}

pub(super) fn drain(controller: &Identity, signal: libc::c_int) -> Result<DrainResult, Error> {
    match unsafe { lomi_privileged_drain(controller, signal) } {
        0 => Ok(DrainResult::Empty),
        1 => Ok(DrainResult::MembersRemain),
        _ => Err(Error::CleanupFailed),
    }
}

pub(super) fn available() -> bool {
    unsafe { lomi_privileged_available() == 0 }
}

pub(super) fn probe() -> Result<PrivilegeProbe, Error> {
    match unsafe { lomi_privileged_probe() } {
        0 => Ok(PrivilegeProbe::NonPrivileged),
        1 => Ok(PrivilegeProbe::Privileged),
        _ => Err(Error::CleanupFailed),
    }
}

pub(super) fn require_nonprivileged_current() -> Result<(), Error> {
    match probe()? {
        PrivilegeProbe::NonPrivileged => Ok(()),
        PrivilegeProbe::Privileged => Err(Error::CleanupFailed),
    }
}
