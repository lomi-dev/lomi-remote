//! Agent profiles retain their existing caller-scoped Mach and network
//! grants. NativeGit uses separate explicit fixed-service and egress rules.
use super::failure;
use crate::{NativeGitPolicy, Policy, PolicyMode};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const MDNS_RESOLVER_SOCKET: &str = "/private/var/run/mDNSResponder";
const NATIVE_GIT_NETWORK_MACH_SERVICES: &[&str] = &[
    "com.apple.SystemConfiguration.DNSConfiguration",
    "com.apple.SystemConfiguration.configd",
    "com.apple.trustd.agent",
    "com.apple.SecurityServer",
];
fn quote(path: &Path) -> Result<String, String> {
    let p = path.to_str().ok_or_else(failure)?;
    if p.len() > 16384 || p.chars().any(char::is_control) || !path.is_absolute() {
        return Err(failure());
    }
    serde_json::to_string(p).map_err(|_| failure())
}
fn canonical_or_future(path: &Path) -> Result<(), String> {
    use std::path::Component;
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                Component::CurDir | Component::ParentDir | Component::Prefix(_)
            )
        })
    {
        return Err(failure());
    }
    let mut ancestor = path;
    loop {
        match std::fs::symlink_metadata(ancestor) {
            Ok(_) => {
                if ancestor.canonicalize().map_err(|_| failure())? != ancestor {
                    return Err(failure());
                }
                return Ok(());
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ancestor = ancestor.parent().ok_or_else(failure)?
            }
            Err(_) => return Err(failure()),
        }
    }
}

fn canonical_directory(path: &Path) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|_| failure())?;
    if path == Path::new("/")
        || metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || path.canonicalize().map_err(|_| failure())? != path
    {
        return Err(failure());
    }
    quote(path)?;
    Ok(())
}

fn overlaps(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn validate_system_resolver_socket() -> Result<(), String> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let path = Path::new(MDNS_RESOLVER_SOCKET);
    let metadata = std::fs::symlink_metadata(path).map_err(|_| failure())?;
    let parent = path.parent().ok_or_else(failure)?;
    let parent_metadata = std::fs::symlink_metadata(parent).map_err(|_| failure())?;
    if path.canonicalize().map_err(|_| failure())? != path
        || parent.canonicalize().map_err(|_| failure())? != parent
        || !metadata.file_type().is_socket()
        || metadata.uid() != 0
        || parent_metadata.file_type().is_symlink()
        || !parent_metadata.is_dir()
        || parent_metadata.uid() != 0
        || parent_metadata.mode() & 0o022 != 0
    {
        return Err(failure());
    }
    Ok(())
}

fn allow_unix_socket(profile: &mut String, path: &Path) -> Result<(), String> {
    let parent = path.parent().ok_or_else(failure)?;
    profile.push_str(&format!(
        "(allow file-read-metadata (literal {}))\n",
        quote(parent)?
    ));
    profile.push_str(&format!(
        "(allow network-outbound (remote unix-socket (path-literal {})))\n",
        quote(path)?
    ));
    profile.push_str(&format!(
        "(allow file-read-metadata file-read-data file-write-data (literal {}))\n",
        quote(path)?
    ));
    Ok(())
}

fn git_policy(mode: &PolicyMode) -> Option<&NativeGitPolicy> {
    match mode {
        PolicyMode::Agent => None,
        PolicyMode::NativeGit(policy) => Some(policy),
    }
}
impl Policy {
    pub(super) fn validate(&self) -> Result<(), String> {
        let git = git_policy(&self.mode);
        if self.runtime_reads.len() > 32
            || self.protected_reads.len() > 32
            || self.blocked_reads.len() > 256
            || self.runtime_read_roots.len() > 32
            || self.loopback_tcp_ports.len() > 32
            || self.loopback_tcp_ports.contains(&0)
            || self.unix_sockets.len() > 8
            || git.is_some_and(|policy| {
                policy.executable_roots.len() > 32
                    || policy.runtime_read_roots.len() > 32
                    || policy.repository_write_roots.len() > 32
            })
        {
            return Err(failure());
        }
        if (git.is_some() && self.account_root.is_some())
            || (git.is_none() && self.account_root.is_none())
            || git.is_some_and(|_| {
                self.codex_preferences
                    || !self.loopback_tcp_ports.is_empty()
                    || self.loopback_listener
                    || !self.unix_sockets.is_empty()
                    || self.allow_native_tools
                    || !self.runtime_read_roots.is_empty()
            })
        {
            return Err(failure());
        }
        let mut roots = vec![&self.project_root];
        roots.extend(self.account_root.iter());
        roots.push(&self.temp_root);
        for path in roots
            .into_iter()
            .chain(self.runtime_reads.iter())
            .chain(self.runtime_read_roots.iter())
            .enumerate()
        {
            let (index, path) = path;
            if path
                .canonicalize()
                .map_err(|_| format!("Native runtime policy path {index} is unavailable."))?
                != *path
            {
                return Err(format!(
                    "Native runtime policy path {index} is not canonical."
                ));
            }
            quote(path)?;
        }
        if let Some(git) = git {
            for root in git
                .executable_roots
                .iter()
                .chain(git.runtime_read_roots.iter())
                .chain(git.repository_write_roots.iter())
            {
                canonical_directory(root)?;
            }
            if let Some(socket) = &git.credential_socket {
                canonical_or_future(socket)?;
                let metadata = std::fs::symlink_metadata(socket).map_err(|_| failure())?;
                use std::os::unix::fs::FileTypeExt;
                if !metadata.file_type().is_socket()
                    || self
                        .protected_reads
                        .iter()
                        .chain(self.blocked_reads.iter())
                        .any(|protected| overlaps(socket, protected))
                {
                    return Err(failure());
                }
            }
            if git.outbound_network {
                validate_system_resolver_socket()?;
            }
        }
        for path in self
            .protected_reads
            .iter()
            .chain(self.blocked_reads.iter())
            .chain(self.unix_sockets.iter())
            .enumerate()
        {
            let (index, path) = path;
            canonical_or_future(path)
                .map_err(|_| format!("Native protected policy path {index} is not canonical."))?;
            quote(path)?;
        }
        Ok(())
    }
    pub(super) fn profile(&self, control: &Path) -> Result<String, String> {
        self.validate()?;
        let git = git_policy(&self.mode);
        let mut writable_roots = vec![self.project_root.as_path(), self.temp_root.as_path()];
        if let Some(account_root) = &self.account_root {
            writable_roots.insert(1, account_root);
        }
        if let Some(git) = git {
            writable_roots.extend(git.repository_write_roots.iter().map(PathBuf::as_path));
        }
        for p in &writable_roots {
            if control.starts_with(p) || p.starts_with(control) {
                return Err("Control and native writable domains must not overlap.".into());
            }
        }
        let mut runtime_roots: Vec<&Path> =
            self.runtime_reads.iter().map(PathBuf::as_path).collect();
        if let Some(git) = git {
            runtime_roots.extend(git.runtime_read_roots.iter().map(PathBuf::as_path));
        } else {
            runtime_roots.extend(self.runtime_read_roots.iter().map(PathBuf::as_path));
        }
        for runtime in runtime_roots {
            if writable_roots
                .iter()
                .any(|writable| overlaps(runtime, writable))
                || overlaps(runtime, control)
            {
                return Err(
                    "Executable runtime reads and writable/control domains must not overlap."
                        .into(),
                );
            }
        }
        let mut sockets: Vec<&Path> = self.unix_sockets.iter().map(PathBuf::as_path).collect();
        if let Some(git) = git {
            sockets.extend(git.credential_socket.iter().map(PathBuf::as_path));
        }
        for socket in sockets {
            if writable_roots
                .iter()
                .any(|writable| overlaps(socket, writable))
                || overlaps(socket, control)
            {
                return Err(failure());
            }
            if let Ok(metadata) = std::fs::symlink_metadata(socket) {
                use std::os::unix::fs::FileTypeExt;
                if !metadata.file_type().is_socket() {
                    return Err(failure());
                }
            }
        }
        for read in &self.protected_reads {
            if read.starts_with(control) || control.starts_with(read) {
                return Err(failure());
            }
        }
        if let Some(git) = git {
            for write_root in &git.repository_write_roots {
                if overlaps(write_root, control)
                    || writable_roots
                        .iter()
                        .any(|writable| *writable != write_root && overlaps(write_root, writable))
                    || self
                        .protected_reads
                        .iter()
                        .chain(self.blocked_reads.iter())
                        .any(|protected| overlaps(write_root, protected))
                    || self
                        .runtime_reads
                        .iter()
                        .any(|runtime| overlaps(write_root, runtime))
                    || git
                        .runtime_read_roots
                        .iter()
                        .any(|runtime| overlaps(write_root, runtime))
                {
                    return Err(failure());
                }
            }
            for root in &git.executable_roots {
                if overlaps(root, control)
                    || overlaps(root, &self.temp_root)
                    || self
                        .protected_reads
                        .iter()
                        .chain(self.blocked_reads.iter())
                        .any(|protected| overlaps(root, protected))
                {
                    return Err(failure());
                }
            }
            for root in &git.runtime_read_roots {
                if overlaps(root, control)
                    || self
                        .protected_reads
                        .iter()
                        .chain(self.blocked_reads.iter())
                        .any(|protected| overlaps(root, protected))
                {
                    return Err(failure());
                }
            }
        }
        let mut p="(version 1)\n(deny default)\n(allow process-exec process-fork)\n(allow signal (target self))\n(allow sysctl-read)\n(allow file-read-metadata)\n".to_owned();
        // Darwin 27 libignition opens the root directory for openat bootstrap.
        // This literal grants directory data only, not descendant contents.
        p.push_str("(allow file-read-data (literal \"/\"))\n");
        // Executable mapping is a separate operation from file-read*. System
        // libraries and explicitly admitted runtime files may be mapped.
        // Project mappings require the separately selected native-tools policy;
        // writable account, temporary and control roots receive no mapping grant.
        if self.allow_native_tools {
            for path in [
                Path::new("/bin"),
                Path::new("/usr/bin"),
                Path::new("/usr/sbin"),
                Path::new("/sbin"),
                self.project_root.as_path(),
            ] {
                p.push_str(&format!(
                    "(allow file-read* file-map-executable (literal {}) (subpath {}))\n",
                    quote(path)?,
                    quote(path)?
                ));
            }
        }
        if let Some(git) = git {
            // NativeGit is an explicit code-execution capability. Hooks in
            // admitted project/common-Git roots may run; other helper search
            // paths are limited to Host-captured roots sealed into this policy.
            p.push_str(&format!(
                "(allow file-read* file-map-executable (subpath {}))\n",
                quote(&self.project_root)?
            ));
            for root in &git.executable_roots {
                p.push_str(&format!(
                    "(allow file-read* file-map-executable (literal {}) (subpath {}))\n",
                    quote(root)?,
                    quote(root)?
                ));
            }
            for root in &git.repository_write_roots {
                p.push_str(&format!(
                    "(allow file-read* file-map-executable (subpath {}))\n",
                    quote(root)?
                ));
            }
        }
        for path in [Path::new("/System/Library"), Path::new("/usr/lib")] {
            p.push_str(&format!(
                "(allow file-map-executable (subpath {}))\n",
                quote(path)?
            ));
        }
        for path in &self.runtime_reads {
            p.push_str(&format!(
                "(allow file-map-executable (literal {}))\n",
                quote(path)?
            ));
        }
        if git.is_some() {
            for path in self.protected_reads.iter().chain(self.blocked_reads.iter()) {
                p.push_str(&format!(
                    "(deny file-map-executable (literal {}) (subpath {}))\n",
                    quote(path)?,
                    quote(path)?
                ));
            }
        }
        let native_runtime_roots = git.map_or(self.runtime_read_roots.as_slice(), |git| {
            git.runtime_read_roots.as_slice()
        });
        let mut read_roots: Vec<&Path> = vec![
            Path::new("/System/Library"),
            Path::new("/usr/lib"),
            Path::new("/usr/share"),
        ];
        read_roots.extend(self.runtime_reads.iter().map(PathBuf::as_path));
        read_roots.extend(self.protected_reads.iter().map(PathBuf::as_path));
        read_roots.extend(native_runtime_roots.iter().map(PathBuf::as_path));
        read_roots.push(&self.project_root);
        if let Some(account_root) = &self.account_root {
            read_roots.push(account_root);
        }
        read_roots.push(&self.temp_root);
        if let Some(git) = git {
            read_roots.extend(git.repository_write_roots.iter().map(PathBuf::as_path));
        }
        for path in read_roots {
            p.push_str(&format!(
                "(allow file-read* (literal {}) (subpath {}))\n",
                quote(path)?,
                quote(path)?
            ));
        }
        for path in &writable_roots {
            p.push_str(&format!("(allow file-write* (subpath {}))\n", quote(path)?));
            if git.is_some() {
                // Git publishes loose objects using hard links. Both the
                // source link permission and destination writes stay confined
                // to admitted writable domains.
                p.push_str(&format!("(allow file-link (subpath {}))\n", quote(path)?));
            }
        }
        for path in self
            .protected_reads
            .iter()
            .chain(self.runtime_reads.iter())
            .chain(native_runtime_roots.iter())
        {
            p.push_str(&format!(
                "(deny file-write* (literal {}) (subpath {}))\n",
                quote(path)?,
                quote(path)?
            ));
        }
        for path in &self.blocked_reads {
            p.push_str(&format!(
                "(deny file-read* file-write* (literal {}) (subpath {}))\n",
                quote(path)?,
                quote(path)?
            ));
        }
        p.push_str("(allow file-read* file-write* (literal \"/dev/null\"))\n(allow file-read* (literal \"/dev/urandom\") (literal \"/dev/random\"))\n");
        p.push_str(&format!(
            "(deny file-read* file-write* (literal {}) (subpath {}))\n",
            quote(control)?,
            quote(control)?
        ));
        // Native stdio uses anonymous pipes or the worker-owned terminal. Only
        // the unsandboxed supervisor opens these private transport FIFOs.
        for ancestor in control.ancestors() {
            p.push_str(&format!(
                "(deny file-write-unlink (literal {}))\n",
                quote(ancestor)?
            ));
        }
        if git.is_some() {
            // A protected descendant may be replaced by renaming one of its
            // writable ancestors, even though writes below the protected path
            // itself are denied. Keep the ancestors within admitted Git write
            // roots pinned against unlink/rename operations as well.
            let mut protected_ancestors = BTreeSet::new();
            for protected in self.protected_reads.iter().chain(&self.blocked_reads) {
                for ancestor in protected.ancestors() {
                    if writable_roots
                        .iter()
                        .any(|writable| ancestor.starts_with(writable))
                    {
                        protected_ancestors.insert(ancestor.to_path_buf());
                    }
                }
            }
            for ancestor in protected_ancestors {
                p.push_str(&format!(
                    "(deny file-write-unlink (literal {}))\n",
                    quote(&ancestor)?
                ));
            }
        }
        if self.codex_preferences {
            p.push_str("(allow mach-lookup (global-name \"com.apple.cfprefsd.agent\") (local-name \"com.apple.cfprefsd.agent\") (global-name \"com.apple.cfprefsd.daemon\"))\n");
            p.push_str("(allow user-preference-read (preference-domain \"com.openai.codex\"))\n(deny user-preference-write)\n");
            p.push_str(&format!("(allow ipc-posix-shm-read-data (ipc-posix-name \"apple.cfprefs.{}v1\") (ipc-posix-name \"apple.cfprefs.daemonv1\"))\n", unsafe { libc::geteuid() }));
        } else if let Some(git) = git {
            if git.outbound_network {
                // These fixed services support DNS, TLS trust evaluation, and
                // Keychain-backed credentials. Names come from Chromium's
                // narrowly scoped macOS network policy; no caller-selected
                // service names or service registration are admitted:
                // https://chromium.googlesource.com/experimental/chromium/src/+/HEAD/sandbox/policy/mac/network.sb
                p.push_str("(allow mach-lookup");
                for service in NATIVE_GIT_NETWORK_MACH_SERVICES {
                    p.push_str(&format!(" (global-name \"{service}\")"));
                }
                p.push_str(")\n");
            }
        } else {
            p.push_str("(deny mach-lookup)\n");
        }
        p.push_str("(deny mach-register)\n");
        if git.is_some() {
            // NativeGit identity checks use task_name_for_pid/task_info,
            // proc_pid_rusage, and proc_pidinfo; wait-group observation uses
            // proc_listpids. These are read-only identity, usage, and liveness
            // queries; task-read, task-for-pid, and process injection remain
            // denied.
            p.push_str(
                "(allow mach-task-name process-info-pidinfo process-info-listpids process-info-rusage)\n",
            );
        }
        if let Some(git) = git {
            if git.outbound_network {
                // Native Git is the explicit code-execution mode. Remote Git
                // may use outbound TCP/UDP and the fixed system DNS resolver
                // socket. It never receives inbound listeners or an
                // unrestricted Unix-socket grant. Apple's mDNSResponder IPC
                // socket is defined in:
                // https://github.com/apple-oss-distributions/mDNSResponder/blob/main/mDNSShared/dnssd_ipc.h#L80-L89
                p.push_str(
                    "(allow network-outbound (remote tcp))\n(allow network-outbound (remote udp))\n",
                );
                allow_unix_socket(&mut p, Path::new(MDNS_RESOLVER_SOCKET))?;
                // Seatbelt's `localhost` remote selector includes every
                // address assigned to this machine, including non-loopback
                // IPv4 and IPv6 addresses. Deny those destinations after the
                // broad TCP/UDP grants so Git helpers cannot delegate writes
                // to a local service. The selector is dynamically interpreted
                // by Seatbelt, so it requires no address enumeration that could
                // become stale. See Bazel's Darwin sandbox policy and coverage:
                // https://bazel.googlesource.com/bazel/+/696734cfd3d338d04a885fa65b996ece43fe365c
                p.push_str("(deny network-outbound (remote ip \"localhost:*\"))\n");
            }
            p.push_str("(deny network-inbound)\n(deny network-bind)\n");
            if let Some(path) = &git.credential_socket {
                allow_unix_socket(&mut p, path)?;
            }
        } else if self.loopback_tcp_ports.is_empty()
            && !self.loopback_listener
            && self.unix_sockets.is_empty()
        {
            p.push_str("(deny network-outbound)\n(deny network-inbound)\n(deny network-bind)\n");
        } else {
            for port in &self.loopback_tcp_ports {
                p.push_str(&format!(
                    "(allow network-outbound (remote tcp \"localhost:{}\"))\n",
                    port
                ));
            }
            if self.loopback_listener {
                p.push_str("(allow network-bind network-inbound (local tcp \"localhost:*\"))\n");
            }
            for path in &self.unix_sockets {
                let parent = path.parent().ok_or_else(failure)?;
                p.push_str(&format!(
                    "(allow file-read-metadata (literal {}))\n",
                    quote(parent)?
                ));
                p.push_str(&format!(
                    "(allow network-outbound (remote unix-socket (path-literal {})))\n",
                    quote(path)?
                ));
                p.push_str(&format!(
                    "(allow file-read-metadata file-read-data file-write-data (literal {}))\n",
                    quote(path)?
                ));
            }
        }
        if git.is_some() {
            for path in self
                .protected_reads
                .iter()
                .chain(self.runtime_reads.iter())
                .chain(native_runtime_roots.iter())
                .chain(self.blocked_reads.iter())
                .map(PathBuf::as_path)
                .chain(std::iter::once(control))
            {
                p.push_str(&format!(
                    "(deny file-link (literal {}) (subpath {}))\n",
                    quote(path)?,
                    quote(path)?
                ));
            }
            // Emit after every filesystem grant, including credential socket
            // exceptions. A later allow must not reopen staged recovery data.
            for pattern in lomi_fs_policy::private_staging_path_patterns() {
                let expression = serde_json::to_string(&pattern).map_err(|_| failure())?;
                p.push_str(&format!(
                    "(deny file-read* file-write* file-map-executable file-link (regex #{expression}))\n"
                ));
            }
        }
        Ok(p)
    }
    pub(super) fn apply_terminal(
        &self,
        control: &Path,
        terminal: Option<&Path>,
    ) -> Result<(), String> {
        unsafe extern "C" {
            fn sandbox_init(
                profile: *const std::ffi::c_char,
                flags: u64,
                error: *mut *mut std::ffi::c_char,
            ) -> i32;
            fn sandbox_free_error(error: *mut std::ffi::c_char);
        }
        let mut profile = self.profile(control)?;
        if let Some(path) = terminal {
            if path.parent() != Some(Path::new("/dev"))
                || !path.file_name().and_then(|s| s.to_str()).is_some_and(|s| {
                    s.starts_with("ttys") && s[4..].bytes().all(|b| b.is_ascii_digit())
                })
            {
                return Err(failure());
            }
            profile.push_str(&format!(
                "(allow file-read* file-write* (literal {}))\n",
                quote(path)?
            ));
            profile.push_str(&format!("(allow file-ioctl (literal {}))\n", quote(path)?));
        }
        let p = std::ffi::CString::new(profile).map_err(|_| failure())?;
        let mut error = std::ptr::null_mut();
        let result = unsafe { sandbox_init(p.as_ptr(), 0, &mut error) };
        if !error.is_null() {
            unsafe { sandbox_free_error(error) };
        }
        if result != 0 {
            return Err("The restrictive host sandbox profile was not admitted.".into());
        }
        Ok(())
    }
}
