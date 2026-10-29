//! Isolated cooperative admission experiment, not a product LocalApi.
#![cfg(unix)]
pub mod client;
#[cfg(feature = "host")]
mod endpoint;
#[cfg(feature = "host")]
mod authority {
    use super::{client, endpoint};
    use rusqlite::{Connection, params};
    use serde::{Deserialize, Serialize};
    use std::{
        fs,
        io::{self, Read},
        os::unix::{fs::MetadataExt, net::UnixStream},
        path::{Path, PathBuf},
        sync::{
            Arc, Mutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, SystemTime, UNIX_EPOCH},
    };
    const LEASE_MS: u64 = 2000;
    const MAX_CONNECTIONS: usize = 16;
    const MAX_ROWS: i64 = 256;
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
    use client::{Kind, Reply, Request};
    use client::{read_frame, write_frame};
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Object(u64, u64);
    fn object(path: &Path) -> Result<Object> {
        let m = fs::metadata(path)?;
        Ok(Object(m.dev(), m.ino()))
    }
    #[derive(Debug, Serialize, Deserialize)]
    struct Scope {
        path: PathBuf,
        identity_path: PathBuf,
        identity: Object,
        exact: bool,
        directory: bool,
        ancestry: Vec<Object>,
        git: Vec<(PathBuf, Object)>,
    }
    impl Scope {
        fn resolve(path: &Path) -> Result<Self> {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|p| matches!(p, std::path::Component::ParentDir))
            {
                return Err("absolute path without parent traversal required".into());
            }
            let mut existing = path;
            let mut suffix = Vec::new();
            while fs::symlink_metadata(existing).is_err_and(|e| e.kind() == io::ErrorKind::NotFound)
            {
                suffix.push(existing.file_name().ok_or("invalid path")?.to_owned());
                existing = existing.parent().ok_or("invalid parent")?;
            }
            let canonical = existing.canonicalize()?;
            if !suffix.is_empty() && !canonical.is_dir() {
                return Err("parent is not a directory".into());
            }
            let mut resolved = canonical.clone();
            for part in suffix.iter().rev() {
                resolved.push(part);
            }
            let directory = if canonical.is_dir() {
                canonical.as_path()
            } else {
                canonical.parent().ok_or("no parent")?
            };
            let ancestry = directory
                .ancestors()
                .map(object)
                .collect::<Result<Vec<_>>>()?;
            let mut git = Vec::new();
            for ancestor in directory.ancestors() {
                let marker = ancestor.join(".git");
                if fs::symlink_metadata(&marker).is_ok() {
                    let gitdir = if marker.is_dir() {
                        marker.canonicalize()?
                    } else {
                        let text = bounded_text(&marker)?;
                        ancestor
                            .join(
                                text.trim()
                                    .strip_prefix("gitdir: ")
                                    .ok_or("invalid gitdir")?,
                            )
                            .canonicalize()?
                    };
                    let common = gitdir.join("commondir");
                    let common = if common.exists() {
                        gitdir.join(bounded_text(&common)?.trim()).canonicalize()?
                    } else {
                        gitdir.clone()
                    };
                    if !gitdir.is_dir() || !common.is_dir() {
                        return Err("Git scopes must be directories".into());
                    }
                    git.push((gitdir.clone(), object(&gitdir)?));
                    git.push((common.clone(), object(&common)?));
                    // Worktree identity is independent of common-dir identity.
                    git.push((ancestor.to_owned(), object(ancestor)?));
                    break;
                }
            }
            Ok(Self {
                path: resolved,
                identity_path: canonical.clone(),
                identity: object(&canonical)?,
                exact: suffix.is_empty(),
                directory: suffix.is_empty() && canonical.is_dir(),
                ancestry,
                git,
            })
        }
        fn stable(&self) -> bool {
            object(&self.identity_path).is_ok_and(|v| v == self.identity)
                && self
                    .git
                    .iter()
                    .all(|(p, id)| object(p).is_ok_and(|v| v == *id))
        }
        fn conflicts(&self, other: &Self) -> bool {
            self.path.starts_with(&other.path)
                || other.path.starts_with(&self.path)
                || (other.directory && self.ancestry.contains(&other.identity))
                || (self.directory && other.ancestry.contains(&self.identity))
                || (self.exact && other.exact && self.identity == other.identity)
                || self.git.iter().any(|(_, id)| {
                    other.git.iter().any(|(_, v)| v == id)
                        || other.ancestry.contains(id)
                        || other.identity == *id
                })
                || other
                    .git
                    .iter()
                    .any(|(_, id)| self.ancestry.contains(id) || self.identity == *id)
        }
    }
    fn bounded_text(path: &Path) -> Result<String> {
        if !fs::metadata(path)?.is_file() {
            return Err("Git pointer must be a regular file".into());
        }
        let mut s = String::new();
        fs::File::open(path)?.take(4097).read_to_string(&mut s)?;
        if s.len() > 4096 {
            return Err("git metadata limit".into());
        }
        Ok(s)
    }
    fn now() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
    fn random() -> Result<String> {
        let mut b = [0u8; 32];
        fs::File::open("/dev/urandom")?.read_exact(&mut b)?;
        Ok(b.iter().map(|v| format!("{v:02x}")).collect())
    }
    fn sweep(db: &Connection) -> Result<()> {
        db.execute(
            "UPDATE admissions SET state='quarantine' WHERE state='active' AND deadline<=?",
            [now() as i64],
        )?;
        Ok(())
    }
    fn acquire(
        db: &mut Connection,
        owner: &str,
        request: Option<(PathBuf, Kind)>,
    ) -> Result<Option<String>> {
        let scope = request
            .as_ref()
            .map(|(path, _)| Scope::resolve(path))
            .transpose()?;
        if request
            .as_ref()
            .is_some_and(|(_, kind)| matches!(kind, Kind::Native))
            && !scope.as_ref().is_some_and(|s| s.directory)
        {
            return Err("native writer requires an existing directory".into());
        }
        let tx = db.transaction()?;
        let count: i64 = tx.query_row("SELECT count(*) FROM admissions", [], |r| r.get(0))?;
        if count >= MAX_ROWS {
            return Err("admission capacity".into());
        }
        {
            let mut stmt = tx.prepare("SELECT scope FROM admissions")?;
            for row in stmt.query_map([], |r| r.get::<_, String>(0))? {
                let old: Option<Scope> = serde_json::from_str(&row?)?;
                if old.as_ref().is_some_and(|s| !s.stable()) {
                    return Err("namespace changed; local reconciliation required".into());
                }
                if scope
                    .as_ref()
                    .zip(old.as_ref())
                    .is_none_or(|(a, b)| a.conflicts(b))
                {
                    return Err("conflicting writer fenced".into());
                }
            }
        }
        let token = random()?;
        tx.execute(
            "INSERT INTO admissions VALUES(?,?,?,'active',?)",
            params![
                token,
                owner,
                serde_json::to_string(&scope)?,
                (now() + LEASE_MS) as i64
            ],
        )?;
        tx.commit()?;
        Ok(Some(token))
    }
    fn dispatch(db: &mut Connection, owner: &str, req: Request) -> Result<Option<String>> {
        sweep(db)?;
        match req {
            Request::Acquire { path, kind } => acquire(db, owner, Some((path, kind))),
            Request::AcquireUnscoped {} => acquire(db, owner, None),
            Request::Renew { token } => {
                if db.execute(
                    "UPDATE admissions SET deadline=? WHERE token=? AND owner=? AND state='active'",
                    params![(now() + LEASE_MS) as i64, token, owner],
                )? != 1
                {
                    return Err("not active owner".into());
                }
                Ok(None)
            }
            Request::Finish { token } => {
                // A settled completion assertion is accepted only on the original live connection.
                if db.execute(
                    "DELETE FROM admissions WHERE token=? AND owner=? AND state='active'",
                    params![token, owner],
                )? != 1
                {
                    return Err("not active owner".into());
                }
                Ok(None)
            }
            Request::Reconcile {
                token,
                confirmed_terminated,
            } => {
                if !confirmed_terminated {
                    return Err("confirmed termination required".into());
                }
                if db.execute(
                    "DELETE FROM admissions WHERE token=? AND state='quarantine'",
                    [token],
                )? != 1
                {
                    return Err("not quarantined".into());
                }
                Ok(None)
            }
        }
    }
    struct ConnectionGuard {
        db: Arc<Mutex<Connection>>,
        owner: String,
        count: Arc<AtomicUsize>,
    }
    impl Drop for ConnectionGuard {
        fn drop(&mut self) {
            if let Ok(db) = self.db.lock() {
                let _ = db.execute(
                    "UPDATE admissions SET state='quarantine' WHERE owner=? AND state='active'",
                    [&self.owner],
                );
            }
            self.count.fetch_sub(1, Ordering::SeqCst);
        }
    }
    fn serve(mut stream: UnixStream, guard: ConnectionGuard) -> Result<()> {
        if !endpoint::same_uid(&stream)? {
            return Err("peer UID mismatch".into());
        }
        stream.set_read_timeout(Some(Duration::from_millis(LEASE_MS)))?;
        stream.set_write_timeout(Some(Duration::from_millis(500)))?;
        for _ in 0..256 {
            let req = read_frame(&mut stream)?;
            let result = dispatch(
                &mut *guard.db.lock().map_err(|_| "state poisoned")?,
                &guard.owner,
                req,
            );
            let reply = match result {
                Ok(token) => Reply {
                    ok: true,
                    token,
                    error: None,
                },
                Err(e) => Reply {
                    ok: false,
                    token: None,
                    error: Some(e.to_string()),
                },
            };
            write_frame(&mut stream, &reply)?;
        }
        Ok(())
    }
    pub fn host(directory: &Path) -> Result<()> {
        let endpoint = endpoint::Endpoint::bind(directory)?;
        let db = Connection::open(directory.join("admission.sqlite"))?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL; CREATE TABLE IF NOT EXISTS admissions(token TEXT PRIMARY KEY,owner TEXT NOT NULL,scope TEXT NOT NULL,state TEXT NOT NULL CHECK(state IN ('active','quarantine')),deadline INTEGER NOT NULL); UPDATE admissions SET state='quarantine';")?;
        let db = Arc::new(Mutex::new(db));
        let count = Arc::new(AtomicUsize::new(0));
        let sweep_db = db.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(Duration::from_millis(100));
                if let Ok(db) = sweep_db.lock() {
                    let _ = sweep(&db);
                }
            }
        });
        for stream in endpoint.listener.incoming() {
            let stream = stream?;
            if count.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
                continue;
            }
            count.fetch_add(1, Ordering::SeqCst);
            let guard = ConnectionGuard {
                db: db.clone(),
                owner: random()?,
                count: count.clone(),
            };
            std::thread::spawn(move || {
                let _ = serve(stream, guard);
            });
        }
        Ok(())
    }
}
#[cfg(feature = "host")]
pub use authority::host;

pub use client::{Kind, Reply, Request, connect, send};
