//! Opt-in E0 bridge. No environment or IPC access in default builds.
use lomi_admission_spike::{connect, send, Kind, Request};
use std::{os::unix::net::UnixStream, path::Path, sync::Mutex};

pub(crate) struct Admission {
    connection: Mutex<UnixStream>,
    token: String,
    synchronous: bool,
}
impl Admission {
    pub(crate) fn acquire(path: Option<&Path>, native: bool) -> Result<Self, String> {
        let directory = std::env::var_os("LOMI_E0_ADMISSION_DIRECTORY")
            .ok_or("E0 admission host is required")?;
        let mut connection =
            connect(Path::new(&directory)).map_err(|_| "E0 admission unavailable")?;
        let request = match path {
            Some(path) => Request::Acquire {
                path: path.into(),
                kind: if native { Kind::Native } else { Kind::File },
            },
            None => Request::AcquireUnscoped {},
        };
        let reply = send(&mut connection, &request).map_err(|_| "E0 admission unavailable")?;
        if !reply.ok {
            return Err("E0 conflicting or uncertain writer".into());
        }
        Ok(Self {
            connection: Mutex::new(connection),
            token: reply.token.ok_or("E0 missing token")?,
            synchronous: false,
        })
    }
    pub(crate) fn known_in_process(&mut self) {
        self.synchronous = true;
    }
    pub(crate) fn check(&self) -> Result<(), String> {
        let mut connection = self
            .connection
            .lock()
            .map_err(|_| "E0 admission unavailable")?;
        let reply = send(
            &mut connection,
            &Request::Renew {
                token: self.token.clone(),
            },
        )
        .map_err(|_| "E0 admission unavailable")?;
        if reply.ok {
            Ok(())
        } else {
            Err("E0 native admission revoked".into())
        }
    }
    pub(crate) fn token(&self) -> &str {
        &self.token
    }
}
impl Drop for Admission {
    fn drop(&mut self) {
        // A Rust lease destructor never proves an external child has stopped.
        if self.synchronous {
            if let Ok(connection) = self.connection.get_mut() {
                let _ = send(
                    connection,
                    &Request::Finish {
                        token: self.token.clone(),
                    },
                );
            }
        }
    }
}
