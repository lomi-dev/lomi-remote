//! Debug-only extra trust anchor for a local development stack (for example a
//! Caddy `tls internal` CA). This module is compiled out of release builds.
//! Certificate and hostname verification stay enabled; the CA is only added to
//! the root store. Any misconfiguration fails closed.
use super::{Error, Result};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use std::path::Path;

const ENV: &str = "LOMI_REMOTE_DEV_EXTRA_CA";

/// `None` when the variable is unset; an error when it is set but unusable.
pub(crate) fn extra_roots() -> Result<Option<Vec<CertificateDer<'static>>>> {
    let Some(path) = std::env::var_os(ENV) else {
        return Ok(None);
    };
    load(Path::new(&path)).map(Some)
}

fn load(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    if !path.is_absolute() {
        return Err(Error::InvalidConfig);
    }
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(|iter| iter.collect::<std::result::Result<Vec<_>, _>>())
        .map_err(|_| Error::InvalidConfig)?;
    if certs.is_empty() {
        return Err(Error::InvalidConfig);
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "-----BEGIN CERTIFICATE-----
MIIB+zCCAaICCQDwyhXUT4UXEDAKBggqhkjOPQQDAjAMMQowCAYDVQQDDAF0MB4XDTI2MTEyNjIxMDgzMFoXDTM2MTEyMzIxMDgzMFowDDEKMAgGA1UEAwwBdDCCAUswggEDBgcqhkjOPQIBMIH3AgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP///////////////zBbBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsDFQDEnTYIhucEk2pmeOETnSa3gZ9+kARBBGsX0fLhLEJH+Lzm5WOkQPJ3A32BLeszoPShOUXYmMKWT+NC4v4af5uO5+tKfA+eFivOM1drMV7Oy7ZAaDe/UfUCIQD/////AAAAAP//////////vOb6racXnoTzucrC/GMlUQIBAQNCAAQ/RbKuxumzeqLLBYY4za+ICBscrjv3zubP1TAXTfny/GlszQJPmesPQeR+vCWH6EEZDmTHkv9VNhTmC3RB8JLcMAoGCCqGSM49BAMCA0cAMEQCIHe0K6IHYsA+2gjXCtQd+g/1/SZ951ydfG4/22a+d9ZyAiAqN7glXvzbnj4mN5IiTyOE8XlzdHX6GDdZ2StGgC+OdA==
-----END CERTIFICATE-----
";

    fn temp(name: &str, body: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("lomi-dev-ca-{}-{name}", std::process::id()));
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn loads_every_certificate_in_a_pem_file() {
        let path = temp("ok.pem", &format!("{CERT}{CERT}"));
        assert_eq!(load(&path).unwrap().len(), 2);
    }

    #[test]
    fn invalid_missing_empty_or_relative_files_fail_closed() {
        let garbage = temp("bad.pem", "not a pem");
        let empty = temp("empty.pem", "");
        let bad_base64 = temp(
            "b64.pem",
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        );
        for path in [garbage, empty, bad_base64, "/nonexistent/ca.pem".into()] {
            assert!(matches!(load(&path), Err(Error::InvalidConfig)));
        }
        assert!(matches!(
            load(Path::new("relative.pem")),
            Err(Error::InvalidConfig)
        ));
    }
}
