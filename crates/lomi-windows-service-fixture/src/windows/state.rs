use super::native::*;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    ptr,
};
use uuid::Uuid;
use windows_sys::Win32::{Security::Cryptography::*, Storage::FileSystem::*};

#[derive(Clone)]
pub struct Config {
    pub run: String,
    pub operator: String,
    pub directory: PathBuf,
}
impl Config {
    pub fn new(run: &str, operator: &str) -> Result<Self> {
        if Uuid::parse_str(run).map(|u| u.to_string()).ok().as_deref() != Some(run)
            || !operator.starts_with("S-1-5-21-")
            || operator.len() > 128
            || !operator[2..]
                .bytes()
                .all(|b| b.is_ascii_digit() || b == b'-')
        {
            return Err(denied("invalid fixture identity"));
        }
        // Installer and service agree on this fixed, dedicated synthetic root.
        let directory = PathBuf::from(r"C:\ProgramData\LomiWindowsFixture").join(run);
        Ok(Self {
            run: run.into(),
            operator: operator.into(),
            directory,
        })
    }
    pub fn name(&self) -> String {
        format!("LomiFixture-{}", self.run)
    }
    pub fn pipe(&self) -> String {
        format!(r"\\.\pipe\LomiFixture-{}", self.run)
    }
    pub fn directory_security(&self) -> Result<Security> {
        Security::new(&format!(
            "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;LS)(A;OICI;FA;;;{})",
            self.operator
        ))
    }
    pub fn pipe_security(&self) -> Result<Security> {
        Security::new(&format!(
            "D:P(A;;GA;;;SY)(A;;GA;;;LS)(A;;GA;;;{})",
            self.operator
        ))
    }
    pub fn validate_directory(&self) -> Result<()> {
        for path in [
            Path::new(r"C:\"),
            Path::new(r"C:\ProgramData"),
            Path::new(r"C:\ProgramData\LomiWindowsFixture"),
            &self.directory,
        ] {
            let metadata = fs::symlink_metadata(path)?;
            if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            {
                return Err(denied("invalid fixture directory chain"));
            }
        }
        check_owner(Path::new(r"C:\ProgramData"), &["S-1-5-18", "S-1-5-32-544"])?;
        no_untrusted_parent_delete(Path::new(r"C:\ProgramData"))?;
        let parent = Path::new(r"C:\ProgramData\LomiWindowsFixture");
        check_owner(parent, &["S-1-5-32-544"])?;
        check_directory_acl(
            parent,
            &Security::new("D:P(A;OICI;FA;;;SY)(A;;0x1200a9;;;LS)(A;OICI;FA;;;BA)")?,
        )?;
        check_directory_acl(&self.directory, &self.directory_security()?)
    }
}
pub fn open_regular(path: &Path, write: bool, create: bool, exclusive: bool) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .create_new(create)
        .share_mode(if exclusive { 0 } else { FILE_SHARE_READ })
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file() || m.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(denied("invalid fixture file"));
    }
    Ok(file)
}
pub fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = open_regular(path, false, false, false)?;
    let mut bytes = Vec::new();
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(denied("fixture file exceeds bound"));
    }
    Ok(bytes)
}
pub fn atomic_file(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = directory.join(format!("{}.tmp", Uuid::new_v4()));
    let result = (|| {
        let mut file = open_regular(&temporary, true, true, true)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        unsafe {
            check(MoveFileExW(
                wide(&temporary).as_ptr(),
                wide(directory.join(name)).as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            ))
        }
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    version: u8,
    epoch: String,
}
pub fn previous(config: &Config) -> Result<Option<String>> {
    let bytes = match read_bounded(&config.directory.join("session.json")) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    let descriptor: Descriptor =
        serde_json::from_slice(&bytes).map_err(|_| denied("invalid descriptor"))?;
    if descriptor.version != 1 || Uuid::parse_str(&descriptor.epoch).is_err() {
        return Err(denied("invalid descriptor"));
    }
    Ok(Some(descriptor.epoch))
}
pub fn persist(config: &Config, epoch: &str) -> Result<()> {
    let bytes = serde_json::to_vec(&Descriptor {
        version: 1,
        epoch: epoch.into(),
    })
    .map_err(|_| denied("descriptor encode"))?;
    atomic_file(&config.directory, "session.json", &bytes)
}
fn erase(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}
fn crypt(bytes: &mut [u8], protect: bool) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_mut_ptr(),
    };
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    };
    let ok = unsafe {
        if protect {
            CryptProtectData(
                &input,
                ptr::null(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &input,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
                ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    erase(bytes);
    check(ok)?;
    let _guard = Local(output.pbData.cast());
    if output.cbData > 4096 {
        return Err(denied("DPAPI allocation exceeds fixture bound"));
    }
    let foreign = unsafe { std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize) };
    let copied = foreign.to_vec();
    erase(foreign);
    Ok(copied)
}
pub fn decrypt_synthetic(path: &Path) -> Result<()> {
    let mut encrypted = read_bounded(path)?;
    let mut plain = crypt(&mut encrypted, false)?;
    let valid =
        plain.len() == b"LOMI-SYNTHETIC-V1:".len() + 32 && plain.starts_with(b"LOMI-SYNTHETIC-V1:");
    erase(&mut plain);
    if !valid {
        return Err(denied("synthetic DPAPI payload invalid"));
    }
    Ok(())
}
pub fn dpapi(config: &Config) -> Result<bool> {
    let path = config.directory.join("dpapi.bin");
    match read_bounded(&path) {
        Ok(_) => {
            decrypt_synthetic(&path)?;
            atomic_file(&config.directory, "initialized", b"synthetic-dpapi-v1\n")?;
            match fs::remove_file(config.directory.join("bootstrap.pending")) {
                Ok(()) => (),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
                Err(error) => return Err(error),
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Only the explicitly installed one-time bootstrap marker permits
            // creation. Missing ciphertext on later service starts is an error.
            if config.directory.join("initialized").try_exists()? {
                return Err(denied("initialized DPAPI ciphertext missing"));
            }
            let marker = config.directory.join("bootstrap.pending");
            if read_bounded(&marker)? != b"synthetic-bootstrap-v1\n" {
                return Err(denied("invalid bootstrap marker"));
            }
            let mut secret = b"LOMI-SYNTHETIC-V1:".to_vec();
            secret.extend_from_slice(Uuid::new_v4().as_bytes());
            secret.extend_from_slice(Uuid::new_v4().as_bytes());
            let encrypted = crypt(&mut secret, true)?;
            atomic_file(&config.directory, "dpapi.bin", &encrypted)?;
            decrypt_synthetic(&path)?;
            atomic_file(&config.directory, "initialized", b"synthetic-dpapi-v1\n")?;
            fs::remove_file(marker)?;
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
