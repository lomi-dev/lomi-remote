//! Small malicious WASI fixture. No host authority is inferred from Rust APIs.
use std::{fs, hint::black_box, io::Write};
fn recurse(depth: u64) -> u64 {
    let bytes = black_box([1u8; 1]);
    if black_box(depth) == u64::MAX {
        return 0;
    }
    recurse(depth + 1) + black_box(bytes[0] as u64)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mode = fs::read_to_string("/snapshot/mode")?;
    match mode.as_str() {
        "denial" => {
            assert_eq!(fs::read_to_string("/snapshot/inside")?, "synthetic inside");
            for path in [
                "/outside-canary",
                "/snapshot/../outside-canary",
                "/snapshot/escape",
                "/snapshot/escape-dir/outside-canary",
            ] {
                assert!(fs::read(path).is_err(), "outside content read");
                assert!(fs::metadata(path).is_err(), "outside metadata read");
            }
            assert!(fs::write("/snapshot/write-marker", b"denied").is_err());
            assert!(fs::write("/snapshot/inside", b"denied").is_err());
            assert!(fs::create_dir("/snapshot/new-directory").is_err());
            assert!(fs::remove_file("/snapshot/inside").is_err());
            assert!(fs::rename("/snapshot/inside", "/snapshot/moved").is_err());
            assert!(std::env::var("LOMI_PRIVATE_CANARY").is_err());
            assert_eq!(std::env::args_os().count(), 0);
            assert!(
                std::process::Command::new("/bin/sh")
                    .args(["-c", "touch /snapshot/helper-marker"])
                    .status()
                    .is_err()
            );
            assert!(std::net::TcpStream::connect("127.0.0.1:9").is_err());
            println!("sandbox_denial_probe_passed");
        }
        "fuel" => loop {
            black_box(1u64.wrapping_add(black_box(2)));
        },
        "memory" => {
            let bytes = vec![black_box(1u8); 256 * 1024 * 1024];
            black_box(bytes);
        }
        "output" => loop {
            std::io::stdout().write_all(&[b'x'; 4096])?;
        },
        "stack" => {
            black_box(recurse(0));
        }
        _ => return Err("unknown fixed probe mode".into()),
    }
    Ok(())
}
