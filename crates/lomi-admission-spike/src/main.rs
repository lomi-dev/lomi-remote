use lomi_admission_spike::{Kind, Request, host, send};
use std::{
    io::{self, BufRead, Write},
    os::unix::net::UnixStream,
    path::Path,
};
fn run() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("host") => host(Path::new(args.get(2).ok_or("directory required")?)),
        Some("writer") => {
            let mut stream = Some(UnixStream::connect(Path::new(&args[2]).join("host.sock"))?);
            let reply = send(
                stream.as_mut().unwrap(),
                &Request::Acquire {
                    path: args[3].clone().into(),
                    kind: Kind::Native,
                },
            )?;
            println!("{}", serde_json::to_string(&reply)?);
            io::stdout().flush()?;
            let token = reply.token.ok_or("writer denied")?;
            for line in io::stdin().lock().lines() {
                match line?.as_str() {
                    "disconnect" => {
                        stream.take();
                        println!("disconnected");
                    }
                    "finish" => {
                        let reply = send(
                            stream.as_mut().ok_or("disconnected")?,
                            &Request::Finish {
                                token: token.clone(),
                            },
                        )?;
                        println!("{}", serde_json::to_string(&reply)?);
                    }
                    "exit" => break,
                    _ => return Err("unknown writer command".into()),
                }
                io::stdout().flush()?;
            }
            Ok(())
        }
        Some("request") => {
            let mut stream = UnixStream::connect(Path::new(&args[2]).join("host.sock"))?;
            let req: Request = serde_json::from_str(&args[3])?;
            let reply = send(&mut stream, &req)?;
            if let Some(token) = &reply.token {
                let _ = send(
                    &mut stream,
                    &Request::Finish {
                        token: token.clone(),
                    },
                )?;
            }
            println!("{}", serde_json::to_string(&reply)?);
            Ok(())
        }
        _ => Err(
            "usage: lomi-admission-spike host DIR | writer DIR PROJECT | request DIR JSON".into(),
        ),
    }
}
fn main() {
    if let Err(e) = run() {
        eprintln!("admission spike: {e}");
        std::process::exit(1)
    }
}
