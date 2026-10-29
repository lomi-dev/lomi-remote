#[cfg(feature = "test-fixtures")]
fn main() {
    use lomi_remote_crypto::*;
    use std::io::{BufRead, Write};
    let host = Identity::fixture(Role::Host, 11).unwrap();
    let device = Identity::fixture(Role::Device, 21).unwrap();
    let db = device.public_bundle();
    let context = ChannelContext {
        version: 1,
        account_id: [1; 16],
        host_id: [2; 16],
        device_id: [3; 16],
        initiator_role: Role::Device,
        responder_role: Role::Host,
        channel_id: [5; 16],
        grant_id: [4; 16],
        session_id: [6; 16],
        workspace_id: None,
        workspace_epoch: None,
        session_epoch: None,
        purpose: None,
        access_epoch: 1,
        revision: 1,
    };
    let mut handshake = Some(
        Handshake::new(
            false,
            &host,
            &context,
            &db,
            &db.bundle.fingerprint().unwrap(),
        )
        .unwrap(),
    );
    let mut channel: Option<Channel> = None;
    for line in std::io::stdin().lock().lines() {
        let command: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let bytes = || serde_json::from_value::<Vec<u8>>(command["bytes"].clone()).unwrap();
        let result: Result<Vec<u8>> = match command["op"].as_str().unwrap() {
            "read" => handshake.as_mut().unwrap().read(&bytes()).map(|_| vec![]),
            "write" => handshake.as_mut().unwrap().write(),
            "finish" => handshake.take().unwrap().finish().map(|c| {
                let h = c.transcript_hash.to_vec();
                channel = Some(c);
                h
            }),
            "seal" => channel.as_mut().unwrap().seal_binary([9; 16], &bytes()),
            "open" => channel
                .as_mut()
                .unwrap()
                .open_binary([9; 16], &bytes())
                .map(|p| p.to_vec()),
            "dispose" => {
                if let Some(h) = handshake.as_mut() {
                    h.dispose();
                }
                if let Some(c) = channel.as_mut() {
                    c.dispose();
                }
                Ok(vec![])
            }
            _ => Err("unknown operation".into()),
        };
        println!("{}", serde_json::to_string(&result).unwrap());
        std::io::stdout().flush().unwrap();
    }
}
#[cfg(not(feature = "test-fixtures"))]
fn main() {
    panic!("requires test-fixtures");
}
