#[cfg(feature = "test-fixtures")]
fn main() {
    use lomi_remote_crypto::*;
    use std::io::Read;
    let host = Identity::fixture(Role::Host, 11).unwrap();
    let mut device = Identity::fixture(Role::Device, 21).unwrap();
    let hb = host.public_bundle();
    let db = device.public_bundle();
    let policy = MailboxPolicy {
        account_id: [1; 16],
        sender_host_id: [2; 16],
        recipient_device_id: [3; 16],
        grant_ref: [4; 16],
        access_epoch: 1,
        grant_revision: 1,
        grant_deadline: 2000,
    };
    if std::env::args().nth(1).as_deref() == Some("verify") {
        let mut input = String::new();
        std::io::stdin()
            .take(MAX_JSON as u64 + 1)
            .read_to_string(&mut input)
            .unwrap();
        assert!(input.len() <= MAX_JSON);
        let envelope: Envelope = serde_json::from_str(&input).unwrap();
        let plaintext = device
            .open_mailbox(
                &envelope,
                &hb,
                &hb.bundle.fingerprint().unwrap(),
                &policy,
                1100,
            )
            .unwrap();
        assert_eq!(&*plaintext, b"browser-to-native");
        println!("browser-to-native verified");
        return;
    }
    let envelope = host
        .seal_mailbox(
            &db,
            &db.bundle.fingerprint().unwrap(),
            &policy,
            1000,
            1500,
            b"native-to-browser",
        )
        .unwrap();
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
    let approval = host
        .sign_peer_approval(PeerApproval {
            version: 1,
            account_id: [1; 16],
            host_id: [2; 16],
            device_id: [3; 16],
            host_fingerprint: hb.bundle.fingerprint().unwrap(),
            device_fingerprint: db.bundle.fingerprint().unwrap(),
            pairing_nonce: [8; 32],
            grant_id: [4; 16],
            session_ids: vec![[6; 16]],
            workspace_id: None,
            workspace_epoch: None,
            session_epochs: vec![],
            permissions: Permissions::Control,
            access_epoch: 1,
            revision: 1,
            expires_at: 2000,
        })
        .unwrap();
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    println!(
        "{}",
        serde_json::json!({"host_bundle":hb,"device_bundle":db,"host_pin":hb.bundle.fingerprint().unwrap(),"device_pin":db.bundle.fingerprint().unwrap(),"host_canonical":hb.bundle.canonical().unwrap(),"device_canonical":db.bundle.canonical().unwrap(),"context":context,"policy":policy,"envelope":envelope,"approval":approval,"approval_canonical_hex":hex(&approval.approval.canonical().unwrap()),"host_canonical_hex":hex(&hb.bundle.canonical().unwrap()),"device_canonical_hex":hex(&db.bundle.canonical().unwrap()),"pairing_fingerprint_hex":hex(&pairing_fingerprint(&[1;16],&[2;16],&[3;16],&hb.bundle.fingerprint().unwrap(),&db.bundle.fingerprint().unwrap(),&[8;32]))})
    );
}
#[cfg(not(feature = "test-fixtures"))]
fn main() {
    eprintln!("requires --features test-fixtures");
    std::process::exit(1);
}
