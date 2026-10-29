#[cfg(feature = "test-fixtures")]
fn main() {
    use lomi_remote_crypto::*;
    let host = Identity::fixture(Role::Host, 11).unwrap();
    let device = Identity::fixture(Role::Device, 21).unwrap();
    let hb = host.public_bundle();
    let db = device.public_bundle();
    let base = PeerApproval {
        version: 2,
        account_id: [1; 16],
        host_id: [2; 16],
        device_id: [3; 16],
        host_fingerprint: hb.bundle.fingerprint().unwrap(),
        device_fingerprint: db.bundle.fingerprint().unwrap(),
        pairing_nonce: [8; 32],
        grant_id: [4; 16],
        workspace_id: Some([9; 16]),
        workspace_epoch: Some([10; 16]),
        session_ids: vec![[6; 16]],
        session_epochs: vec![[11; 16]],
        permissions: Permissions::Control,
        access_epoch: 1,
        revision: 2,
        expires_at: 2000,
    };
    let terminal = ChannelContext {
        version: 2,
        account_id: [1; 16],
        host_id: [2; 16],
        device_id: [3; 16],
        initiator_role: Role::Device,
        responder_role: Role::Host,
        channel_id: [5; 16],
        grant_id: [4; 16],
        session_id: [6; 16],
        access_epoch: 1,
        revision: 2,
        workspace_id: Some([9; 16]),
        workspace_epoch: Some([10; 16]),
        session_epoch: Some([11; 16]),
        purpose: Some(ChannelPurpose::Terminal),
    };
    let hex = |bytes: &[u8]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    let vector = |approval: PeerApproval, context: ChannelContext| {
        context.validate_approval(&approval).unwrap();
        let signed = host.sign_peer_approval(approval).unwrap();
        serde_json::json!({"approval_canonical_hex":hex(&signed.approval.canonical().unwrap()),
            "context_canonical_hex":hex(&context.canonical().unwrap()), "approval":signed,"context":context})
    };
    let terminal_vector = vector(base.clone(), terminal.clone());
    let mut empty = base;
    empty.session_ids.clear();
    empty.session_epochs.clear();
    let mut metadata = terminal;
    metadata.session_id = [9; 16];
    metadata.session_epoch = Some([10; 16]);
    metadata.purpose = Some(ChannelPurpose::Metadata);
    println!(
        "{}",
        serde_json::json!({"host_bundle":hb,"device_bundle":db,
        "host_pin":hb.bundle.fingerprint().unwrap(),"device_pin":db.bundle.fingerprint().unwrap(),
        "terminal":terminal_vector,"metadata":vector(empty,metadata)})
    );
}
#[cfg(not(feature = "test-fixtures"))]
fn main() {
    panic!("requires test-fixtures");
}
