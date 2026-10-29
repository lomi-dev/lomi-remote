//! Test-only canonical proof bridge. Never use these public fixture seeds in a host.
use lomi_remote_crypto::{
    EnrollmentChallenge, Identity, PendingHostIdentity, Role, SignedEnrollmentProof,
    SignedHostKeyCommitment,
};
use serde::Deserialize;
use std::io::{self, Read};
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Verification {
    proof: SignedEnrollmentProof,
    expected: EnrollmentChallenge,
    now: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyInit {
    signed: SignedHostKeyCommitment,
    pin: [u8; 32],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AccountBinding {
    signed: SignedHostKeyCommitment,
    pin: [u8; 32],
    account: [u8; 16],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingProof {
    account: [u8; 16],
    pin: [u8; 32],
    expected: EnrollmentChallenge,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommittedVerification {
    proof: SignedEnrollmentProof,
    expected: EnrollmentChallenge,
    signed: SignedHostKeyCommitment,
    pin: [u8; 32],
    account: [u8; 16],
    now: u64,
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).ok_or("missing fixture mode")?;
    if mode == "pending-host" {
        let signed = PendingHostIdentity::fixture(17)?.signed_commitment()?;
        let pin = signed.descriptor.commitment()?;
        println!("{}", serde_json::json!({"signed":signed,"pin":pin}));
        return Ok(());
    }
    let host = Identity::fixture(Role::Host, 17)?;
    if mode == "fingerprint" {
        println!(
            "{}",
            serde_json::to_string(&host.public_bundle().bundle.fingerprint()?)?
        );
        return Ok(());
    }
    if mode == "bundle" {
        println!("{}", serde_json::to_string(&host.public_bundle())?);
        return Ok(());
    }
    let mut input = String::new();
    io::stdin().take(16385).read_to_string(&mut input)?;
    if input.len() > 16384 {
        return Err("fixture input exceeds limit".into());
    }
    match mode.as_str() {
        "verify-host-key" => {
            let request: KeyInit = serde_json::from_str(&input)?;
            request.signed.verify(&request.pin)?;
            println!(
                "{}",
                serde_json::json!({"descriptor":request.signed.descriptor,"commitment":request.pin})
            );
        }
        "derive-host-binding" => {
            let request: AccountBinding = serde_json::from_str(&input)?;
            request.signed.verify(&request.pin)?;
            let bundle = request
                .signed
                .descriptor
                .account_bound_bundle(request.account)?;
            let fingerprint = bundle.fingerprint()?;
            println!(
                "{}",
                serde_json::json!({"bundle":bundle,"fingerprint":fingerprint})
            );
        }
        "pending-sign" => {
            let request: PendingProof = serde_json::from_str(&input)?;
            let pending = PendingHostIdentity::fixture(17)?;
            let finalized = pending.finalize(request.account, &request.pin)?;
            let proof = finalized.sign_enrollment_proof(&request.expected)?;
            println!("{}", serde_json::to_string(&proof)?);
        }
        "verify-committed" => {
            let request: CommittedVerification = serde_json::from_str(&input)?;
            request.proof.verify_committed_host(
                &request.expected,
                &request.signed,
                &request.pin,
                request.account,
                request.now,
            )?;
            println!("verified");
        }
        "sign" => {
            let expected: EnrollmentChallenge = serde_json::from_str(&input)?;
            println!(
                "{}",
                serde_json::to_string(&host.sign_enrollment_proof(&expected)?)?
            );
        }
        "verify" => {
            let request: Verification = serde_json::from_str(&input)?;
            let bundle = host.public_bundle();
            request.proof.verify(
                &request.expected,
                &bundle,
                &bundle.bundle.fingerprint()?,
                request.now,
            )?;
            println!("verified");
        }
        _ => return Err("unsupported fixture mode".into()),
    }
    Ok(())
}
fn main() {
    if run().is_err() {
        // Never echo proof, input or credential data in errors.
        eprintln!("synthetic enrollment proof rejected");
        std::process::exit(1);
    }
}
