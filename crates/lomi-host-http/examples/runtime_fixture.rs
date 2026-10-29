//! Private PostgreSQL E2 driver. Input comes only from the owning Bun fixture;
//! output is closed markers and never includes credentials or response bodies.
use lomi_host_auth::Config;
use lomi_host_http::{DataFailure, DataTransport, Error, RemoteApiOrigin};
use lomi_remote_protocol::*;
use serde::Deserialize;
use std::{
    io::{self, Read},
    path::PathBuf,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[serde(rename_all = "camelCase")]
struct Input {
    mode: String,
    origin: String,
    host_id: String,
    access: String,
    root_der_path: PathBuf,
    #[serde(default)]
    binding: Option<RuntimeBinding>,
    #[serde(default)]
    expected_publication_seq: Option<String>,
}

fn run(input: Input) -> Result<&'static str, Error> {
    let host = HostId::try_from(input.host_id).map_err(|_| Error::InvalidConfig)?;
    let identity = Config::new(
        host,
        ipc::IpcProfileId::from_bytes([2; 16]).map_err(|_| Error::InvalidConfig)?,
        "https://identity.example".to_owned(),
        "runtime_fixture"
            .to_owned()
            .try_into()
            .map_err(|_| Error::InvalidConfig)?,
    )
    .map_err(|_| Error::InvalidConfig)?;
    let origin = RemoteApiOrigin::new(&identity, input.origin).map_err(|_| Error::InvalidConfig)?;
    let root = std::fs::read(input.root_der_path).map_err(|_| Error::InvalidConfig)?;
    let transport = DataTransport::with_test_root(origin, root)?;
    let access = HostAccessCredential::try_from(input.access).map_err(|_| Error::InvalidConfig)?;
    if input.mode == "deny-get" {
        return match transport.runtime_get(host, &access) {
            Err(Error::DataRemote(DataFailure::AuthRequired)) => Ok("oldTokenDenied"),
            _ => Err(Error::InvalidResponse),
        };
    }
    if input.mode != "exercise" {
        return Err(Error::InvalidConfig);
    }
    let binding = input.binding.ok_or(Error::InvalidConfig)?;
    let expected = input
        .expected_publication_seq
        .ok_or(Error::InvalidConfig)?
        .parse::<u64>()
        .map_err(|_| Error::InvalidConfig)?;
    let snapshot = transport.runtime_get(host, &access)?;
    if snapshot.host_id != host
        || snapshot.runtime.as_ref() != Some(&binding)
        || snapshot.publication_seq.0 != expected
    {
        return Err(Error::InvalidResponse);
    }
    let heartbeat = transport.heartbeat(
        host,
        &HeartbeatParams {
            runtime: binding.clone(),
        },
        &access,
    )?;
    if heartbeat.runtime != binding {
        return Err(Error::InvalidResponse);
    }
    let publication = transport.publication(
        host,
        &PublicationParams {
            runtime: binding.clone(),
            expected_publication_seq: DecimalU64(expected),
            publication_seq: DecimalU64(expected.checked_add(1).ok_or(Error::InvalidConfig)?),
            workspaces: Vec::<PublishedWorkspace>::new()
                .try_into()
                .map_err(|_| Error::InvalidConfig)?,
        },
        &access,
    )?;
    if publication.runtime != binding || publication.publication_seq.0 != expected + 1 {
        return Err(Error::InvalidResponse);
    }
    Ok("runtimeTransportAccepted")
}

fn main() {
    let mut bytes = Vec::new();
    if io::stdin().take(8193).read_to_end(&mut bytes).is_err() || bytes.len() > 8192 {
        std::process::exit(2);
    }
    let result = std::panic::catch_unwind(|| {
        let input: Input = serde_json::from_slice(&bytes).map_err(|_| Error::Request)?;
        run(input)
    });
    match result {
        Ok(Ok(marker)) => println!("{{\"ok\":true,\"marker\":\"{marker}\"}}"),
        Ok(Err(error)) => {
            println!("{{\"ok\":false,\"error\":\"{error}\"}}");
            std::process::exit(1);
        }
        Err(_) => {
            println!("{{\"ok\":false,\"error\":\"HOST_HTTP_FIXTURE_INTERNAL\"}}");
            std::process::exit(1);
        }
    }
}
