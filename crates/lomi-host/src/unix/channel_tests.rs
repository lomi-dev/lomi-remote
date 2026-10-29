//! Real private Store and protected synthetic identities; no live HTTP/providers.
use super::*;
use lomi_remote_crypto::Role;
use lomi_remote_protocol::rpc::*;
use peer::tests::{Fixture, fixture};
use std::cell::{Cell, RefCell};
// Static error classes and original-clock/counter samples only; never print
// credentials, grants, admission bodies, Store errors, or provider Debug values.
fn step_error_class(error: &StepError) -> String {
    match error {
        StepError::Auth(error) => format!("Auth({error})"),
        StepError::Http(error) => format!("Http({error})"),
        StepError::ExpiredEnrollment => "Auth(HOST_AUTH_EXPIRED)".to_owned(),
        StepError::ExpiredRotation => "Auth(HOST_AUTH_EXPIRED)".to_owned(),
        StepError::Rejected => "Rejected".to_owned(),
        StepError::Stale => "Stale".to_owned(),
    }
}
fn fixture_diagnostics(f: &Fixture) -> String {
    let now = Instant::now();
    let runtime = f.runtime();
    let heartbeat = &f.eligibility.heartbeat;
    let rows = f.store.try_lock().ok().map(|store| {
        (
            store
                .pending_pairing_decisions()
                .ok()
                .map(|rows| rows.len()),
            store
                .acknowledged_workspace_grants()
                .ok()
                .map(|rows| rows.len()),
            store
                .pending_channel_admissions()
                .ok()
                .map(|rows| rows.len()),
            store
                .acknowledged_channel_admissions()
                .ok()
                .map(|rows| rows.len()),
        )
    });
    format!(
        "anchor_elapsed_ms={} operation_remaining_ms={} heartbeat_elapsed_ms={} heartbeat_freshness_ms={} heartbeat_lease_ms={} heartbeat_freshness_remaining_ms={} heartbeat_lease_remaining_ms={} rows(pending_pairing,ack_workspace,pending_channel,ack_channel)={rows:?}",
        now.saturating_duration_since(f.anchor).as_millis(),
        runtime
            .operation
            .deadline()
            .saturating_duration_since(now)
            .as_millis(),
        now.saturating_duration_since(heartbeat.request_started)
            .as_millis(),
        heartbeat.freshness_ms,
        heartbeat.lease_ms,
        (heartbeat.request_started + Duration::from_millis(heartbeat.freshness_ms))
            .saturating_duration_since(now)
            .as_millis(),
        (heartbeat.request_started + Duration::from_millis(heartbeat.lease_ms))
            .saturating_duration_since(now)
            .as_millis(),
    )
}
fn copy_eligibility(e: &PeerEligibility) -> PeerEligibility {
    PeerEligibility {
        identity: e.identity.clone(),
        binding: e.binding.clone(),
        publication: e.publication.clone(),
        heartbeat: e.heartbeat.clone(),
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
struct PairApi {
    proposal: PairingProposal,
    pending_calls: Cell<usize>,
    decide_calls: Cell<usize>,
    get_calls: Cell<usize>,
}
impl PairApi {
    fn counters(&self) -> (usize, usize, usize) {
        (
            self.pending_calls.get(),
            self.decide_calls.get(),
            self.get_calls.get(),
        )
    }
}
impl peer::PeerApi for PairApi {
    fn pending(
        &self,
        _: HostId,
        _: &HostAccessCredential,
    ) -> Result<PairingPendingResult, lomi_host_http::Error> {
        self.pending_calls.set(self.pending_calls.get() + 1);
        Ok(PairingPendingResult {
            pairings: vec![PendingPairing {
                pairing_id: PairingId::from_bytes([26; 16]).unwrap(),
                proposal: self.proposal.clone(),
            }]
            .try_into()
            .unwrap(),
        })
    }
    fn get(
        &self,
        _: PairingId,
        _: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        self.get_calls.set(self.get_calls.get() + 1);
        panic!("no pairing recovery in channel fixture")
    }
    fn decide(
        &self,
        id: PairingId,
        p: &PairingDecisionParams,
        _: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        self.decide_calls.set(self.decide_calls.get() + 1);
        let PairingDecisionParams::Approve { grant, .. } = p else {
            panic!("workspace approval")
        };
        Ok(PairingResult::Approved {
            pairing_id: id,
            proposal: self.proposal.clone(),
            grant: grant.clone(),
            identities: self.proposal.identities.clone(),
            authority: self.proposal.authority.clone(),
        })
    }
}
fn terminal(f: &mut Fixture) -> TerminalContext {
    let mut store = f.store.lock().unwrap();
    let binding = lomi_host_store::OperationBinding {
        rights: StoredOperationRights::new(
            OperationId::from_bytes([50; 16]).unwrap(),
            ConsumerAuthorizationId::from_bytes([23; 16]).unwrap(),
            f.workspace,
            Method::TerminalCreate,
            CapabilitySet::control_with_workspace_tools(),
            false,
        )
        .unwrap(),
        parameter_hash: lomi_host_store::parameter_hash(&(Method::TerminalCreate, f.workspace))
            .unwrap(),
    };
    let mut state = store.workspace(f.workspace).unwrap().state;
    store
        .admit_external(&binding, state.domain_revision)
        .unwrap();
    let permit = store.start_external(&binding).unwrap();
    state.domain_revision.0 += 1;
    let terminal = TerminalContext {
        workspace: state.context.clone(),
        pane_id: PaneId::from_bytes([51; 16]).unwrap(),
        session_id: TerminalSessionId::from_bytes([52; 16]).unwrap(),
        session_epoch: SessionEpoch::from_bytes([53; 16]).unwrap(),
        profile: TerminalProfile::ExperimentalRustGridV1,
    };
    state.tabs.0.push(TerminalTab {
        tab_id: TabId::from_bytes([54; 16]).unwrap(),
        name: "private-terminal".to_owned().try_into().unwrap(),
        layout: TerminalLayout::Pane {
            pane: TerminalPane {
                pane_id: terminal.pane_id,
                session: Some(terminal.clone()),
                state: PaneState::Running,
            },
        },
    });
    store
        .complete_external(
            &permit,
            OperationState::Succeeded,
            Effect::Committed,
            Some(OperationResult::Terminal {
                domain_revision: state.domain_revision,
                pane_id: terminal.pane_id,
                session_id: terminal.session_id,
                session_epoch: terminal.session_epoch,
            }),
            Some(state),
        )
        .unwrap();
    let intent = store
        .prepare_host_publication(&f.eligibility.binding)
        .unwrap();
    f.eligibility.binding = store
        .acknowledge_host_publication(
            &intent,
            &PublicationResult {
                runtime: intent.params.runtime.clone(),
                publication_seq: intent.params.publication_seq,
            },
        )
        .unwrap();
    f.eligibility.publication = store
        .acknowledged_host_publication(&f.eligibility.binding)
        .unwrap()
        .unwrap();
    terminal
}
#[track_caller]
fn inputs(
    f: &mut Fixture,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    terminal_target: bool,
) -> ChannelAdmissionInputs {
    let terminal = terminal_target.then(|| terminal(f));
    let api = PairApi {
        proposal: f.proposal(auth),
        pending_calls: Cell::new(0),
        decide_calls: Cell::new(0),
        get_calls: Cell::new(0),
    };
    let mut pairing = peer::Worker::default();
    for stage in 0..3 {
        let result = pairing.step(auth, &f.config, f.runtime(), &f.eligibility, Some(&api));
        eprintln!(
            "inputs pairing stage={stage} terminal={terminal_target} api_calls(pending,decide,get)={:?} ok={} {}",
            api.counters(),
            result.is_ok(),
            fixture_diagnostics(f),
        );
        assert!(
            result.is_ok(),
            "inputs pairing stage={stage} terminal={terminal_target} error={:?} {}",
            result.as_ref().err().map(step_error_class),
            fixture_diagnostics(f),
        );
    }
    let mut sources = f
        .store
        .lock()
        .unwrap()
        .acknowledged_workspace_grants()
        .unwrap();
    assert!(
        !sources.is_empty(),
        "inputs missing pairing ACK caller={} completed_pairing_stages=3 terminal={terminal_target} ack_count={} api_calls(pending,decide,get)={:?} {}",
        std::panic::Location::caller(),
        sources.len(),
        api.counters(),
        fixture_diagnostics(f),
    );
    let source = sources.remove(0);
    let PairingResult::Approved {
        grant,
        identities,
        mut authority,
        ..
    } = source.response
    else {
        panic!("approved source")
    };
    let t = terminal.as_ref().map(|t| TerminalTargetV3 {
        pane_id: t.pane_id.to_bytes(),
        session_id: t.session_id.to_bytes(),
        session_epoch: t.session_epoch.to_bytes(),
        terminal_profile: "lomi-rust-grid-v1-experimental".to_owned(),
    });
    authority.terminal_membership = terminal.map(|t| ChannelTerminalMembership {
        pane_id: t.pane_id,
        session_id: t.session_id,
        session_epoch: t.session_epoch,
        terminal_profile: t.profile,
    });
    let context = ChannelContextV3 {
        version: 3,
        grant: SignedGrantV3::from_wire(&grant).unwrap().grant,
        channel_id: [44; 16],
        initiator_role: Role::Device,
        responder_role: Role::Host,
        purpose: if terminal_target {
            ChannelPurposeV3::Terminal
        } else {
            ChannelPurposeV3::Workspace
        },
        terminal: t,
        issued_at: 1005,
        expires_at: 1030,
    };
    ChannelAdmissionInputs {
        expected_context: hex(&context.canonical().unwrap()).try_into().unwrap(),
        expected_context_json: serde_json::to_value(&context)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
        grant,
        identities,
        authority,
    }
}
enum Reply {
    Poll(ChannelPendingResult),
    State(Box<ChannelResult>),
    Error(lomi_host_http::Error),
}
impl Reply {
    fn state(value: ChannelResult) -> Self {
        Self::State(Box::new(value))
    }
}
struct Api<'a> {
    replies: RefCell<VecDeque<Reply>>,
    requests: RefCell<Vec<&'static str>>,
    params: RefCell<Vec<ChannelAdmissionParams>>,
    hook: RefCell<Option<Box<dyn FnOnce() + 'a>>>,
}
impl Api<'_> {
    fn poll(inputs: ChannelAdmissionInputs) -> Self {
        Self {
            replies: RefCell::new(
                vec![Reply::Poll(ChannelPendingResult {
                    channels: vec![PendingChannel {
                        channel_id: ChannelId::from_bytes([44; 16]).unwrap(),
                        inputs,
                    }]
                    .try_into()
                    .unwrap(),
                })]
                .into(),
            ),
            requests: RefCell::new(vec![]),
            params: RefCell::new(vec![]),
            hook: RefCell::new(None),
        }
    }
    fn reply(&self, name: &'static str) -> Result<Reply, lomi_host_http::Error> {
        self.requests.borrow_mut().push(name);
        if let Some(hook) = self.hook.borrow_mut().take() {
            hook();
        }
        match self
            .replies
            .borrow_mut()
            .pop_front()
            .expect("bounded channel script")
        {
            Reply::Error(e) => Err(e),
            r => Ok(r),
        }
    }
}
impl ChannelApi for Api<'_> {
    fn pending(
        &self,
        _: HostId,
        _: &HostAccessCredential,
    ) -> Result<ChannelPendingResult, lomi_host_http::Error> {
        match self.reply("POLL")? {
            Reply::Poll(p) => Ok(p),
            _ => panic!("poll reply"),
        }
    }
    fn get(
        &self,
        _: ChannelId,
        _: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error> {
        match self.reply("GET")? {
            Reply::State(p) => Ok(*p),
            _ => panic!("get reply"),
        }
    }
    fn admit(
        &self,
        _: ChannelId,
        params: &ChannelAdmissionParams,
        _: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error> {
        self.params.borrow_mut().push(params.clone());
        match self.reply("POST")? {
            Reply::State(p) => Ok(*p),
            _ => panic!("post reply"),
        }
    }
}
#[track_caller]
fn step(
    f: &Fixture,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    worker: &mut Worker,
    api: &dyn ChannelApi,
) -> Result<(), StepError> {
    let result = worker.step(auth, &f.config, f.runtime(), &f.eligibility, Some(api));
    if let Err(error) = &result {
        eprintln!(
            "channel step caller={} error={} {}",
            std::panic::Location::caller(),
            step_error_class(error),
            fixture_diagnostics(f),
        );
    }
    result
}
#[track_caller]
fn prepared(
    f: &Fixture,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    api: &dyn ChannelApi,
) -> (Worker, ChannelAdmissionIntent) {
    let mut w = Worker::default();
    for stage in 0..2 {
        let result = step(f, auth, &mut w, api);
        assert!(
            result.is_ok(),
            "prepared stage={stage} error={:?} {}",
            result.as_ref().err().map(step_error_class),
            fixture_diagnostics(f),
        );
    }
    let mut pending = f
        .store
        .lock()
        .unwrap()
        .pending_channel_admissions()
        .unwrap();
    assert!(
        !pending.is_empty(),
        "prepared missing pending admission caller={} pending_count={} {}",
        std::panic::Location::caller(),
        pending.len(),
        fixture_diagnostics(f),
    );
    let intent = pending.remove(0);
    (w, intent)
}
fn ticket_response(i: &ChannelAdmissionIntent) -> ChannelTicketResult {
    ChannelTicketResult {
        channel_id: i.preparation.channel_id,
        ticket: "A".repeat(43).try_into().unwrap(),
        expires_in_ms: DecimalU64(5000),
    }
}
fn driver_for_ticket(i: &ChannelAdmissionIntent) -> super::super::remote_ingress::Driver<'_> {
    let mut driver = super::super::remote_ingress::Driver::default();
    driver.script_ticket_for_test(Ok(ticket_response(i)), None, Duration::ZERO);
    driver
}
fn admitted(i: &ChannelAdmissionIntent) -> ChannelResult {
    ChannelResult::Admitted {
        channel_id: i.preparation.channel_id,
        inputs: i.preparation.inputs.clone(),
        admission: i.preparation.params.admission.clone(),
    }
}
#[test]
fn workspace_and_terminal_reconstruct_parent_longer_than_context_without_git_execute() {
    for is_terminal in [false, true] {
        fixture(|f, auth| {
            let input = inputs(f, auth, is_terminal);
            let expected = input.clone();
            let api = Api::poll(input);
            let (mut w, i) = prepared(f, auth, &api);
            assert_eq!(i.preparation.inputs, expected);
            assert_eq!(i.preparation.expires_at, 1030);
            assert_eq!(
                SignedGrantV3::from_wire(&expected.grant)
                    .unwrap()
                    .grant
                    .expires_at,
                1100
            );
            assert!(
                !SignedGrantV3::from_wire(&expected.grant)
                    .unwrap()
                    .grant
                    .capabilities
                    .contains(Capability::GitExecute)
            );
            api.replies
                .borrow_mut()
                .push_back(Reply::state(admitted(&i)));
            let store = f.store.clone();
            *api.hook.borrow_mut() = Some(Box::new(move || {
                assert!(store.try_lock().is_ok());
            }));
            assert!(step(f, auth, &mut w, &api).is_ok());
            assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
            assert!(w.has_retained_operation());
            // A full producer output slot prevents another HTTP/write turn.
            assert!(step(f, auth, &mut w, &api).is_ok());
            assert_eq!(*api.requests.borrow(), ["POLL", "POST"]);
            let output = w
                .pending_handoff
                .as_ref()
                .expect("successful live ACK handoff");
            assert_eq!(output.acknowledgement.response, admitted(&i));
            assert_eq!(output.target, i.preparation.target);
            assert_eq!(output.source.intent.token, i.preparation.source_grant_token);
            assert_eq!(
                output.prepared.canonical(),
                hex_bytes(expected.expected_context.expose_wire())
                    .ok()
                    .unwrap()
            );
            assert_eq!(output.prepared.context().terminal.is_some(), is_terminal);
            assert_eq!(
                output.deadline,
                f.runtime()
                    .operation
                    .deadline()
                    .min(f.anchor + Duration::from_secs(25))
            );
            assert!(f.runtime().operation.is_same_admission(&output.operation));
            assert!(output.observation.current_operation(f.runtime()));
            // Exercise the production Ready call site's exact consumer, which
            // retains provenance and polls rather than merely dropping output.
            let mut driver = driver_for_ticket(&i);
            driver.after_channel_step(&mut w, auth, f.runtime(), &f.eligibility);
            assert!(w.take_admitted().is_none());
            assert!(driver.has_retained_operation());
            assert!(driver.poll(auth, f.runtime(), Some(&f.eligibility)));
            assert_eq!(
                f.store
                    .lock()
                    .unwrap()
                    .acknowledged_channel_admissions()
                    .unwrap()[0]
                    .intent,
                i
            );
        });
    }
}
#[test]
fn lost_post_and_coordinator_restart_require_exact_get_then_exact_retry_or_ack() {
    for approved_on_get in [false, true] {
        fixture(|f, auth| {
            let input = inputs(f, auth, true);
            let api = Api::poll(input);
            let (mut w, i) = prepared(f, auth, &api);
            api.replies
                .borrow_mut()
                .push_back(Reply::Error(lomi_host_http::Error::Timeout));
            assert!(step(f, auth, &mut w, &api).is_ok());
            assert!(w.take_admitted().is_none(), "lost POST is not an admission");
            let mut w = Worker::default();
            api.replies
                .borrow_mut()
                .push_back(Reply::state(if approved_on_get {
                    admitted(&i)
                } else {
                    ChannelResult::Pending {
                        channel_id: i.preparation.channel_id,
                        inputs: i.preparation.inputs.clone(),
                    }
                }));
            assert!(step(f, auth, &mut w, &api).is_ok());
            assert_eq!(*api.requests.borrow(), ["POLL", "POST", "GET"]);
            if !approved_on_get {
                assert_eq!(
                    f.store
                        .lock()
                        .unwrap()
                        .pending_channel_admissions()
                        .unwrap(),
                    vec![i.clone()]
                );
                api.replies
                    .borrow_mut()
                    .push_back(Reply::state(admitted(&i)));
                assert!(step(f, auth, &mut w, &api).is_ok());
                assert_eq!(api.params.borrow()[0], api.params.borrow()[1]);
            }
            let handoff = w.take_admitted().expect("exact fresh GET/POST ACK handoff");
            assert_eq!(handoff.acknowledgement.response, admitted(&i));
            assert!(handoff.observation.current_operation(f.runtime()));
            assert!(
                w.take_admitted().is_none(),
                "handoff is delivered exactly once"
            );
            assert!(
                Worker::default().take_admitted().is_none(),
                "stored ACK cannot construct provenance"
            );
            assert_eq!(
                f.store
                    .lock()
                    .unwrap()
                    .acknowledged_channel_admissions()
                    .unwrap()[0]
                    .intent,
                i
            );
        });
    }
}
#[test]
fn changed_context_grant_identity_authority_and_outer_id_never_prepare() {
    for variant in 0..7 {
        fixture(|f, auth| {
            eprintln!("changed-context variant={variant}");
            let mut input = inputs(f, auth, true);
            match variant {
                0 => input.authority.grant_revision.0 += 1,
                1 => {
                    input.authority.account_session_id =
                        "other-session".to_owned().try_into().unwrap()
                }
                2 => input.identities.consumer_fingerprint = "01".repeat(32).try_into().unwrap(),
                3 => input.grant.signature = "01".repeat(64).try_into().unwrap(),
                4 => {
                    let mut c = ChannelContextV3::from_canonical(
                        &hex_bytes(input.expected_context.expose_wire())
                            .ok()
                            .unwrap(),
                    )
                    .unwrap();
                    c.channel_id = [99; 16];
                    input.expected_context = hex(&c.canonical().unwrap()).try_into().unwrap();
                }
                5 => {
                    input
                        .authority
                        .terminal_membership
                        .as_mut()
                        .unwrap()
                        .session_epoch = SessionEpoch::from_bytes([99; 16]).unwrap()
                }
                _ => input.expected_context = "01".to_owned().try_into().unwrap(),
            }
            let api = Api::poll(input);
            let mut w = Worker::default();
            assert!(step(f, auth, &mut w, &api).is_ok());
            assert!(step(f, auth, &mut w, &api).is_ok());
            assert!(
                f.store
                    .lock()
                    .unwrap()
                    .pending_channel_admissions()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(*api.requests.borrow(), ["POLL"]);
            assert!(!f.gate.load(Ordering::Acquire));
        });
    }
}
#[test]
fn source_retirement_or_token_change_prevents_send_without_replacing_intent() {
    for retire in [false, true] {
        fixture(|f, auth| {
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (mut w, i) = prepared(f, auth, &api);
            if retire {
                let mut s = f.store.lock().unwrap();
                let source = s.acknowledged_workspace_grants().unwrap().remove(0);
                s.retire_acknowledged_workspace_grant(&source).unwrap();
            } else {
                w.active
                    .as_mut()
                    .unwrap()
                    .intent
                    .as_mut()
                    .unwrap()
                    .preparation
                    .source_grant_token = uuid::Uuid::new_v4().to_string();
            }
            assert!(step(f, auth, &mut w, &api).is_ok());
            assert_eq!(*api.requests.borrow(), ["POLL"]);
            assert_eq!(
                f.store
                    .lock()
                    .unwrap()
                    .pending_channel_admissions()
                    .unwrap(),
                vec![i]
            );
        });
    }
}
#[test]
fn paused_logout_unshare_and_runtime_gates_preempt_post() {
    for variant in 0..4 {
        fixture(|f, auth| {
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (mut w, i) = prepared(f, auth, &api);
            match variant {
                0 => f.paused.store(true, Ordering::Release),
                1 => f.gate.store(true, Ordering::Release),
                2 => {
                    f.store.lock().unwrap().unshare(f.workspace).unwrap();
                }
                _ => {
                    let binding = f.eligibility.binding.clone();
                    f.store
                        .lock()
                        .unwrap()
                        .invalidate_cloud_runtime(&binding.scope, &binding, None)
                        .unwrap();
                }
            }
            let _ = step(f, auth, &mut w, &api);
            assert_eq!(*api.requests.borrow(), ["POLL"]);
            assert_eq!(
                f.store
                    .lock()
                    .unwrap()
                    .pending_channel_admissions()
                    .unwrap(),
                vec![i]
            );
        });
    }
}
#[test]
fn gate_during_post_preserves_exact_intent_and_drops_ack() {
    fixture(|f, auth| {
        let input = inputs(f, auth, false);
        let api = Api::poll(input);
        let (mut w, i) = prepared(f, auth, &api);
        api.replies
            .borrow_mut()
            .push_back(Reply::state(admitted(&i)));
        let gate = &f.gate;
        let api = Api {
            hook: RefCell::new(Some(Box::new(|| gate.store(true, Ordering::Release)))),
            ..api
        };
        assert!(step(f, auth, &mut w, &api).is_err());
        assert!(w.take_admitted().is_none());
        let s = f.store.lock().unwrap();
        assert_eq!(s.pending_channel_admissions().unwrap(), vec![i]);
        assert!(s.acknowledged_channel_admissions().unwrap().is_empty());
    });
}
#[test]
fn peer_resource_auth_errors_never_globally_fence_owner() {
    for get in [false, true] {
        fixture(|f, auth| {
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (mut w, i) = prepared(f, auth, &api);
            api.replies
                .borrow_mut()
                .push_back(Reply::Error(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::AuthRequired,
                )));
            if get {
                w = Worker::default();
            }
            assert!(step(f, auth, &mut w, &api).is_ok());
            assert!(!f.gate.load(Ordering::Acquire));
            assert!(
                !f.store
                    .lock()
                    .unwrap()
                    .authorization_state()
                    .unwrap()
                    .locked
            );
            assert_eq!(
                f.store
                    .lock()
                    .unwrap()
                    .pending_channel_admissions()
                    .unwrap(),
                vec![i]
            );
        });
    }
}
#[test]
fn mismatched_get_or_admission_cannot_ack_or_rebase() {
    for pending in [false, true] {
        fixture(|f, auth| {
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (_, i) = prepared(f, auth, &api);
            let mut changed = i.preparation.inputs.clone();
            changed.authority.grant_revision.0 += 1;
            let response = if pending {
                ChannelResult::Pending {
                    channel_id: i.preparation.channel_id,
                    inputs: changed,
                }
            } else {
                ChannelResult::Admitted {
                    channel_id: i.preparation.channel_id,
                    inputs: changed,
                    admission: i.preparation.params.admission.clone(),
                }
            };
            api.replies.borrow_mut().push_back(Reply::state(response));
            let mut w = Worker::default();
            assert!(step(f, auth, &mut w, &api).is_ok());
            let s = f.store.lock().unwrap();
            assert_eq!(s.pending_channel_admissions().unwrap(), vec![i]);
            assert!(s.acknowledged_channel_admissions().unwrap().is_empty());
            assert!(api.params.borrow().is_empty());
        });
    }
}
#[test]
fn slow_poll_and_sign_consume_original_observation_even_after_new_heartbeat() {
    for signing in [false, true] {
        fixture(|f, auth| {
            // Complete all pairing/identity setup before the FIRST channel poll.
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let mut w = Worker::default();
            f.eligibility.heartbeat.request_started = Instant::now();
            f.eligibility.heartbeat.freshness_ms = 2000;
            let original_expiry =
                f.eligibility.heartbeat.request_started + Duration::from_millis(2000);
            let hooks = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let reached = hooks.clone();
            let expire_original = move || {
                reached.fetch_add(1, Ordering::SeqCst);
                assert!(
                    Instant::now() < original_expiry,
                    "actual hook reached while original observation still fresh"
                );
                let release = original_expiry + Duration::from_millis(30);
                let stop = Instant::now() + Duration::from_secs(3);
                for _ in 0..128 {
                    let now = Instant::now();
                    if now >= release {
                        break;
                    }
                    assert!(now < stop, "bounded original observation expiry wait");
                    thread::sleep(
                        release
                            .saturating_duration_since(now)
                            .min(Duration::from_millis(25)),
                    );
                }
                assert!(
                    Instant::now() >= release,
                    "original deadline actually passed inside hook"
                );
            };
            let current_expiry = if signing {
                assert!(step(f, auth, &mut w, &api).is_ok());
                assert_eq!(*api.requests.borrow(), ["POLL"]);
                assert_eq!(w.cache.len(), 1, "fresh original poll observation retained");
                w.after_sign = Some(Box::new(expire_original));
                // Renew only the current handoff, never the retained poll/HB proof.
                f.eligibility.heartbeat.request_started = Instant::now();
                f.eligibility.heartbeat.freshness_ms = 5000;
                Some(f.eligibility.heartbeat.request_started + Duration::from_millis(5000))
            } else {
                *api.hook.borrow_mut() = Some(Box::new(expire_original));
                None
            };
            let result = step(f, auth, &mut w, &api);
            assert_eq!(
                hooks.load(Ordering::SeqCst),
                1,
                "actual {} hook reached once before result classification",
                if signing { "after_sign" } else { "POLL" }
            );
            assert!(Instant::now() > original_expiry);
            if let Some(current_expiry) = current_expiry {
                assert!(
                    Instant::now() < current_expiry,
                    "renewed handoff remains fresh"
                );
                assert!(
                    result.is_ok(),
                    "expired original work is a resource-local rejection"
                );
            } else {
                assert!(
                    result.is_err(),
                    "POLL consumed the original live heartbeat freshness"
                );
            }
            let store = f.store.lock().unwrap();
            assert!(store.pending_channel_admissions().unwrap().is_empty());
            assert!(store.acknowledged_channel_admissions().unwrap().is_empty());
            assert!(!store.authorization_state().unwrap().locked);
            assert!(!f.gate.load(Ordering::Acquire));
            assert_eq!(*api.requests.borrow(), ["POLL"]);
        });
    }
}

#[test]
fn exact_expired_pending_and_ack_cleanup_do_not_close_remote_or_create_authority() {
    for ack in [false, true] {
        fixture(|f, auth| {
            eprintln!("expired-cleanup ack={ack}");
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (mut w, i) = prepared(f, auth, &api);
            if ack {
                api.replies
                    .borrow_mut()
                    .push_back(Reply::state(admitted(&i)));
                assert!(step(f, auth, &mut w, &api).is_ok());
            }
            w.active = None;
            w.capacity_blocked = true;
            w.poll_at = Some(Instant::now() + Duration::from_secs(30));
            f.eligibility.heartbeat.request_started = Instant::now();
            let runtime = Runtime {
                base: 1030,
                ..f.runtime()
            };
            assert!(
                w.step(auth, &f.config, runtime, &f.eligibility, Some(&api))
                    .is_ok()
            );
            let s = f.store.lock().unwrap();
            assert!(s.pending_channel_admissions().unwrap().is_empty());
            assert!(s.acknowledged_channel_admissions().unwrap().is_empty());
            assert_eq!(api.requests.borrow().len(), if ack { 2 } else { 1 });
        });
    }
}
#[test]
fn joint_idle_class_selection_alternates_even_for_local_or_backoff_turns() {
    let mut scheduler = IdleScheduler::default();
    let selected: Vec<_> = (0..8).map(|_| scheduler.select_channel(true)).collect();
    assert_eq!(
        selected,
        [false, true, false, true, false, true, false, true]
    );
    assert!(!scheduler.select_channel(false));
}
#[test]
fn terminal_exit_or_missing_ack_membership_rejects_before_sign_and_send() {
    for exit in [false, true] {
        fixture(|f, auth| {
            let input = inputs(f, auth, true);
            let api = Api::poll(input.clone());
            let mut w = Worker::default();
            assert!(step(f, auth, &mut w, &api).is_ok());
            if exit {
                let context = ChannelContextV3::from_canonical(
                    &hex_bytes(input.expected_context.expose_wire())
                        .ok()
                        .unwrap(),
                )
                .unwrap();
                let t = context.terminal.unwrap();
                let local = f.store.lock().unwrap().workspace(f.workspace).unwrap();
                let terminal = TerminalContext {
                    workspace: local.state.context,
                    pane_id: PaneId::from_bytes(t.pane_id).unwrap(),
                    session_id: TerminalSessionId::from_bytes(t.session_id).unwrap(),
                    session_epoch: SessionEpoch::from_bytes(t.session_epoch).unwrap(),
                    profile: TerminalProfile::ExperimentalRustGridV1,
                };
                f.store
                    .lock()
                    .unwrap()
                    .record_terminal_exit(&terminal)
                    .unwrap();
            } else {
                f.eligibility.publication.workspaces = vec![PublishedWorkspace {
                    workspace_id: f.workspace,
                    workspace_epoch: input.authority.workspace_epoch,
                    terminals: vec![].try_into().unwrap(),
                }]
                .try_into()
                .unwrap();
            }
            let signed = Arc::new(AtomicBool::new(false));
            let flag = signed.clone();
            w.after_sign = Some(Box::new(move || {
                flag.store(true, Ordering::Release);
            }));
            let _ = step(f, auth, &mut w, &api);
            assert!(!signed.load(Ordering::Acquire));
            assert!(
                f.store
                    .lock()
                    .unwrap()
                    .pending_channel_admissions()
                    .unwrap()
                    .is_empty()
            );
            assert_eq!(*api.requests.borrow(), ["POLL"]);
        });
    }
}
#[test]
fn final_store_contention_cannot_extend_original_work_for_prepare_or_ack() {
    for ack in [false, true] {
        fixture(|f, auth| {
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (mut w, original) = if ack {
                let (w, i) = prepared(f, auth, &api);
                (w, Some(i))
            } else {
                let mut w = Worker::default();
                assert!(step(f, auth, &mut w, &api).is_ok());
                (w, None)
            };
            let mut original_eligibility = copy_eligibility(&f.eligibility);
            original_eligibility.heartbeat.request_started = Instant::now();
            original_eligibility.heartbeat.freshness_ms = 1500;
            let expires =
                original_eligibility.heartbeat.request_started + Duration::from_millis(1500);
            let proof = Arc::new(Observation::new(
                &original_eligibility,
                Instant::now(),
                f.original_scope(),
            ));
            if ack {
                w.active.as_mut().unwrap().observation = proof;
            } else {
                w.cache.front_mut().unwrap().observation = proof;
            }
            f.eligibility.heartbeat.request_started = Instant::now();
            let handles = Arc::new(Mutex::new(Vec::new()));
            let owned = peer::tests::JoinContentionThreads(handles.clone());
            let hook =
                peer::tests::hold_store_for_final_lock(f.store.clone(), handles.clone(), expires);
            if ack {
                w.before_ack_lock = Some(hook);
                api.replies
                    .borrow_mut()
                    .push_back(Reply::state(admitted(original.as_ref().unwrap())));
            } else {
                w.before_prepare_lock = Some(hook);
            }
            let result = step(f, auth, &mut w, &api);
            assert_eq!(handles.lock().unwrap().len(), 1, "finalStorehook reached");
            assert!(owned.join_all());
            assert!(Instant::now() > expires);
            assert!(result.is_err());
            assert!(
                w.take_admitted().is_none(),
                "expired/failed ACK has no handoff"
            );
            assert!(
                Instant::now() < f.eligibility.heartbeat.request_started + Duration::from_secs(5)
            );
            let s = f.store.lock().unwrap();
            assert_eq!(
                s.pending_channel_admissions().unwrap(),
                original.into_iter().collect::<Vec<_>>()
            );
            assert!(s.acknowledged_channel_admissions().unwrap().is_empty());
        });
    }
}
#[test]
fn real_trusted_second_crossing_keeps_prepare_send_and_get_ack_exact() {
    for stage in ["prepare", "send", "ack"] {
        fixture(|f, auth| {
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let mut w = Worker {
                clock: Some(PolicyClock::new(1005, f.anchor).unwrap()),
                ..Worker::default()
            };
            assert!(step(f, auth, &mut w, &api).is_ok());
            let original = if stage == "prepare" {
                None
            } else {
                assert!(step(f, auth, &mut w, &api).is_ok());
                let i = f
                    .store
                    .lock()
                    .unwrap()
                    .pending_channel_admissions()
                    .unwrap()
                    .remove(0);
                if stage == "ack" {
                    api.replies
                        .borrow_mut()
                        .push_back(Reply::Error(lomi_host_http::Error::Timeout));
                    assert!(step(f, auth, &mut w, &api).is_ok());
                    w.parked.clear();
                }
                Some(i)
            };
            if stage == "send" {
                api.replies
                    .borrow_mut()
                    .push_back(Reply::Error(lomi_host_http::Error::Timeout));
            } else if stage == "ack" {
                api.replies
                    .borrow_mut()
                    .push_back(Reply::state(admitted(original.as_ref().unwrap())));
            }
            let crossed = Arc::new(Mutex::new(Vec::new()));
            w.after_snapshot = Some(peer::tests::cross_snapshot_second(
                f.store.clone(),
                1005,
                f.anchor,
                crossed.clone(),
            ));
            let heartbeat = f.eligibility.heartbeat.request_started;
            assert!(step(f, auth, &mut w, &api).is_ok(), "stage={stage}");
            let crossed = crossed.lock().unwrap();
            assert_eq!(crossed.len(), 1, "stage={stage}");
            assert!(crossed[0].1 > crossed[0].0);
            assert_eq!(w.failures, 0, "stage={stage}");
            assert_eq!(f.eligibility.heartbeat.request_started, heartbeat);
            assert!(Instant::now() < heartbeat + Duration::from_secs(5));
            let s = f.store.lock().unwrap();
            if stage == "ack" {
                assert!(s.pending_channel_admissions().unwrap().is_empty());
                assert_eq!(
                    s.acknowledged_channel_admissions().unwrap()[0].intent,
                    original.unwrap()
                );
            } else {
                let i = s.pending_channel_admissions().unwrap().remove(0);
                assert_eq!(i.preparation.expires_at, 1030);
                assert_eq!(i.preparation.issued_at, 1005);
                if let Some(original) = original {
                    assert_eq!(i, original);
                }
            }
        });
    }
}
struct MixedApi {
    store: Arc<shared_owner::PeerStoreForTest>,
    requests: RefCell<Vec<(&'static str, ChannelId)>>,
}
impl ChannelApi for MixedApi {
    fn pending(
        &self,
        _: HostId,
        _: &HostAccessCredential,
    ) -> Result<ChannelPendingResult, lomi_host_http::Error> {
        panic!("poll deliberatelynotdue")
    }
    fn get(
        &self,
        id: ChannelId,
        _: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error> {
        self.requests.borrow_mut().push(("GET", id));
        let i = self
            .store
            .lock()
            .unwrap()
            .pending_channel_admissions()
            .unwrap()
            .into_iter()
            .find(|i| i.preparation.channel_id == id)
            .unwrap();
        Ok(ChannelResult::Pending {
            channel_id: id,
            inputs: i.preparation.inputs,
        })
    }
    fn admit(
        &self,
        id: ChannelId,
        p: &ChannelAdmissionParams,
        _: &HostAccessCredential,
    ) -> Result<ChannelResult, lomi_host_http::Error> {
        self.requests.borrow_mut().push(("POST", id));
        let i = self
            .store
            .lock()
            .unwrap()
            .pending_channel_admissions()
            .unwrap()
            .into_iter()
            .find(|i| i.preparation.channel_id == id)
            .unwrap();
        assert_eq!(*p, i.preparation.params);
        Ok(admitted(&i))
    }
}
#[test]
fn continuously_valid_fresh_work_cannot_starve_durable_recovery() {
    fixture(|f, auth| {
        let input = inputs(f, auth, false);
        let api = Api::poll(input.clone());
        let (mut prior, old) = prepared(f, auth, &api);
        api.replies
            .borrow_mut()
            .push_back(Reply::Error(lomi_host_http::Error::Timeout));
        assert!(step(f, auth, &mut prior, &api).is_ok());
        let api = MixedApi {
            store: f.store.clone(),
            requests: RefCell::new(vec![]),
        };
        let mut w = Worker {
            scope: Some(f.eligibility.binding.scope.clone()),
            poll_at: Some(Instant::now() + Duration::from_secs(30)),
            ..Worker::default()
        };
        let mut completed = None;
        for turn in 0..8 {
            // Build the expensive input batch before obtaining a fresh proof.
            // Never rewrite a retained observation or the original durable intent.
            let mut proposals = Vec::new();
            for n in 0..64 {
                let mut inputs = input.clone();
                let mut c = ChannelContextV3::from_canonical(
                    &hex_bytes(inputs.expected_context.expose_wire())
                        .ok()
                        .unwrap(),
                )
                .unwrap();
                c.channel_id = ((1000 + turn * 64 + n) as u128).to_be_bytes();
                inputs.expected_context = hex(&c.canonical().unwrap()).try_into().unwrap();
                proposals.push((ChannelId::from_bytes(c.channel_id).unwrap(), inputs));
            }
            let refresh_at = f.eligibility.heartbeat.request_started
                + Duration::from_millis(f.eligibility.heartbeat.freshness_ms.saturating_sub(1000));
            if turn == 0 || Instant::now() >= refresh_at {
                f.refresh_eligibility_using_cloud(auth);
            }
            w.cache.clear();
            for (id, inputs) in proposals {
                w.cache.push_back(Work {
                    id,
                    inputs,
                    observation: Arc::new(Observation::new(
                        &f.eligibility,
                        Instant::now(),
                        f.original_scope(),
                    )),
                    intent: None,
                });
            }
            let before = api.requests.borrow().len();
            let result = step(f, auth, &mut w, &api);
            assert!(
                result.is_ok(),
                "fairness turn={turn} requests_before={before} requests_after={} error={:?} {}",
                api.requests.borrow().len(),
                result.as_ref().err().map(step_error_class),
                fixture_diagnostics(f),
            );
            assert!(api.requests.borrow().len() <= before + 1);
            // Drain the one live output slot, as the ingress consumer does.
            // Keeping a valid handoff applies intentional backpressure before
            // scheduling; it does not exercise fresh-versus-recovery fairness.
            if let Some(handoff) = w.take_admitted() {
                assert!(
                    handoff
                        .check_current(auth, f.runtime(), &f.eligibility)
                        .is_ok()
                );
                assert_eq!(
                    f.store
                        .lock()
                        .unwrap()
                        .acknowledged_channel_admissions()
                        .unwrap()
                        .into_iter()
                        .find(|ack| ack == handoff.acknowledgement()),
                    Some(handoff.acknowledgement().clone())
                );
            }
            if f.store
                .lock()
                .unwrap()
                .acknowledged_channel_admissions()
                .unwrap()
                .iter()
                .any(|a| a.intent == old)
            {
                completed = Some(turn + 1);
                break;
            }
        }
        assert!(completed.is_some_and(|turn| turn <= 6));
        assert!(
            api.requests
                .borrow()
                .contains(&("GET", old.preparation.channel_id))
        );
        assert!(
            api.requests
                .borrow()
                .contains(&("POST", old.preparation.channel_id))
        );
    });
}
#[test]
fn sixty_four_unknowns_reserve_due_poll_and_do_not_evict_intents() {
    fixture(|f, auth| {
        let input = inputs(f, auth, false);
        let api = Api::poll(input);
        let (_, base) = prepared(f, auth, &api);
        let mut all = vec![base.clone()];
        for n in 1..64 {
            let mut p = base.preparation.clone();
            let mut c = ChannelContextV3::from_canonical(
                &hex_bytes(p.inputs.expected_context.expose_wire())
                    .ok()
                    .unwrap(),
            )
            .unwrap();
            c.channel_id = (n as u128 + 100).to_be_bytes();
            p.channel_id = ChannelId::from_bytes(c.channel_id).unwrap();
            p.inputs.expected_context = hex(&c.canonical().unwrap()).try_into().unwrap();
            p.params.admission = auth
                .sign_channel_admission_v3(&c, f.now())
                .unwrap()
                .to_wire()
                .unwrap();
            all.push(
                f.store
                    .lock()
                    .unwrap()
                    .prepare_channel_admission(p, f.now())
                    .unwrap(),
            );
        }
        let mut w = Worker::default();
        for _ in 0..3 {
            api.replies
                .borrow_mut()
                .push_back(Reply::Error(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::AuthRequired,
                )));
        }
        api.replies
            .borrow_mut()
            .push_back(Reply::Poll(ChannelPendingResult {
                channels: vec![].try_into().unwrap(),
            }));
        for _ in 0..4 {
            assert!(step(f, auth, &mut w, &api).is_ok());
        }
        assert_eq!(
            *api.requests.borrow(),
            ["POLL", "GET", "GET", "GET", "POLL"]
        );
        let retained = f
            .store
            .lock()
            .unwrap()
            .pending_channel_admissions()
            .unwrap();
        assert_eq!(retained.len(), all.len());
        assert!(all.iter().all(|i| retained.contains(i)));
    });
}
#[test]
fn reserved_capacity_stops_new_approval_before_any_post() {
    fixture(|f, auth| {
        let input = inputs(f, auth, false);
        let api = Api::poll(input.clone());
        let (_, base) = prepared(f, auth, &api);
        for n in 1..64 {
            let mut p = base.preparation.clone();
            let mut c = ChannelContextV3::from_canonical(
                &hex_bytes(p.inputs.expected_context.expose_wire())
                    .ok()
                    .unwrap(),
            )
            .unwrap();
            c.channel_id = (n as u128 + 100).to_be_bytes();
            p.channel_id = ChannelId::from_bytes(c.channel_id).unwrap();
            p.inputs.expected_context = hex(&c.canonical().unwrap()).try_into().unwrap();
            p.params.admission = auth
                .sign_channel_admission_v3(&c, f.now())
                .unwrap()
                .to_wire()
                .unwrap();
            f.store
                .lock()
                .unwrap()
                .prepare_channel_admission(p, f.now())
                .unwrap();
        }
        let mut changed = input;
        let mut c = ChannelContextV3::from_canonical(
            &hex_bytes(changed.expected_context.expose_wire())
                .ok()
                .unwrap(),
        )
        .unwrap();
        c.channel_id = [77; 16];
        changed.expected_context = hex(&c.canonical().unwrap()).try_into().unwrap();
        let mut w = Worker {
            scope: Some(f.eligibility.binding.scope.clone()),
            poll_at: Some(Instant::now() + Duration::from_secs(30)),
            ..Worker::default()
        };
        w.cache.push_back(Work {
            id: ChannelId::from_bytes(c.channel_id).unwrap(),
            inputs: changed,
            observation: Arc::new(Observation::new(
                &f.eligibility,
                Instant::now(),
                f.original_scope(),
            )),
            intent: None,
        });
        assert!(step(f, auth, &mut w, &api).is_ok());
        assert!(w.capacity_blocked);
        assert!(w.active.is_none());
        assert_eq!(*api.requests.borrow(), ["POLL"]);
        assert_eq!(
            f.store
                .lock()
                .unwrap()
                .pending_channel_admissions()
                .unwrap()
                .len(),
            64
        );
    });
}
#[test]
fn storage_failure_is_sealed_and_ack_rollback_remains_store_qualification_boundary() {
    assert!(matches!(
        peer::durable::<()>(Err(StoreError::Storage)),
        Err(PeerError::Fatal(StepError::Auth(
            lomi_host_auth::Error::Sealed
        )))
    ));
    // Actual injected SQLite ACK-write rollback remains exercised by the qualified
    // Store journal suite; this coordinator adds no SQLite/unsafe dependency.
}
struct PairCounter {
    calls: RefCell<usize>,
}
impl peer::PeerApi for PairCounter {
    fn pending(
        &self,
        _: HostId,
        _: &HostAccessCredential,
    ) -> Result<PairingPendingResult, lomi_host_http::Error> {
        *self.calls.borrow_mut() += 1;
        Ok(PairingPendingResult {
            pairings: vec![].try_into().unwrap(),
        })
    }
    fn get(
        &self,
        _: PairingId,
        _: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        panic!("unexpectedpairGET")
    }
    fn decide(
        &self,
        _: PairingId,
        _: &PairingDecisionParams,
        _: &HostAccessCredential,
    ) -> Result<PairingResult, lomi_host_http::Error> {
        panic!("unexpectedpairPOST")
    }
}
#[test]
fn combined_owner_loop_prioritizes_runtime_refresh_and_alternates_peer_classes() {
    for refresh in [false, true] {
        fixture(|f, auth| {
            let transport = peer::tests::PriorityAuth {
                stop: &f.stopping,
                refreshes: RefCell::new(0),
            };
            let data = peer::tests::RuntimeApi {
                binding: f.eligibility.binding.clone(),
                requests: RefCell::new(vec![]),
            };
            let pairing = PairCounter {
                calls: RefCell::new(0),
            };
            let channel = Api {
                replies: RefCell::new(
                    vec![Reply::Poll(ChannelPendingResult {
                        channels: vec![].try_into().unwrap(),
                    })]
                    .into(),
                ),
                requests: RefCell::new(vec![]),
                params: RefCell::new(vec![]),
                hook: RefCell::new(None),
            };
            if refresh {
                auth.prepare_rotation(f.now()).unwrap();
            } else {
                *channel.hook.borrow_mut() = Some(Box::new(|| {
                    assert_eq!(*pairing.calls.borrow(), 1);
                    // The settled pairing poll releases its worker unit. The
                    // channel turn must obtain its own GET/heartbeat observation.
                    assert_eq!(*data.requests.borrow(), ["GET", "HB", "GET", "HB"]);
                    f.stopping.store(true, Ordering::Release);
                }));
            }
            run_with_apis(
                auth,
                &transport,
                &f.config,
                f.runtime(),
                InjectedApis {
                    data: Some(&data),
                    pairing: Some(&pairing),
                    channel: Some(&channel),
                    enabled: true,
                    channels_enabled: true,
                },
            );
            if refresh {
                assert_eq!(*transport.refreshes.borrow(), 1);
                assert_eq!(*pairing.calls.borrow(), 0);
                assert!(channel.requests.borrow().is_empty());
                assert!(data.requests.borrow().is_empty());
            } else {
                assert_eq!(*pairing.calls.borrow(), 1);
                assert_eq!(*channel.requests.borrow(), ["POLL"]);
            }
        });
    }
}

#[test]
fn fixture_channel_signing_uses_current_original_anchor_without_rebasing_the_context() {
    fixture(|f, auth| {
        let input = inputs(f, auth, false);
        let context = ChannelContextV3::from_canonical(
            &hex_bytes(input.expected_context.expose_wire())
                .ok()
                .unwrap(),
        )
        .unwrap();
        let original_heartbeat = f.eligibility.heartbeat.request_started;
        let crossed = Arc::new(Mutex::new(Vec::new()));
        peer::tests::cross_snapshot_second(f.store.clone(), 1005, f.anchor, crossed.clone())(
            f.now(),
            f.runtime(),
        );
        auth.public_host_identity(f.now()).unwrap();
        let signed = auth.sign_channel_admission_v3(&context, f.now()).unwrap();
        assert_eq!(signed.context, context);
        assert_eq!(signed.context.issued_at, 1005);
        assert_eq!(signed.context.expires_at, 1030);
        assert_eq!(f.eligibility.heartbeat.request_started, original_heartbeat);
        assert!(
            matches!(
                auth.sign_channel_admission_v3(&context, 1005),
                Err(lomi_host_auth::Error::ClockRollback)
            ),
            "the production signing rollback guard remains enforced"
        );
        assert_eq!(crossed.lock().unwrap().len(), 1);
    });
}

#[test]
fn actual_owner_logout_after_channel_signature_prevents_admission_and_ack() {
    fixture(|f, auth| {
        let input = inputs(f, auth, false);
        let api = Api::poll(input);
        let mut worker = Worker::default();
        assert!(step(f, auth, &mut worker, &api).is_ok());
        let owner = f.owner.clone();
        worker.after_sign = Some(Box::new(move || {
            let cancel = AtomicBool::new(false);
            let operation =
                owner_domain::Operation::new(Instant::now() + Duration::from_secs(2), &cancel);
            owner
                .begin_local_logout(&operation)
                .unwrap()
                .try_commit()
                .unwrap();
        }));
        assert!(step(f, auth, &mut worker, &api).is_err());
        assert_eq!(*api.requests.borrow(), ["POLL"]);
        assert!(
            f.store
                .lock()
                .unwrap()
                .pending_channel_admissions()
                .unwrap()
                .is_empty()
        );
        assert!(
            f.store
                .lock()
                .unwrap()
                .acknowledged_channel_admissions()
                .unwrap()
                .is_empty()
        );
    });
}

#[test]
fn admitted_driver_rejects_replacement_operation_owner_expiry_and_actual_latches() {
    for variant in 0..6 {
        fixture(|f, auth| {
            eprintln!("driver-latches variant={variant}");
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (mut worker, intent) = prepared(f, auth, &api);
            api.replies
                .borrow_mut()
                .push_back(Reply::state(admitted(&intent)));
            let result = step(f, auth, &mut worker, &api);
            assert!(
                result.is_ok(),
                "admission setup variant={variant} requests={:?} error={:?} {}",
                api.requests.borrow(),
                result.as_ref().err().map(step_error_class),
                fixture_diagnostics(f),
            );
            let mut driver = driver_for_ticket(&intent);
            driver.after_channel_step(&mut worker, auth, f.runtime(), &f.eligibility);
            assert!(
                driver.has_retained_operation(),
                "driver admission variant={variant} observation={:?} requests={:?} {}",
                driver.channel_step_observation_for_test(),
                api.requests.borrow(),
                fixture_diagnostics(f),
            );
            assert!(driver.poll(auth, f.runtime(), Some(&f.eligibility)));
            match variant {
                0 => {
                    let cancelled = AtomicBool::new(false);
                    let replacement =
                        owner_domain::Operation::new(f.runtime().operation.deadline(), &cancelled);
                    let runtime = Runtime {
                        operation: &replacement,
                        ..f.runtime()
                    };
                    assert!(!driver.poll(auth, runtime, Some(&f.eligibility)));
                }
                1 => {
                    // New wall samples may shorten validity, never extend the
                    // original runtime-anchor-derived channel expiry.
                    let runtime = Runtime {
                        base: 1030,
                        ..f.runtime()
                    };
                    assert!(!driver.poll(auth, runtime, Some(&f.eligibility)));
                }
                2 => {
                    f.runtime().operation.expire_for_test();
                    assert!(!driver.poll(auth, f.runtime(), Some(&f.eligibility)));
                }
                3 => {
                    f.gate.store(true, Ordering::Release);
                    assert!(!driver.poll(auth, f.runtime(), Some(&f.eligibility)));
                    f.gate.store(false, Ordering::Release);
                }
                4 => fixture(|other, _| {
                    let runtime = Runtime {
                        owner: &other.owner,
                        ..f.runtime()
                    };
                    assert!(!driver.poll(auth, runtime, Some(&f.eligibility)));
                }),
                _ => {
                    // Normal owner work continues; a different writer invalidates
                    // the preparation instead of being delayed by the driver.
                    let mut writer = f
                        .owner
                        .begin_unshare(f.runtime().operation, f.workspace)
                        .unwrap();
                    assert!(!driver.poll(auth, f.runtime(), Some(&f.eligibility)));
                    writer.try_commit().unwrap();
                }
            }
            assert!(!driver.has_retained_operation());
            assert!(
                !driver.poll(auth, f.runtime(), Some(&f.eligibility)),
                "discarded provenance cannot revive"
            );
        });
    }
}

#[test]
fn admitted_driver_slot_cannot_overwrite_original_candidate() {
    fixture(|f, auth| {
        let input = inputs(f, auth, false);
        let api = Api::poll(input);
        let (mut worker, intent) = prepared(f, auth, &api);
        api.replies
            .borrow_mut()
            .push_back(Reply::state(admitted(&intent)));
        assert!(step(f, auth, &mut worker, &api).is_ok());
        let mut driver = driver_for_ticket(&intent);
        driver.after_channel_step(&mut worker, auth, f.runtime(), &f.eligibility);
        fixture(|other, other_auth| {
            let input = inputs(other, other_auth, true);
            let api = Api::poll(input);
            let (mut worker, intent) = prepared(other, other_auth, &api);
            api.replies
                .borrow_mut()
                .push_back(Reply::state(admitted(&intent)));
            assert!(step(other, other_auth, &mut worker, &api).is_ok());
            let handoff = worker.take_admitted().unwrap();
            assert!(!driver.accept(handoff, other_auth, other.runtime(), &other.eligibility));
        });
        assert!(
            driver.poll(auth, f.runtime(), Some(&f.eligibility)),
            "full slot retained original owner/operation"
        );
        driver.discard();
        assert!(!driver.has_retained_operation());
        assert!(Worker::default().take_admitted().is_none());
    });
}

#[test]
fn live_ack_ticket_stage_is_once_budgeted_guard_free_and_caches_from_request_start() {
    fixture(|f, auth| {
        let input = inputs(f, auth, true);
        let api = Api::poll(input);
        let (mut worker, intent) = prepared(f, auth, &api);
        api.replies
            .borrow_mut()
            .push_back(Reply::state(admitted(&intent)));
        assert!(step(f, auth, &mut worker, &api).is_ok());
        let owner = f.owner.clone();
        let store = f.store.clone();
        let expected_id = intent.preparation.channel_id;
        let expected_runtime = intent.preparation.scope.runtime.clone();
        let original_identity = f.runtime().operation.retained_identity();
        let original_deadline = f.runtime().operation.deadline();
        let mut driver = super::super::remote_ingress::Driver::default();
        let calls = driver.script_ticket_for_test(
            Ok(ticket_response(&intent)),
            Some(Box::new(move |id, params, operation, watch| {
                assert_eq!(id, expected_id);
                assert_eq!(params.runtime, expected_runtime);
                assert!(operation.is_same_admission(&original_identity));
                assert_eq!(operation.deadline(), original_deadline);
                assert!(
                    owner.auth_status(operation).is_ok(),
                    "Domain/Store must be free at ticket IO"
                );
                let held_store = store.lock().unwrap();
                assert!(
                    watch().is_ok(),
                    "watcher cannot reacquire Store or provider/Domain"
                );
                drop(held_store);
            })),
            Duration::ZERO,
        );
        driver.after_channel_step(&mut worker, auth, f.runtime(), &f.eligibility);
        assert_eq!(calls.get(), 1);
        let (started, expiry, ttl) = driver
            .ticket_timing_for_test()
            .expect("one retained ticket");
        assert_eq!(ttl, 5000);
        assert_eq!(
            expiry,
            (started + Duration::from_millis(ttl))
                .min(original_deadline)
                .min(f.anchor + Duration::from_secs(25))
        );
        assert!(driver.poll(auth, f.runtime(), Some(&f.eligibility)));
        driver.after_channel_step(&mut worker, auth, f.runtime(), &f.eligibility);
        assert_eq!(calls.get(), 1, "ticket cache must not issue another POST");
        driver.discard();
        assert!(!driver.has_retained_operation());
        assert!(driver.ticket_timing_for_test().is_none());
    });
}

#[test]
fn exact_ack_source_and_current_local_ticket_facts_deny_before_http() {
    for variant in 0..10 {
        fixture(|f, auth| {
            eprintln!("ticket-denial variant={variant}");
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (mut worker, intent) = prepared(f, auth, &api);
            api.replies
                .borrow_mut()
                .push_back(Reply::state(admitted(&intent)));
            let result = step(f, auth, &mut worker, &api);
            assert!(
                result.is_ok(),
                "admission setup variant={variant} requests={:?} error={:?} {}",
                api.requests.borrow(),
                result.as_ref().err().map(step_error_class),
                fixture_diagnostics(f),
            );
            // Only this descendant fixture can fault private handoff fields;
            // production callers cannot construct/clone these sealed values.
            let mut configuration_writer = None;
            match variant {
                0 => worker
                    .pending_handoff
                    .as_mut()
                    .unwrap()
                    .acknowledgement
                    .intent
                    .token
                    .push('x'),
                1 => worker
                    .pending_handoff
                    .as_mut()
                    .unwrap()
                    .source
                    .intent
                    .token
                    .push('x'),
                2 => {
                    worker
                        .pending_handoff
                        .as_mut()
                        .unwrap()
                        .scope
                        .workspace_fence += 1
                }
                3 => {
                    worker
                        .pending_handoff
                        .as_mut()
                        .unwrap()
                        .scope
                        .workspace_epoch = WorkspaceEpoch::from_bytes([97; 16]).unwrap()
                }
                4 => {
                    f.store.lock().unwrap().unshare(f.workspace).unwrap();
                }
                5 => f.eligibility.binding.server_runtime.runtime_generation.0 += 1,
                6 => f.eligibility.binding.scope.remote_api_origin = "https://other.example".into(),
                7 => {
                    let ack = worker
                        .pending_handoff
                        .as_ref()
                        .unwrap()
                        .acknowledgement
                        .clone();
                    f.store
                        .lock()
                        .unwrap()
                        .retire_acknowledged_channel_admission(&ack)
                        .unwrap();
                }
                8 => {
                    let mut configuration = f
                        .store
                        .lock()
                        .unwrap()
                        .auth_configuration()
                        .unwrap()
                        .unwrap();
                    // Existing origins are immutable after public migration.
                    // Announce a legal independent relay first-fill through the
                    // actual owner; retain that writer across ticket admission.
                    assert!(configuration.relay_endpoint.is_none());
                    configuration.relay_endpoint = Some(
                        "wss://relay.example/v2/relay"
                            .to_owned()
                            .try_into()
                            .unwrap(),
                    );
                    configuration_writer = Some(
                        f.owner
                            .begin_public_configuration(f.runtime().operation, configuration)
                            .unwrap(),
                    );
                }
                _ => f.runtime().operation.expire_for_test(),
            }
            let mut driver = super::super::remote_ingress::Driver::default();
            let calls =
                driver.script_ticket_for_test(Ok(ticket_response(&intent)), None, Duration::ZERO);
            driver.after_channel_step(&mut worker, auth, f.runtime(), &f.eligibility);
            assert_eq!(
                calls.get(),
                0,
                "changed exact/current facts must deny the ticket effect"
            );
            assert!(!driver.has_retained_operation());
            assert!(driver.ticket_timing_for_test().is_none());
            if let Some(writer) = configuration_writer {
                assert!(
                    writer.is_pending(),
                    "the same announced writer remains retained"
                );
            }
        });
    }
}

#[test]
fn ticket_unknown_malformed_delayed_and_postresponse_change_never_cache_or_retry() {
    for variant in 0..10 {
        fixture(|f, auth| {
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (mut worker, intent) = prepared(f, auth, &api);
            api.replies
                .borrow_mut()
                .push_back(Reply::state(admitted(&intent)));
            assert!(step(f, auth, &mut worker, &api).is_ok());
            let mut response = ticket_response(&intent);
            match variant {
                0 => response.channel_id = ChannelId::from_bytes([97; 16]).unwrap(),
                1 => response.expires_in_ms = DecimalU64(0),
                2 => response.expires_in_ms = DecimalU64(5001),
                3 => response.ticket = "short".to_owned().try_into().unwrap(),
                4 => response.ticket = "A".repeat(129).try_into().unwrap(),
                _ => {}
            }
            let response = match variant {
                5 => Err(lomi_host_http::Error::Timeout),
                6 => Err(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::AuthRequired,
                )),
                _ => Ok(response),
            };
            let store = f.store.clone();
            let workspace = f.workspace;
            let hook: Option<super::super::remote_ingress::TicketTestHook> = if variant == 7 {
                Some(Box::new(move |_, _, _, _| {
                    store.lock().unwrap().unshare(workspace).unwrap();
                }))
            } else if variant == 9 {
                Some(Box::new(move |_, _, operation, watch| {
                    let actual_cancelled = operation.cancellation_latch();
                    actual_cancelled.store(true, Ordering::Release);
                    assert!(watch().is_err());
                    actual_cancelled.store(false, Ordering::Release);
                    assert!(
                        watch().is_err(),
                        "same original cancellation remains sticky"
                    );
                }))
            } else {
                None
            };
            let elapsed = if variant == 8 {
                Duration::from_secs(6)
            } else {
                Duration::ZERO
            };
            let mut driver = super::super::remote_ingress::Driver::default();
            let calls = driver.script_ticket_for_test(response, hook, elapsed);
            driver.after_channel_step(&mut worker, auth, f.runtime(), &f.eligibility);
            assert_eq!(calls.get(), 1);
            assert!(!driver.has_retained_operation());
            assert!(driver.ticket_timing_for_test().is_none());
            assert!(!driver.poll(auth, f.runtime(), Some(&f.eligibility)));
            driver.after_channel_step(&mut worker, auth, f.runtime(), &f.eligibility);
            assert_eq!(
                calls.get(),
                1,
                "uncertain/failed ticket request is never replayed"
            );
            assert_eq!(
                auth.status(),
                Status::Ready,
                "resource-local failure is not a host credential rejection"
            );
            assert!(!f.gate.load(Ordering::Acquire));
        });
    }
}

#[test]
fn ticket_effect_retains_its_own_clock_checkpoint_without_adopting_postresponse_mutation() {
    for changed_after_post in [false, true] {
        fixture(|f, auth| {
            let input = inputs(f, auth, false);
            let api = Api::poll(input);
            let (mut worker, intent) = prepared(f, auth, &api);
            api.replies
                .borrow_mut()
                .push_back(Reply::state(admitted(&intent)));
            assert!(step(f, auth, &mut worker, &api).is_ok());
            let before = f
                .store
                .lock()
                .unwrap()
                .authorization_state()
                .unwrap()
                .clock_floor;
            // A forward trusted wall sample without sleeping or replacing the
            // original operation, anchor, observation or admitted deadline.
            let original = f.runtime();
            let runtime = Runtime {
                base: original.base + 1,
                ..original
            };
            let deadline = runtime.operation.deadline();
            let identity = runtime.operation.retained_identity();
            let store = f.store.clone();
            let workspace = f.workspace;
            let mut driver = super::super::remote_ingress::Driver::default();
            let hook: Option<super::super::remote_ingress::TicketTestHook> = if changed_after_post {
                Some(Box::new(move |_, _, _, _| {
                    store.lock().unwrap().unshare(workspace).unwrap();
                }))
            } else {
                None
            };
            let calls =
                driver.script_ticket_for_test(Ok(ticket_response(&intent)), hook, Duration::ZERO);
            driver.after_channel_step(&mut worker, auth, runtime, &f.eligibility);
            assert_eq!(calls.get(), 1);
            assert!(
                f.store
                    .lock()
                    .unwrap()
                    .authorization_state()
                    .unwrap()
                    .clock_floor
                    > before
            );
            assert!(runtime.operation.is_same_admission(&identity));
            assert_eq!(runtime.operation.deadline(), deadline);
            if changed_after_post {
                assert!(driver.ticket_timing_for_test().is_none());
                assert!(
                    !driver.has_retained_operation(),
                    "unrelated post-response change cannot be rebased"
                );
            } else {
                assert!(
                    driver.ticket_timing_for_test().is_some(),
                    "own successful checkpoint must not stale the effect"
                );
                assert!(driver.poll(auth, runtime, Some(&f.eligibility)));
                assert_eq!(calls.get(), 1);
            }
        });
    }
}

#[path = "remote_ingress_driver_tests.rs"]
mod ingress_driver_tests;
