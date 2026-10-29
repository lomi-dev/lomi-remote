//! Actual TLS/WebSocket/native Noise + Rename/Move and Create/Split/Close/Restart
//! ingress. Effect cases spawn/stop real host-local `/bin/sh` PTYs.
//! Move fixture creates two actual host-local PTYs;
//! Reuses the existing native-client handshake and authenticated owner fixture.
//! Synthetic cloud approval/ACK responses are applied through actual Store APIs;
//! this fixture does not qualify cloud HTTP publication transport.
use super::*;

fn send_request(client: &mut NativeClient, call: RpcCall, ordinal: u8) -> RpcRequest {
    let request = RpcRequest {
        v: ApplicationMajor,
        r#type: RequestKind::Request,
        request_id: format!("rename-original-request-{ordinal}")
            .try_into()
            .unwrap(),
        timeout_ms: if matches!(
            &call,
            RpcCall::GitRepositories(_)
                | RpcCall::GitStatus(_)
                | RpcCall::GitDiff(_)
                | RpcCall::GitLog(_)
                | RpcCall::GitShow(_)
        ) {
            15_000u64
        } else {
            4000u64
        }
        .try_into()
        .unwrap(),
        call,
    };
    client
        .encoder
        .begin(
            MessageKind::RpcRequest,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
    while let Some(frame) = client.encoder.next_frame().unwrap() {
        client
            .socket
            .send(Message::Binary(
                client
                    .crypto
                    .seal_binary(client.channel, &frame)
                    .unwrap()
                    .into(),
            ))
            .unwrap();
    }
    request
}
fn read_result(client: &mut NativeClient, request: &RpcRequest, message_id: u64) -> RpcResult {
    let message = client.message();
    assert_eq!(message.kind, MessageKind::RpcResponse);
    assert_eq!(
        message.id, message_id,
        "edit restarted or bypassed the connection encoder"
    );
    match lomi_remote_protocol::decode_response_for(&message.bytes, request).unwrap() {
        RpcResponse::Result { result, .. } => result,
        error => panic!("edit fixture rejected: {error:?}"),
    }
}

// Fixture-only closed cases. No extra production mutation or authority path.
#[derive(Clone, Copy)]
enum EditFixture {
    Rename,
    MoveSameTabBefore,
    MoveCrossTabAfter,
    // Effect lifecycle. Create starts from the source-only fixture terminal;
    // the others start from two real local PTYs in two tabs.
    Create,
    Split,
    Close,
    Restart,
}
impl EditFixture {
    fn is_effect(self) -> bool {
        matches!(
            self,
            Self::Create | Self::Split | Self::Close | Self::Restart
        )
    }
}
fn call_response(client: &mut NativeClient, call: RpcCall, ordinal: u8) -> RpcResponse {
    let request = send_request(client, call, ordinal);
    let message = client.message();
    assert_eq!(message.kind, MessageKind::RpcResponse);
    assert_eq!(message.id, u64::from(ordinal));
    lomi_remote_protocol::decode_response_for(&message.bytes, &request).unwrap()
}

/// Real-wire Explorer script on ONE connection: every read goes through the
/// production gate/response path; every refusal keeps the connection usable.
fn files_script(client: &mut NativeClient, context: &WorkspaceContext, root: EntryId) {
    use lomi_remote_protocol::rpc::{
        EntryKind, FileEncoding, FilesListParams, FilesReadParams, FilesSearchNamesParams,
        FilesStatParams, LineEndings, PageLimit, PreviewLimit,
    };
    let mut ordinal = 1u8;
    let mut next = || {
        ordinal += 1;
        ordinal
    };
    let list = |client: &mut NativeClient, parent: EntryId, ordinal: u8| match call_response(
        client,
        RpcCall::FilesList(FilesListParams {
            context: context.clone(),
            parent_entry_id: parent,
            cursor: None,
            limit: PageLimit::try_from(200).unwrap(),
        }),
        ordinal,
    ) {
        RpcResponse::Result {
            result: RpcResult::FilesList(list),
            ..
        } => list,
        other => panic!("files.list failed: {other:?}"),
    };
    let error_code = |response: RpcResponse| match response {
        RpcResponse::Error { error, .. } => {
            assert_eq!(error.effect(), Effect::None);
            error.code()
        }
        other => panic!("expected an error response, got {other:?}"),
    };
    let read = |client: &mut NativeClient, entry: EntryId, rev: Option<FileRevision>, ordinal| {
        call_response(
            client,
            RpcCall::FilesRead(FilesReadParams {
                context: context.clone(),
                entry_id: entry,
                file_revision: rev,
                offset: DecimalU64(0),
                max_bytes: PreviewLimit::try_from(4096).unwrap(),
            }),
            ordinal,
        )
    };
    let top = list(client, root, next());
    let find = |name: &str, list: &lomi_remote_protocol::rpc::FilesListResult| {
        list.entries
            .0
            .iter()
            .find(|e| e.display_name.as_str() == name)
            .unwrap_or_else(|| panic!("{name} missing from listing"))
            .clone()
    };
    let hello = find("hello.txt", &top);
    assert_eq!(hello.kind, EntryKind::File);
    match read(
        client,
        hello.entry_id,
        Some(hello.file_revision.clone()),
        next(),
    ) {
        RpcResponse::Result {
            result: RpcResult::FilesRead(read),
            ..
        } => {
            assert_eq!(read.encoding, FileEncoding::Utf8);
            assert_eq!(read.line_endings, LineEndings::CrLf);
            assert_eq!(read.bytes.0, "héllo\r\nworld\r\n".as_bytes());
            assert!(!read.truncated);
        }
        other => panic!("files.read failed: {other:?}"),
    }
    // Stat and a nested listing through the entry id handed out by the host.
    let docs = find("docs", &top);
    assert_eq!(docs.kind, EntryKind::Directory);
    match call_response(
        client,
        RpcCall::FilesStat(FilesStatParams {
            context: context.clone(),
            entry_id: docs.entry_id,
            file_revision: Some(docs.file_revision.clone()),
        }),
        next(),
    ) {
        RpcResponse::Result {
            result: RpcResult::FilesStat(meta),
            ..
        } => assert_eq!(meta.entry_id, docs.entry_id),
        other => panic!("files.stat failed: {other:?}"),
    }
    let nested = list(client, docs.entry_id, next());
    assert_eq!(find("note.md", &nested).kind, EntryKind::File);
    match call_response(
        client,
        RpcCall::FilesSearchNames(FilesSearchNamesParams {
            context: context.clone(),
            parent_entry_id: root,
            query: "NOTE".to_owned().try_into().unwrap(),
            cursor: None,
            limit: PageLimit::try_from(10).unwrap(),
        }),
        next(),
    ) {
        RpcResponse::Result {
            result: RpcResult::FilesSearchNames(found),
            ..
        } => {
            assert_eq!(found.entries.0.len(), 1);
            assert_eq!(found.entries.0[0].display_name.as_str(), "note.md");
        }
        other => panic!("files.searchNames failed: {other:?}"),
    }
    // Refusals: each is an ordinary error and the connection survives them all.
    let linked = top
        .entries
        .0
        .iter()
        .any(|e| e.display_name.as_str() == "outside-link");
    assert!(
        linked || cfg!(windows),
        "unix must always have created the symlink"
    );
    if linked {
        let link = find("outside-link", &top);
        assert_eq!(link.kind, EntryKind::Symlink);
        assert_eq!(
            error_code(read(client, link.entry_id, None, next())),
            ErrorCode::InvalidArgument
        );
    }
    assert_eq!(
        error_code(read(client, find("hard.txt", &top).entry_id, None, next())),
        ErrorCode::ProtectedPath
    );
    assert_eq!(
        error_code(read(
            client,
            hello.entry_id,
            Some("rdeadbeef".to_owned().try_into().unwrap()),
            next()
        )),
        ErrorCode::FileChanged
    );
    assert_eq!(
        error_code(read(
            client,
            EntryId::from_bytes([9; 16]).unwrap(),
            None,
            next()
        )),
        ErrorCode::ResourceNotFound
    );
    match read(client, find("bin.dat", &top).entry_id, None, next()) {
        RpcResponse::Result {
            result: RpcResult::FilesRead(read),
            ..
        } => {
            assert_eq!(read.encoding, FileEncoding::Binary);
            assert!(
                read.bytes.0.is_empty() && read.truncated,
                "binary content is withheld"
            );
        }
        other => panic!("binary read failed: {other:?}"),
    }
    // Still alive after all refusals.
    assert_eq!(
        list(client, root, next()).entries.0.len(),
        top.entries.0.len()
    );
}

/// Reads host frames until the response to `request` arrives, collecting every
/// `files.watch` frame that was interleaved. Message ids are not asserted:
/// watch frames legitimately advance the host's connection encoder.
fn exchange(
    client: &mut NativeClient,
    call: RpcCall,
    ordinal: u8,
) -> (RpcResponse, Vec<lomi_remote_protocol::FileWatchFrame>) {
    let request = send_request(client, call, ordinal);
    let mut frames = Vec::new();
    loop {
        let message = client.message();
        match message.kind {
            MessageKind::FileWatchFrame => {
                frames.push(lomi_remote_protocol::decode_watch_frame(&message.bytes).unwrap())
            }
            MessageKind::RpcResponse => {
                return (
                    lomi_remote_protocol::decode_response_for(&message.bytes, &request).unwrap(),
                    frames,
                );
            }
            other => panic!("unexpected message kind {other:?}"),
        }
    }
}
fn next_watch_frame(client: &mut NativeClient) -> lomi_remote_protocol::FileWatchFrame {
    let message = client.message();
    assert_eq!(message.kind, MessageKind::FileWatchFrame);
    lomi_remote_protocol::decode_watch_frame(&message.bytes).unwrap()
}
fn send_watch_ack(
    client: &mut NativeClient,
    context: &WorkspaceContext,
    subscription: &lomi_remote_protocol::rpc::SubscriptionId,
    through: u64,
    cursor: &EventCursor,
) {
    let ack =
        lomi_remote_protocol::FileWatchFrame::Ack(lomi_remote_protocol::streams::FileWatchAck {
            context: context.clone(),
            subscription_id: subscription.clone(),
            through_seq: lomi_remote_protocol::streams::WatchSeq(DecimalU64(through)),
            cursor: cursor.clone(),
        });
    client
        .encoder
        .begin(
            MessageKind::FileWatchFrame,
            serde_json::to_vec(&ack).unwrap(),
        )
        .unwrap();
    while let Some(frame) = client.encoder.next_frame().unwrap() {
        client
            .socket
            .send(Message::Binary(
                client
                    .crypto
                    .seal_binary(client.channel, &frame)
                    .unwrap()
                    .into(),
            ))
            .unwrap();
    }
}
/// Real-wire `files.watch` on ONE connection: a change is announced once as an
/// invalidation of the watched directory (never as content), acknowledgements
/// are accepted, a stale resume cursor is invalidated immediately, and an
/// acknowledgement for an unsent sequence ends the connection.
fn files_watch_script(
    client: &mut NativeClient,
    context: &WorkspaceContext,
    root: EntryId,
    disk: &std::path::Path,
) {
    // The fixture root also holds the live host database, whose journal changes
    // constantly; watch the project's own `docs` directory instead.
    let disk = &disk.join("docs");
    let docs = {
        let (response, _) = exchange(
            client,
            RpcCall::FilesList(lomi_remote_protocol::rpc::FilesListParams {
                context: context.clone(),
                parent_entry_id: root,
                cursor: None,
                limit: lomi_remote_protocol::rpc::PageLimit::try_from(200).unwrap(),
            }),
            1,
        );
        let RpcResponse::Result {
            result: RpcResult::FilesList(listing),
            ..
        } = response
        else {
            panic!("files.list failed")
        };
        listing
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "docs")
            .expect("fixture docs directory")
            .entry_id
    };
    let root = docs;
    use lomi_remote_protocol::FileWatchFrame;
    use lomi_remote_protocol::rpc::{FilesListParams, FilesWatchParams, PageLimit};
    // Atomic replace from outside the watched directory: one observable change
    // per call, never a truncated intermediate state.
    let place = |disk: &std::path::Path, bytes: &[u8]| {
        let staging = disk.parent().unwrap().join("lomi-watch-staging");
        std::fs::write(&staging, bytes).unwrap();
        std::fs::rename(&staging, disk.join("watched.txt")).unwrap();
    };
    let watch = |client: &mut NativeClient, cursor: Option<EventCursor>, ordinal: u8| match exchange(
        client,
        RpcCall::FilesWatch(FilesWatchParams {
            context: context.clone(),
            entry_id: root,
            cursor,
        }),
        ordinal,
    ) {
        (
            RpcResponse::Result {
                result: RpcResult::FilesWatch(result),
                ..
            },
            frames,
        ) => (result, frames),
        other => panic!("files.watch failed: {other:?}"),
    };
    let (first, frames) = watch(client, None, 2);
    assert!(frames.is_empty(), "nothing changed yet");
    assert_eq!(first.through_seq.0.0, 0);
    // A new entry is announced exactly once, as an invalidation of the root.
    place(disk, b"one");
    let FileWatchFrame::Invalidated(event) = next_watch_frame(client) else {
        panic!("expected an invalidation")
    };
    assert_eq!(event.subscription_id, first.subscription_id);
    assert_eq!(event.context, *context);
    assert_eq!(event.watch_seq.0.0, 1);
    assert_ne!(
        event.cursor, first.cursor,
        "the cursor moves with the state"
    );
    assert_eq!(event.invalidation.entries.0, vec![root]);
    assert!(!event.invalidation.overflow);
    send_watch_ack(client, context, &first.subscription_id, 1, &event.cursor);
    // The connection is alive and the listing shows the new entry.
    let (response, frames) = exchange(
        client,
        RpcCall::FilesList(FilesListParams {
            context: context.clone(),
            parent_entry_id: root,
            cursor: None,
            limit: PageLimit::try_from(200).unwrap(),
        }),
        3,
    );
    assert!(frames.is_empty());
    let RpcResponse::Result {
        result: RpcResult::FilesList(listing),
        ..
    } = response
    else {
        panic!("files.list failed")
    };
    assert!(
        listing
            .entries
            .0
            .iter()
            .any(|entry| entry.display_name.as_str() == "watched.txt")
    );
    // A content change inside the directory is the next sequence.
    place(disk, b"two-changed");
    let FileWatchFrame::Invalidated(second) = next_watch_frame(client) else {
        panic!("expected a second invalidation")
    };
    assert_eq!(second.watch_seq.0.0, 2);
    assert_ne!(second.cursor, event.cursor);
    send_watch_ack(client, context, &first.subscription_id, 2, &second.cursor);
    // Resuming from a cursor the client saw before the changes is invalidated
    // at once, so a reconnecting client never misses a change.
    let (resumed, frames) = watch(client, Some(first.cursor.clone()), 4);
    assert!(frames.is_empty());
    assert_ne!(resumed.subscription_id, first.subscription_id);
    let FileWatchFrame::Invalidated(stale) = next_watch_frame(client) else {
        panic!("a stale cursor must be invalidated")
    };
    assert_eq!(stale.subscription_id, resumed.subscription_id);
    assert_eq!(stale.watch_seq.0.0, 1);
    assert_eq!(stale.cursor, second.cursor);
    // Resuming from the current cursor is quiet.
    send_watch_ack(client, context, &resumed.subscription_id, 1, &stale.cursor);
    let (quiet, frames) = watch(client, Some(stale.cursor.clone()), 5);
    assert!(frames.is_empty());
    assert_eq!(quiet.cursor, stale.cursor);
    // An acknowledgement for a sequence that was never sent is a violation.
    send_watch_ack(client, context, &quiet.subscription_id, 9, &stale.cursor);
    assert!(
        client.try_message().is_none(),
        "a bad ack must close the connection"
    );
}

#[derive(Clone, Copy)]
enum FilesMode {
    Read,
    Mutate,
    /// `files.watch` invalidation frames, acknowledgements and resume.
    Watch,
    /// The grant lacks GitRead: Git methods are refused fail-closed.
    GitRefused,
    /// All five isolated Git read RPCs on the ordinary encrypted connection.
    GitRead,
    /// Unshare while a Git job/result is pending, before any disclosure.
    GitRevoke,
    /// Revoke after the first physical fragment of a larger Git diff.
    GitFragmentRevoke,
    /// A competing Shared writer commits between the durable start and the
    /// syscall: the effect must never run.
    Fenced,
}

/// Real-wire Explorer mutations on ONE connection. Every effect happens at
/// most once, refusals are ordinary errors, and the connection survives them.
fn git_read_script(client: &mut NativeClient, context: &WorkspaceContext, revoke_fragment: bool) {
    let RpcResponse::Result {
        result: RpcResult::GitRepositories(repositories),
        ..
    } = call_response(
        client,
        RpcCall::GitRepositories(WorkspaceReadParams {
            context: context.clone(),
        }),
        2,
    )
    else {
        panic!("Git repositories result");
    };
    assert_eq!(repositories.repositories.0.len(), 1);
    let repository_id = repositories.repositories.0[0].repository_id;
    let RpcResponse::Result {
        result: RpcResult::GitStatus(status),
        ..
    } = call_response(
        client,
        RpcCall::GitStatus(GitStatusParams {
            context: context.clone(),
            repository_id,
            state_token: None,
            cursor: None,
            limit: 20u32.try_into().unwrap(),
        }),
        3,
    )
    else {
        panic!("Git status result");
    };
    assert_eq!(status.entries.0.len(), 1);
    assert_eq!(status.entries.0[0].worktree, GitChange::Modified);
    let diff_call = RpcCall::GitDiff(GitDiffParams {
        context: context.clone(),
        repository_id,
        state_token: status.state_token.clone(),
        entry_id: None,
        view: DiffView::Worktree,
        cursor: None,
        limit: 20u32.try_into().unwrap(),
    });
    if revoke_fragment {
        let _ = send_request(client, diff_call, 4);
        let plaintext = client
            .crypto
            .open_binary(client.channel, &binary(&mut client.socket))
            .unwrap();
        assert!(
            client
                .decoder
                .push(&plaintext, client.started.elapsed().as_millis() as u64)
                .unwrap()
                .is_none(),
            "first fragment must not complete the diff"
        );
        loop {
            match client.socket.read() {
                Err(_) | Ok(Message::Close(_)) => break,
                Ok(Message::Ping(_)) => client.socket.flush().unwrap(),
                Ok(Message::Pong(_)) => (),
                other => panic!("unshare disclosed another Git fragment: {other:?}"),
            }
        }
        return;
    }
    let RpcResponse::Result {
        result: RpcResult::GitDiff(diff),
        ..
    } = call_response(client, diff_call, 4)
    else {
        panic!("Git diff result");
    };
    assert_eq!(diff.files.0.len(), 1);
    assert!(
        diff.files.0[0]
            .hunks
            .0
            .iter()
            .flat_map(|h| &h.lines.0)
            .any(|line| line.kind == DiffLineKind::Added && line.text.as_str().contains("after"))
    );
    let RpcResponse::Result {
        result: RpcResult::GitLog(log),
        ..
    } = call_response(
        client,
        RpcCall::GitLog(GitLogParams {
            context: context.clone(),
            repository_id,
            state_token: status.state_token.clone(),
            cursor: None,
            limit: 20u32.try_into().unwrap(),
        }),
        5,
    )
    else {
        panic!("Git log result");
    };
    assert_eq!(log.commits.0.len(), 1);
    let RpcResponse::Result {
        result: RpcResult::GitShow(show),
        ..
    } = call_response(
        client,
        RpcCall::GitShow(GitShowParams {
            context: context.clone(),
            repository_id,
            state_token: status.state_token.clone(),
            object_id: log.commits.0[0].object_id.clone(),
            cursor: None,
            limit: 20u32.try_into().unwrap(),
        }),
        6,
    )
    else {
        panic!("Git show result");
    };
    assert_eq!(show.commit.object_id, log.commits.0[0].object_id);
    assert_eq!(show.diff.files.0.len(), 1);
    let response = call_response(
        client,
        RpcCall::WorkspaceGet(WorkspaceReadParams {
            context: context.clone(),
        }),
        7,
    );
    assert!(matches!(
        response,
        RpcResponse::Result {
            result: RpcResult::WorkspaceGet(_),
            ..
        }
    ));
}

fn files_mutation_script(
    client: &mut NativeClient,
    context: &WorkspaceContext,
    root: EntryId,
    disk: &std::path::Path,
) {
    use lomi_remote_protocol::rpc::{
        Confirmed, DestinationState, FileMutationContext, FilesCreateParams, FilesListParams,
        FilesRemoveParams, FilesRenameParams, FilesStatParams, PageLimit,
    };
    let mut ordinal = 1u8;
    let mut next = || {
        ordinal += 1;
        ordinal
    };
    let mutation = |n: u8| FileMutationContext {
        operation_id: OperationId::from_bytes([0x40 + n; 16]).unwrap(),
        context: context.clone(),
    };
    let stat = |client: &mut NativeClient, entry: EntryId, ordinal: u8| match call_response(
        client,
        RpcCall::FilesStat(FilesStatParams {
            context: context.clone(),
            entry_id: entry,
            file_revision: None,
        }),
        ordinal,
    ) {
        RpcResponse::Result {
            result: RpcResult::FilesStat(meta),
            ..
        } => meta.file_revision,
        other => panic!("files.stat failed: {other:?}"),
    };
    let name = |text: &str| text.to_owned().try_into().unwrap();
    let file_result = |response: RpcResponse| match response {
        RpcResponse::Result {
            result:
                RpcResult::FilesCreate(receipt)
                | RpcResult::FilesMkdir(receipt)
                | RpcResult::FilesRename(receipt)
                | RpcResult::FilesRemove(receipt),
            ..
        } => {
            assert_eq!(receipt.state(), OperationState::Succeeded);
            assert_eq!(receipt.effect(), Effect::Committed);
            match receipt.result() {
                Some(OperationResult::File {
                    entry_id,
                    file_revision,
                }) => (receipt.clone(), *entry_id, file_revision.clone()),
                other => panic!("file result missing: {other:?}"),
            }
        }
        other => panic!("file mutation failed: {other:?}"),
    };
    let refusal = |response: RpcResponse| match response {
        RpcResponse::Error { error, .. } => {
            assert_eq!(error.effect(), Effect::None);
            error.code()
        }
        other => panic!("expected an error response, got {other:?}"),
    };

    // create: exact, empty, fresh entry id.
    let root_rev = stat(client, root, next());
    let create = RpcCall::FilesCreate(FilesCreateParams {
        mutation: mutation(1),
        parent_entry_id: root,
        parent_revision: root_rev.clone(),
        name: name("new.txt"),
        destination: DestinationState::Absent,
    });
    let (first, created, created_rev) = file_result(call_response(client, create.clone(), next()));
    assert_eq!(std::fs::read(disk.join("new.txt")).unwrap(), b"");
    // Retrying the same operation returns the SAME receipt and replays nothing.
    let (again, created_again, _) = file_result(call_response(client, create, next()));
    assert_eq!(first, again);
    assert_eq!(created, created_again);
    // A stale precondition is FILE_CHANGED and changes nothing.
    assert_eq!(
        refusal(call_response(
            client,
            RpcCall::FilesCreate(FilesCreateParams {
                mutation: mutation(2),
                parent_entry_id: root,
                parent_revision: root_rev,
                name: name("stale.txt"),
                destination: DestinationState::Absent,
            }),
            next()
        )),
        ErrorCode::FileChanged
    );
    assert!(!disk.join("stale.txt").exists());

    // mkdir, then rename within the root with fresh revisions.
    let root_rev = stat(client, root, next());
    let (_, dir, _) = file_result(call_response(
        client,
        RpcCall::FilesMkdir(FilesCreateParams {
            mutation: mutation(3),
            parent_entry_id: root,
            parent_revision: root_rev,
            name: name("sub"),
            destination: DestinationState::Absent,
        }),
        next(),
    ));
    assert!(disk.join("sub").is_dir());
    let root_rev = stat(client, root, next());
    let rename = |n: u8, to: &str, parent_rev: FileRevision| {
        RpcCall::FilesRename(FilesRenameParams {
            mutation: mutation(n),
            entry_id: created,
            file_revision: stat_placeholder(&created_rev),
            source_parent_id: root,
            source_parent_revision: parent_rev.clone(),
            target_parent_id: root,
            target_parent_revision: parent_rev,
            name: name(to),
            destination: DestinationState::Absent,
        })
    };
    // Renaming over an existing name never overwrites.
    assert_eq!(
        refusal(call_response(
            client,
            rename(4, "hello.txt", root_rev.clone()),
            next()
        )),
        ErrorCode::FileChanged
    );
    assert_eq!(
        std::fs::read(disk.join("hello.txt")).unwrap(),
        "héllo\r\nworld\r\n".as_bytes()
    );
    let (_, renamed, renamed_rev) = file_result(call_response(
        client,
        rename(5, "renamed.txt", root_rev),
        next(),
    ));
    assert_eq!(renamed, created);
    assert!(!disk.join("new.txt").exists() && disk.join("renamed.txt").exists());

    // Protected and non-empty targets are refused without effect.
    let listing = match call_response(
        client,
        RpcCall::FilesList(FilesListParams {
            context: context.clone(),
            parent_entry_id: root,
            cursor: None,
            limit: PageLimit::try_from(200).unwrap(),
        }),
        next(),
    ) {
        RpcResponse::Result {
            result: RpcResult::FilesList(list),
            ..
        } => list,
        other => panic!("files.list failed: {other:?}"),
    };
    let find = |name: &str| {
        listing
            .entries
            .0
            .iter()
            .find(|e| e.display_name.as_str() == name)
            .unwrap_or_else(|| panic!("{name} missing"))
            .clone()
    };
    let root_rev = stat(client, root, next());
    let remove = |n: u8, entry: &lomi_remote_protocol::rpc::FileMetadata| {
        RpcCall::FilesRemove(FilesRemoveParams {
            mutation: mutation(n),
            entry_id: entry.entry_id,
            file_revision: entry.file_revision.clone(),
            parent_entry_id: root,
            parent_revision: root_rev.clone(),
            confirmation: Confirmed::Confirmed,
        })
    };
    assert_eq!(
        refusal(call_response(client, remove(6, &find(".git")), next())),
        ErrorCode::ProtectedPath
    );
    assert!(disk.join(".git").is_dir());
    assert_eq!(
        refusal(call_response(client, remove(7, &find("hard.txt")), next())),
        ErrorCode::ProtectedPath
    );
    assert!(disk.join("hard.txt").exists());
    assert_eq!(
        refusal(call_response(client, remove(8, &find("docs")), next())),
        ErrorCode::DirectoryNotEmpty
    );
    assert!(disk.join("docs/note.md").exists());
    let git_rename = RpcCall::FilesRename(FilesRenameParams {
        mutation: mutation(9),
        entry_id: find(".git").entry_id,
        file_revision: find(".git").file_revision,
        source_parent_id: root,
        source_parent_revision: root_rev.clone(),
        target_parent_id: root,
        target_parent_revision: root_rev.clone(),
        name: name("not-git"),
        destination: DestinationState::Absent,
    });
    assert_eq!(
        refusal(call_response(client, git_rename, next())),
        ErrorCode::ProtectedPath
    );
    assert!(disk.join(".git").is_dir() && !disk.join("not-git").exists());

    // Remove the renamed file and the empty directory (exact preconditions).
    let renamed_meta = find("renamed.txt");
    assert_eq!(renamed_meta.entry_id, renamed);
    assert_eq!(renamed_meta.file_revision, renamed_rev);
    let (_, removed, _) = file_result(call_response(client, remove(10, &renamed_meta), next()));
    assert_eq!(removed, renamed);
    assert!(!disk.join("renamed.txt").exists());
    let root_rev = stat(client, root, next());
    let sub_meta = lomi_remote_protocol::rpc::FilesRemoveParams {
        mutation: mutation(11),
        entry_id: dir,
        file_revision: stat(client, dir, next()),
        parent_entry_id: root,
        parent_revision: root_rev,
        confirmation: Confirmed::Confirmed,
    };
    file_result(call_response(
        client,
        RpcCall::FilesRemove(sub_meta),
        next(),
    ));
    assert!(!disk.join("sub").exists());
    // Alive after every refusal and effect.
    assert!(stat(client, root, next()).as_str().len() > 1);
}
fn stat_placeholder(revision: &FileRevision) -> FileRevision {
    revision.clone()
}
#[test]
fn real_tls_noise_explorer_reads_are_root_confined_and_refusals_keep_the_connection() {
    exercise_edit_ingress_inner(
        EditFixture::Rename,
        false,
        None,
        Some(FilesMode::Read),
        FaultWriter::CleanShutdown,
    )
}
#[test]
fn real_tls_noise_files_watch_invalidates_acknowledges_resumes_and_rejects_bad_acks() {
    exercise_edit_ingress_inner(
        EditFixture::Rename,
        false,
        None,
        Some(FilesMode::Watch),
        FaultWriter::CleanShutdown,
    )
}
#[test]
fn real_tls_noise_git_methods_are_refused_without_git_read_permission() {
    exercise_edit_ingress_inner(
        EditFixture::Rename,
        false,
        None,
        Some(FilesMode::GitRefused),
        FaultWriter::CleanShutdown,
    )
}
#[test]
fn real_tls_noise_git_reads_use_the_host_repository_and_keep_the_channel_usable() {
    exercise_edit_ingress_inner(
        EditFixture::Rename,
        false,
        None,
        Some(FilesMode::GitRead),
        FaultWriter::CleanShutdown,
    )
}
#[test]
fn real_tls_noise_unshare_cancels_a_pending_git_read_and_withholds_its_result() {
    exercise_edit_ingress_inner(
        EditFixture::Rename,
        false,
        None,
        Some(FilesMode::GitRevoke),
        FaultWriter::CleanShutdown,
    )
}
#[test]
fn real_tls_noise_unshare_after_first_git_diff_fragment_stops_disclosure() {
    exercise_edit_ingress_inner(
        EditFixture::Rename,
        false,
        None,
        Some(FilesMode::GitFragmentRevoke),
        FaultWriter::CleanShutdown,
    )
}
#[test]
fn real_tls_noise_explorer_create_fenced_by_competing_writer_never_touches_the_disk() {
    exercise_edit_ingress_with_files(FilesMode::Fenced, FaultWriter::CleanShutdown)
}
#[test]
fn real_tls_noise_explorer_mutations_are_exact_idempotent_and_protected() {
    exercise_edit_ingress_inner(
        EditFixture::Rename,
        false,
        None,
        Some(FilesMode::Mutate),
        FaultWriter::CleanShutdown,
    )
}
#[test]
fn real_tls_noise_rename_delivers_one_durable_receipt_and_reconnect_deduplicates_without_replay() {
    exercise_edit_ingress(EditFixture::Rename);
}
#[test]
fn real_tls_noise_move_same_tab_before_retains_two_local_ptys_and_deduplicates() {
    exercise_edit_ingress(EditFixture::MoveSameTabBefore);
}
#[test]
fn real_tls_noise_move_cross_tab_after_retains_two_local_ptys_and_deduplicates() {
    exercise_edit_ingress(EditFixture::MoveCrossTabAfter);
}
#[test]
fn real_tls_noise_create_spawns_one_real_pty_and_reconnect_deduplicates_without_second_spawn() {
    exercise_edit_ingress(EditFixture::Create);
}
#[test]
fn real_tls_noise_create_fenced_by_competing_writer_never_spawns_and_settles_failed() {
    exercise_edit_ingress_with(EditFixture::Create, true)
}
#[test]
fn real_tls_noise_split_fenced_by_competing_writer_never_spawns_and_settles_failed() {
    exercise_edit_ingress_with(EditFixture::Split, true)
}
#[test]
fn real_tls_noise_close_fenced_by_competing_writer_never_stops_and_settles_failed() {
    exercise_edit_ingress_with(EditFixture::Close, true)
}
#[test]
fn real_tls_noise_restart_fenced_by_competing_writer_neither_stops_nor_spawns() {
    exercise_edit_ingress_with(EditFixture::Restart, true)
}
#[test]
fn real_tls_noise_unshare_during_effect_never_runs_it_for_every_lifecycle_method() {
    for case in [
        EditFixture::Create,
        EditFixture::Split,
        EditFixture::Close,
        EditFixture::Restart,
    ] {
        exercise_edit_ingress_with_writer(case, FaultWriter::Unshare);
    }
}
#[test]
fn real_tls_noise_logout_during_effect_never_runs_it_for_every_lifecycle_method() {
    for case in [
        EditFixture::Create,
        EditFixture::Split,
        EditFixture::Close,
        EditFixture::Restart,
    ] {
        exercise_edit_ingress_with_writer(case, FaultWriter::Logout);
    }
}
#[test]
fn real_tls_noise_unshare_or_logout_during_file_effect_never_touches_the_disk() {
    exercise_edit_ingress_with_files(FilesMode::Fenced, FaultWriter::Unshare);
    exercise_edit_ingress_with_files(FilesMode::Fenced, FaultWriter::Logout);
}
#[test]
fn real_tls_noise_failed_completion_recovers_every_lifecycle_effect_without_repeating_it() {
    for case in [
        EditFixture::Create,
        EditFixture::Split,
        EditFixture::Close,
        EditFixture::Restart,
    ] {
        exercise_edit_ingress_with_writer(case, FaultWriter::CompletionFailure);
    }
}
#[test]
fn real_tls_noise_real_exec_failure_is_a_durable_known_failure_for_create_and_split() {
    for case in [EditFixture::Create, EditFixture::Split] {
        exercise_edit_ingress_with_writer(case, FaultWriter::ExecFailure);
    }
}
#[test]
fn real_tls_noise_real_exec_failure_after_the_stop_is_unknown_for_restart() {
    exercise_edit_ingress_with_writer(EditFixture::Restart, FaultWriter::ExecFailure);
}
#[test]
fn real_tls_noise_failed_completion_recovers_a_file_effect_without_repeating_it() {
    exercise_edit_ingress_with_files(FilesMode::Fenced, FaultWriter::CompletionFailure);
}
#[test]
fn real_tls_noise_stale_revision_is_an_error_response_for_every_lifecycle_method() {
    for case in [
        EditFixture::Create,
        EditFixture::Split,
        EditFixture::Close,
        EditFixture::Restart,
    ] {
        exercise_rejection(case, Rejection::StaleRevision);
    }
}
#[test]
fn real_tls_noise_stale_revision_is_an_error_response_for_rename_and_move() {
    for case in [
        EditFixture::Rename,
        EditFixture::MoveSameTabBefore,
        EditFixture::MoveCrossTabAfter,
    ] {
        exercise_rejection(case, Rejection::StaleRevision);
    }
}
#[test]
fn real_tls_noise_missing_tab_or_pane_is_an_error_response_for_rename_and_move() {
    for case in [
        EditFixture::Rename,
        EditFixture::MoveSameTabBefore,
        EditFixture::MoveCrossTabAfter,
    ] {
        exercise_rejection(case, Rejection::MissingTarget);
    }
}
#[test]
fn real_tls_noise_stale_session_is_an_error_response_for_close_and_restart() {
    for case in [EditFixture::Close, EditFixture::Restart] {
        exercise_rejection(case, Rejection::StaleSession);
    }
}
#[test]
fn real_tls_noise_split_spawns_one_real_pty_and_reconnect_deduplicates_without_second_spawn() {
    exercise_edit_ingress(EditFixture::Split);
}
#[test]
fn real_tls_noise_close_stops_only_the_target_pty_and_reconnect_never_repeats_it() {
    exercise_edit_ingress(EditFixture::Close);
}
#[test]
fn real_tls_noise_restart_replaces_only_the_target_session_and_reconnect_never_repeats_it() {
    exercise_edit_ingress(EditFixture::Restart);
}

fn pane_sessions(state: &WorkspaceState) -> Vec<TerminalContext> {
    fn collect(layout: &TerminalLayout, into: &mut Vec<TerminalContext>) {
        match layout {
            TerminalLayout::Pane { pane } => into.extend(pane.session.iter().cloned()),
            TerminalLayout::Split { first, second, .. } => {
                collect(first, into);
                collect(second, into);
            }
        }
    }
    let mut sessions = Vec::new();
    for tab in &state.tabs.0 {
        collect(&tab.layout, &mut sessions);
    }
    sessions
}

// Setup uses the normal host-local Coordinator/RPC lifecycle and real PTY
// service; remote move itself never dispatches a local lifecycle operation.
thread_local! {
    /// The default-shell executable of the current fixture (test thread only).
    static SHELL: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}
fn shell_executable() -> std::path::PathBuf {
    SHELL.with(|shell| {
        shell
            .borrow()
            .clone()
            .unwrap_or_else(crate::testsupport::shell_executable)
    })
}
/// A working shell wrapper whose exec can later be made to fail for real.
fn write_wrapper(path: &std::path::Path, working: bool) {
    crate::testsupport::write_shell_wrapper(path, working);
}
fn local_move_ptys(
    f: &mut Fixture<'_>,
    coordinator: &Arc<Coordinator>,
    case: EditFixture,
) -> TerminalContext {
    {
        let mut store = f.store.lock().unwrap();
        store
            .initialize_default_shell(lomi_host_store::DefaultShellProfile {
                executable: shell_executable(),
                args: vec![],
            })
            .unwrap();
    }
    let mut connection =
        rpc::ConnectionState::new(coordinator.clone(), f.runtime().operation).unwrap();
    for ordinal in 0..2u8 {
        let before = f
            .store
            .lock()
            .unwrap()
            .workspace(f.workspace)
            .unwrap()
            .state;
        let mutation = MutationContext {
            operation_id: OperationId::from_bytes([71 + ordinal; 16]).unwrap(),
            context: before.context.clone(),
            expected_revision: before.domain_revision,
        };
        let call = if ordinal == 1 && matches!(case, EditFixture::MoveSameTabBefore) {
            RpcCall::TerminalSplit(TerminalSplitParams {
                mutation,
                tab_id: before.tabs.0[0].tab_id,
                pane_id: pane_sessions(&before)[0].pane_id,
                axis: SplitAxis::Vertical,
                profile_id: "default".to_owned().try_into().unwrap(),
            })
        } else {
            RpcCall::TerminalCreate(TerminalCreateParams {
                mutation,
                tab_name: format!("Local move PTY {ordinal}").try_into().unwrap(),
                profile_id: "default".to_owned().try_into().unwrap(),
            })
        };
        let request = RpcRequest {
            v: ApplicationMajor,
            r#type: RequestKind::Request,
            request_id: format!("local-move-setup-{ordinal}").try_into().unwrap(),
            timeout_ms: 4000u64.try_into().unwrap(),
            call,
        };
        assert!(matches!(
            rpc::dispatch(coordinator, &mut connection, request, f.runtime().operation),
            RpcResponse::Result {
                result: RpcResult::TerminalCreate(_) | RpcResult::TerminalSplit(_),
                ..
            }
        ));
    }
    let state = f
        .store
        .lock()
        .unwrap()
        .workspace(f.workspace)
        .unwrap()
        .state;
    let sessions = pane_sessions(&state);
    assert_eq!(sessions.len(), 2);
    assert_ne!(sessions[0].session_id, sessions[1].session_id);
    for target in &sessions {
        let snapshot = coordinator
            .terminals
            .snapshot(target.session_id, target.session_epoch)
            .unwrap();
        assert_eq!(
            snapshot.session_epoch.as_bytes(),
            &target.session_epoch.to_bytes()
        );
    }
    let mut store = f.store.lock().unwrap();
    let publication = store
        .prepare_host_publication(&f.eligibility.binding)
        .unwrap();
    f.eligibility.binding = store
        .acknowledge_host_publication(
            &publication,
            &PublicationResult {
                runtime: publication.params.runtime.clone(),
                publication_seq: publication.params.publication_seq,
            },
        )
        .unwrap();
    f.eligibility.publication = store
        .acknowledged_host_publication(&f.eligibility.binding)
        .unwrap()
        .unwrap();
    sessions[0].clone()
}

/// Structural proof of the committed effect. Session ids are fresh per run, so
/// this checks exactly-one-change against the real PTY service instead.
fn assert_effect_state(
    case: EditFixture,
    coordinator: &Arc<Coordinator>,
    before: &WorkspaceState,
    after: &WorkspaceState,
    old: &[TerminalContext],
) {
    let alive = |target: &TerminalContext| {
        coordinator
            .terminals
            .snapshot(target.session_id, target.session_epoch)
            .is_ok()
    };
    let now = pane_sessions(after);
    assert_eq!(after.domain_revision.0, before.domain_revision.0 + 1);
    assert_eq!(after.context, before.context);
    match case {
        EditFixture::Create => {
            assert_eq!(after.tabs.0.len(), before.tabs.0.len() + 1);
            assert_eq!(&after.tabs.0[..before.tabs.0.len()], &before.tabs.0[..]);
            let name: DisplayText = "remote-create-once".to_owned().try_into().unwrap();
            let tab = after.tabs.0.last().unwrap();
            assert_eq!(tab.name, name);
            let TerminalLayout::Pane { pane } = &tab.layout else {
                panic!("a created tab is one pane")
            };
            assert_eq!(pane.state, PaneState::Running);
            let session = pane.session.as_ref().expect("running pane has a session");
            assert!(old.iter().all(|o| o.session_id != session.session_id));
            assert!(alive(session), "created PTY must be a live host session");
        }
        EditFixture::Split => {
            assert_eq!(after.tabs.0.len(), before.tabs.0.len());
            assert!(matches!(
                after.tabs.0[0].layout,
                TerminalLayout::Split { .. }
            ));
            assert_eq!(now.len(), old.len() + 1);
            assert!(old.iter().all(|o| now.contains(o) && alive(o)));
            let added: Vec<_> = now.iter().filter(|n| !old.contains(n)).collect();
            assert_eq!(added.len(), 1);
            assert!(alive(added[0]), "split PTY must be a live host session");
        }
        EditFixture::Close => {
            assert_eq!(after.tabs.0.len(), before.tabs.0.len() - 1);
            assert_eq!(now, vec![old[0].clone()]);
            assert!(alive(&old[0]), "an untouched PTY must survive");
            assert!(!alive(&old[1]), "the closed PTY must be gone");
        }
        EditFixture::Restart => {
            assert_eq!(after.tabs.0.len(), before.tabs.0.len());
            assert_eq!(now.len(), old.len());
            assert!(now.contains(&old[0]) && alive(&old[0]));
            let replaced = now
                .iter()
                .find(|n| n.pane_id == old[1].pane_id)
                .expect("the restarted pane keeps its identity");
            assert_ne!(replaced.session_id, old[1].session_id);
            assert_ne!(replaced.session_epoch, old[1].session_epoch);
            assert!(alive(replaced), "the replacement PTY must be live");
            assert!(!alive(&old[1]), "the replaced PTY must be gone");
        }
        _ => unreachable!("effect cases only"),
    }
}

fn exercise_edit_ingress(case: EditFixture) {
    exercise_edit_ingress_with(case, false)
}

/// Pre-effect rejection: the request is answered with an ordinary error
/// response; nothing is journaled, spawned or stopped; the connection stays
/// usable for the next request.
#[derive(Clone, Copy, PartialEq)]
enum Rejection {
    StaleRevision,
    StaleSession,
    /// Rename of an unknown tab / move of an unknown pane.
    MissingTarget,
}
fn exercise_rejection(case: EditFixture, rejection: Rejection) {
    exercise_edit_ingress_inner(
        case,
        false,
        Some(rejection),
        None,
        FaultWriter::CleanShutdown,
    )
}

/// `fault`: a competing Shared writer commits between the durable start and the
/// physical effect. The effect must not run, no receipt may be delivered, and
/// maintenance must settle the retained permit as a known no-effect failure.
fn exercise_edit_ingress_with(case: EditFixture, fault: bool) {
    exercise_edit_ingress_inner(case, fault, None, None, FaultWriter::CleanShutdown)
}
fn exercise_edit_ingress_with_writer(case: EditFixture, writer: FaultWriter) {
    exercise_edit_ingress_inner(case, true, None, None, writer)
}
fn exercise_edit_ingress_with_files(mode: FilesMode, writer: FaultWriter) {
    exercise_edit_ingress_inner(EditFixture::Rename, false, None, Some(mode), writer)
}
/// The authority-changing Shared writer that races the effect (REQ-13).
#[derive(Clone, Copy, PartialEq, Debug)]
enum FaultWriter {
    /// Records a clean shutdown: the generic competing Shared writer.
    CleanShutdown,
    /// Unshares the workspace (consumer revocation for this workspace).
    Unshare,
    /// Local logout: fences the whole authorization (revocation).
    Logout,
    /// No competing writer: the completion write fails with a Store error
    /// AFTER the physical effect ran (deferred-completion recovery).
    CompletionFailure,
    /// No competing writer: the shell executable really fails inside execve
    /// (EACCES: no execute permission for its owner) when the effect spawns.
    ExecFailure,
}
impl FaultWriter {
    /// Offset keeping fault operation ids distinct per writer: the fault hook
    /// and its plan registry are process-global and keyed by operation id.
    fn offset(self) -> u8 {
        match self {
            Self::CleanShutdown => 0,
            Self::Unshare => 20,
            Self::Logout => 40,
            Self::CompletionFailure => 60,
            Self::ExecFailure => 80,
        }
    }
    fn files_fence_operation(self) -> [u8; 16] {
        [0x71 + self.offset() / 20; 16]
    }
}
fn exercise_edit_ingress_inner(
    case: EditFixture,
    fault: bool,
    rejection: Option<Rejection>,
    files: Option<FilesMode>,
    writer: FaultWriter,
) {
    // These fixtures share a process-wide fault registry and deliberately
    // reuse operation ids. Run every ingress case one at a time so a callback
    // cannot be consumed by another fixture's owner/store.
    static INGRESS_FIXTURES: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _serial = INGRESS_FIXTURES.lock().unwrap_or_else(|e| e.into_inner());
    let shell_dir = tempfile::tempdir().unwrap();
    if writer == FaultWriter::ExecFailure {
        let wrapper = shell_dir.path().join("shell");
        write_wrapper(&wrapper, true);
        SHELL.with(|shell| *shell.borrow_mut() = Some(wrapper));
    }
    struct ResetShell;
    impl Drop for ResetShell {
        fn drop(&mut self) {
            SHELL.with(|shell| *shell.borrow_mut() = None);
        }
    }
    let _reset_shell = ResetShell;
    peer::current_pairing_script::clear();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint: lomi_remote_protocol::ipc::LocalRelayEndpoint = format!(
        "wss://127.0.0.1:{}/v2/relay",
        listener.local_addr().unwrap().port()
    )
    .try_into()
    .unwrap();
    let (root, tls) = certificate();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    peer::tests::fixture_at_wall_with_relay(now, Some(endpoint.clone()), |f, auth| {
        let coordinator = Coordinator::with_existing_owner_for_test(
            f.owner.clone(),
            Arc::new(AtomicBool::new(false)),
        );
        let _cleanup = ServiceCleanup(coordinator.clone());
        let local = match case {
            EditFixture::Rename | EditFixture::Create => terminal(f),
            EditFixture::MoveSameTabBefore | EditFixture::MoveCrossTabAfter => {
                local_move_ptys(f, &coordinator, case)
            }
            // Two real PTYs in two tabs (cross-tab layout), acknowledged.
            EditFixture::Split | EditFixture::Close | EditFixture::Restart => {
                local_move_ptys(f, &coordinator, EditFixture::MoveCrossTabAfter)
            }
        };
        if matches!(case, EditFixture::Create) {
            f.store
                .lock()
                .unwrap()
                .initialize_default_shell(lomi_host_store::DefaultShellProfile {
                    executable: shell_executable(),
                    args: vec![],
                })
                .unwrap();
        }
        if writer == FaultWriter::ExecFailure {
            // Local setup is done with a working shell; from here on the same
            // executable path really fails inside execve.
            write_wrapper(&shell_executable(), false);
        }
        let before = f
            .store
            .lock()
            .unwrap()
            .workspace(f.workspace)
            .unwrap()
            .state;
        let sessions = pane_sessions(&before);
        let descriptors = f
            .store
            .lock()
            .unwrap()
            .terminal_descriptors(f.workspace)
            .unwrap();
        let events_before = f
            .store
            .lock()
            .unwrap()
            .events_after(0)
            .unwrap()
            .events
            .len();
        let outside = tempfile::tempdir().unwrap();
        let files_root = f
            .store
            .lock()
            .unwrap()
            .workspace(f.workspace)
            .unwrap()
            .local_root;
        if matches!(
            files,
            Some(FilesMode::GitRead | FilesMode::GitRevoke | FilesMode::GitFragmentRevoke)
        ) {
            // The reused owner fixture keeps its live SQLite files at the
            // workspace root. Git snapshots must cover a separate repository,
            // whose files are not being changed by ordinary owner reads.
            let repository = files_root.join("git-project");
            std::fs::create_dir(&repository).unwrap();
            let git = |args: &[&str]| {
                let result = std::process::Command::new("git")
                    .args(args)
                    .current_dir(&repository)
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("GIT_CONFIG_NOSYSTEM", "1")
                    .output()
                    .expect("Git read fixture requires git");
                assert!(result.status.success(), "Git fixture setup failed");
            };
            git(&["init", "-q"]);
            git(&["config", "user.name", "Fixture"]);
            git(&["config", "user.email", "fixture@example.invalid"]);
            let content = |label: &str| {
                if matches!(files, Some(FilesMode::GitFragmentRevoke)) {
                    (0..100)
                        .map(|n| format!("{label}-{n:03}-{}\n", "a".repeat(120)))
                        .collect::<String>()
                } else {
                    format!("{label}\n")
                }
            };
            std::fs::write(repository.join("hello.txt"), content("before")).unwrap();
            git(&["add", "hello.txt"]);
            git(&[
                "-c",
                "core.hooksPath=/dev/null",
                "commit",
                "-qm",
                "Initial fixture",
            ]);
            std::fs::write(repository.join("hello.txt"), content("after")).unwrap();
        } else if files.is_some() {
            let root = f
                .store
                .lock()
                .unwrap()
                .workspace(f.workspace)
                .unwrap()
                .local_root;
            std::fs::write(root.join("hello.txt"), "héllo\r\nworld\r\n").unwrap();
            std::fs::create_dir(root.join("docs")).unwrap();
            std::fs::write(root.join("docs/note.md"), "# note\n").unwrap();
            std::fs::write(root.join("bin.dat"), [0u8, 1, 2, 3]).unwrap();
            std::fs::write(outside.path().join("secret"), "OUTSIDE").unwrap();
            // Needs a privilege on Windows; the symlink checks are skipped without it.
            crate::testsupport::symlink_dir(outside.path(), &root.join("outside-link"));
            std::fs::hard_link(outside.path().join("secret"), root.join("hard.txt")).unwrap();
            std::fs::create_dir(root.join(".git")).unwrap();
        }
        let host_identity = auth.public_host_identity(f.now()).unwrap();
        let consumer = Identity::generate(
            host_identity.account_id.to_bytes(),
            [22; 16],
            Role::Device,
            1,
        )
        .unwrap();
        let first_input = if matches!(files, Some(FilesMode::GitRefused)) {
            input_with_consumer_for_channel_and_capabilities(
                f,
                auth,
                &consumer,
                [44; 16],
                Some(
                    CapabilitySet::try_from(
                        Capability::ALL
                            .into_iter()
                            .filter(|cap| {
                                !matches!(
                                    cap,
                                    Capability::GitRead
                                        | Capability::GitWrite
                                        | Capability::GitNetwork
                                        | Capability::GitExecute
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                    .unwrap(),
                ),
            )
        } else {
            input_with_consumer(f, auth, &consumer)
        };
        let signed = SignedGrantV3::from_wire(&first_input.grant).unwrap();
        let workspace = WorkspaceContext {
            workspace_id: f.workspace,
            workspace_epoch: local.workspace.workspace_epoch,
            runtime_id: RuntimeId::from_bytes(signed.grant.runtime_id).unwrap(),
            runtime_generation: DecimalU64(signed.grant.runtime_generation),
            host_access_epoch: DecimalU64(signed.grant.access_epoch),
            grant_revision: DecimalU64(signed.grant.grant_revision),
        };
        let mutation = MutationContext {
            operation_id: OperationId::from_bytes(
                [if rejection.is_some() {
                    match case {
                        EditFixture::Create => 101,
                        EditFixture::Split => 102,
                        EditFixture::Close => 103,
                        _ => 104,
                    }
                } else if fault {
                    // Distinct per case: the fault hook is keyed by operation id.
                    writer.offset()
                        + match case {
                            EditFixture::Create => 91,
                            EditFixture::Split => 92,
                            EditFixture::Close => 93,
                            _ => 94,
                        }
                } else {
                    81
                }; 16],
            )
            .unwrap(),
            context: workspace.clone(),
            expected_revision: before.domain_revision,
        };
        let original = match case {
            EditFixture::Rename => RpcCall::TerminalRename(TerminalRenameParams {
                mutation,
                tab_id: before.tabs.0[0].tab_id,
                name: "remote-name-once".to_owned().try_into().unwrap(),
            }),
            EditFixture::Create => RpcCall::TerminalCreate(TerminalCreateParams {
                mutation,
                tab_name: "remote-create-once".to_owned().try_into().unwrap(),
                profile_id: "default".to_owned().try_into().unwrap(),
            }),
            EditFixture::Split => RpcCall::TerminalSplit(TerminalSplitParams {
                mutation,
                tab_id: before.tabs.0[0].tab_id,
                pane_id: sessions[0].pane_id,
                axis: SplitAxis::Horizontal,
                profile_id: "default".to_owned().try_into().unwrap(),
            }),
            EditFixture::Close => RpcCall::TerminalClose(TerminalCloseParams {
                mutation,
                pane_id: sessions[1].pane_id,
                expected_session: Some(TerminalContext {
                    workspace: workspace.clone(),
                    ..sessions[1].clone()
                }),
            }),
            EditFixture::Restart => RpcCall::TerminalRestart(TerminalRestartParams {
                mutation,
                pane_id: sessions[1].pane_id,
                expected_session: Some(TerminalContext {
                    workspace: workspace.clone(),
                    ..sessions[1].clone()
                }),
                profile_id: "default".to_owned().try_into().unwrap(),
            }),
            EditFixture::MoveSameTabBefore | EditFixture::MoveCrossTabAfter => {
                RpcCall::TerminalMove(TerminalMoveParams {
                    mutation,
                    pane_id: sessions[0].pane_id,
                    source_tab_id: before.tabs.0[0].tab_id,
                    target_tab_id: before.tabs.0.last().unwrap().tab_id,
                    target_pane_id: sessions[1].pane_id,
                    placement: match case {
                        EditFixture::MoveSameTabBefore => MovePlacement::Before,
                        _ => MovePlacement::After,
                    },
                })
            }
        };
        let mutation = match &original {
            RpcCall::TerminalRename(params) => &params.mutation,
            RpcCall::TerminalMove(params) => &params.mutation,
            RpcCall::TerminalCreate(params) => &params.mutation,
            RpcCall::TerminalSplit(params) => &params.mutation,
            RpcCall::TerminalClose(params) => &params.mutation,
            RpcCall::TerminalRestart(params) => &params.mutation,
            _ => unreachable!("closed fixture"),
        };
        if fault || matches!(files, Some(FilesMode::Fenced)) {
            let workspace = f.workspace;
            if writer == FaultWriter::CompletionFailure {
                crate::unix::remote_terminal_lifecycle::fault::fail_completion(if fault {
                    mutation.operation_id.to_bytes()
                } else {
                    writer.files_fence_operation()
                });
            }
            crate::unix::remote_terminal_lifecycle::fault::arm(
                if fault {
                    mutation.operation_id.to_bytes()
                } else {
                    writer.files_fence_operation()
                },
                Box::new(move |owner, _| {
                    let cancel = AtomicBool::new(false);
                    let competing = crate::unix::owner_domain::Operation::new(
                        Instant::now() + Duration::from_secs(5),
                        &cancel,
                    );
                    match writer {
                        // Planned targets are recorded by the hook itself.
                        FaultWriter::CompletionFailure | FaultWriter::ExecFailure => (),
                        FaultWriter::CleanShutdown => owner
                            .begin_record_clean_shutdown(&competing)
                            .unwrap()
                            .try_commit()
                            .map(|_| ())
                            .unwrap(),
                        FaultWriter::Unshare => owner
                            .begin_unshare(&competing, workspace)
                            .unwrap()
                            .try_commit()
                            .map(|_| ())
                            .unwrap(),
                        FaultWriter::Logout => owner
                            .begin_local_logout(&competing)
                            .unwrap()
                            .try_commit()
                            .map(|_| ())
                            .unwrap(),
                    }
                }),
            );
        }
        // Effect lifecycle mints fresh session ids, so its exact post state is
        // asserted structurally below instead of by a precomputed equality.
        let mut expected = match &original {
            RpcCall::TerminalRename(params) => {
                let mut expected = before.clone();
                expected.tabs.0[0].name = params.name.clone();
                expected
            }
            RpcCall::TerminalMove(params) => lomi_host_store::plan_terminal_move(
                &before,
                &lomi_host_store::TerminalMoveLayout::from(params),
            )
            .unwrap(),
            _ => before.clone(),
        };
        expected.domain_revision.0 += 1;
        let mut settled_state: Option<WorkspaceState> = None;
        let mut settled_descriptors: Option<String> = None;
        let rights: CapabilitySet = vec![
            Capability::WorkspaceRead,
            Capability::TerminalObserve,
            Capability::TerminalManage,
        ]
        .try_into()
        .unwrap();
        let binding = lomi_host_store::OperationBinding {
            rights: StoredOperationRights::new(
                mutation.operation_id,
                ConsumerAuthorizationId::from_bytes(signed.grant.consumer_authorization_id)
                    .unwrap(),
                f.workspace,
                original.method(),
                rights.clone(),
                false,
            )
            .unwrap(),
            parameter_hash: lomi_host_store::parameter_hash(&original).unwrap(),
        };
        let mut committed = None;
        // Round0 commits. After exact publication ACK, round1 repeats identical
        // original wire parameters/stale CAS and round2 changes name/placement.
        for round in 0..3u8 {
            peer::current_pairing_script::clear();
            let source = f
                .store
                .lock()
                .unwrap()
                .acknowledged_workspace_grants()
                .unwrap()
                .remove(0);
            for _ in 0..256 {
                peer::current_pairing_script::enqueue(
                    source.intent.preparation.pairing_id,
                    source.response.clone(),
                );
            }
            let mut input = first_input.clone();
            let mut context = ChannelContextV3::from_canonical(
                &hex_bytes(input.expected_context.expose_wire())
                    .unwrap_or_else(|_| panic!("context bytes")),
            )
            .unwrap();
            context.channel_id = [82 + round; 16];
            context.issued_at = f.now();
            context.expires_at = f.now() + 30;
            input.expected_context = hex(&context.canonical().unwrap()).try_into().unwrap();
            let api = Api {
                replies: RefCell::new(VecDeque::from([Reply::Poll(ChannelPendingResult {
                    channels: vec![PendingChannel {
                        channel_id: ChannelId::from_bytes(context.channel_id).unwrap(),
                        inputs: input.clone(),
                    }]
                    .try_into()
                    .unwrap(),
                })])),
                requests: RefCell::new(vec![]),
                params: RefCell::new(vec![]),
                hook: RefCell::new(None),
            };
            let (mut channel_worker, intent) = prepared(f, auth, &api);
            api.replies
                .borrow_mut()
                .push_back(Reply::state(admitted(&intent)));
            assert!(step(f, auth, &mut channel_worker, &api).is_ok());
            let handoff = channel_worker.take_admitted().unwrap();
            let admission =
                SignedChannelAdmissionV3::from_wire(&intent.preparation.params.admission).unwrap();
            let host = SignedBundle::from_wire(&host_identity.identity).unwrap();
            let validated = admission
                .verify(
                    &signed,
                    &context,
                    &host,
                    &host_identity.fingerprint,
                    &consumer.public_bundle(),
                    &context.grant.consumer_fingerprint,
                    &authority(&input.authority),
                    f.now(),
                )
                .unwrap();
            let initiator = Handshake::new_v3(
                true,
                &consumer,
                validated,
                &host,
                &host_identity.fingerprint,
                f.now(),
            )
            .unwrap();
            let (tx, rx) = mpsc::sync_channel(1);
            let server_listener = listener.try_clone().unwrap();
            let server_tls = tls.clone();
            let remote_workspace = workspace.clone();
            let mut call = original.clone();
            if round == 2 {
                match &mut call {
                    RpcCall::TerminalRename(p) => {
                        p.name = "must-not-commit".to_owned().try_into().unwrap()
                    }
                    RpcCall::TerminalMove(p) => {
                        p.placement = match p.placement {
                            MovePlacement::Before => MovePlacement::After,
                            MovePlacement::After => MovePlacement::Before,
                        }
                    }
                    // Same operation id, different wire parameters: conflict.
                    RpcCall::TerminalCreate(p) => {
                        p.tab_name = "must-not-spawn".to_owned().try_into().unwrap()
                    }
                    RpcCall::TerminalSplit(p) => p.axis = SplitAxis::Vertical,
                    RpcCall::TerminalClose(p) => p.mutation.expected_revision.0 += 7,
                    RpcCall::TerminalRestart(p) => p.mutation.expected_revision.0 += 7,
                    _ => unreachable!("closed fixture"),
                }
            }
            if let Some(rejection) = rejection {
                match (&mut call, rejection) {
                    (RpcCall::TerminalCreate(p), Rejection::StaleRevision) => {
                        p.mutation.expected_revision.0 += 7
                    }
                    (RpcCall::TerminalSplit(p), Rejection::StaleRevision) => {
                        p.mutation.expected_revision.0 += 7
                    }
                    (RpcCall::TerminalClose(p), Rejection::StaleRevision) => {
                        p.mutation.expected_revision.0 += 7
                    }
                    (RpcCall::TerminalRestart(p), Rejection::StaleRevision) => {
                        p.mutation.expected_revision.0 += 7
                    }
                    (RpcCall::TerminalRename(p), Rejection::StaleRevision) => {
                        p.mutation.expected_revision.0 += 7
                    }
                    (RpcCall::TerminalMove(p), Rejection::StaleRevision) => {
                        p.mutation.expected_revision.0 += 7
                    }
                    (RpcCall::TerminalRename(p), Rejection::MissingTarget) => {
                        p.tab_id = TabId::from_bytes([99; 16]).unwrap()
                    }
                    (RpcCall::TerminalMove(p), Rejection::MissingTarget) => {
                        p.pane_id = PaneId::from_bytes([99; 16]).unwrap()
                    }
                    (RpcCall::TerminalClose(p), Rejection::StaleSession) => {
                        p.expected_session.as_mut().unwrap().session_id =
                            TerminalSessionId::from_bytes([99; 16]).unwrap()
                    }
                    (RpcCall::TerminalRestart(p), Rejection::StaleSession) => {
                        p.expected_session.as_mut().unwrap().session_id =
                            TerminalSessionId::from_bytes([99; 16]).unwrap()
                    }
                    _ => unreachable!("closed rejection fixture"),
                }
            }
            let sent_call = call.clone();
            let thread_root = files_root.clone();
            let join = thread::spawn(move || {
                let mut client = accept_native_client(
                    server_listener,
                    server_tls,
                    initiator,
                    context.channel_id,
                );
                let get = send_request(
                    &mut client,
                    RpcCall::WorkspaceGet(WorkspaceReadParams {
                        context: remote_workspace.clone(),
                    }),
                    1,
                );
                assert!(matches!(
                    read_result(&mut client, &get, 1),
                    RpcResult::WorkspaceGet(_)
                ));
                if let Some(mode) = files {
                    let root_entry =
                        EntryId::from_bytes(remote_workspace.workspace_id.to_bytes()).unwrap();
                    match mode {
                        FilesMode::Read => files_script(&mut client, &remote_workspace, root_entry),
                        FilesMode::GitRead | FilesMode::GitFragmentRevoke => {
                            client
                                .socket
                                .get_mut()
                                .sock
                                .set_read_timeout(Some(Duration::from_secs(15)))
                                .unwrap();
                            git_read_script(
                                &mut client,
                                &remote_workspace,
                                matches!(mode, FilesMode::GitFragmentRevoke),
                            );
                        }
                        FilesMode::GitRevoke => {
                            let _ = send_request(
                                &mut client,
                                RpcCall::GitRepositories(WorkspaceReadParams {
                                    context: remote_workspace.clone(),
                                }),
                                2,
                            );
                            assert!(
                                client.try_message().is_none(),
                                "unshared Git result must never be disclosed"
                            );
                        }
                        FilesMode::GitRefused => {
                            // A files-only grant cannot reach the Git service.
                            // The host closes without a fabricated result.
                            let _ = send_request(
                                &mut client,
                                RpcCall::GitRepositories(
                                    lomi_remote_protocol::rpc::WorkspaceReadParams {
                                        context: remote_workspace.clone(),
                                    },
                                ),
                                2,
                            );
                            assert!(client.try_message().is_none());
                        }
                        FilesMode::Watch => files_watch_script(
                            &mut client,
                            &remote_workspace,
                            root_entry,
                            &thread_root,
                        ),
                        FilesMode::Mutate => files_mutation_script(
                            &mut client,
                            &remote_workspace,
                            root_entry,
                            &thread_root,
                        ),
                        FilesMode::Fenced => {
                            use lomi_remote_protocol::rpc::{
                                DestinationState, FileMutationContext, FilesCreateParams,
                                FilesStatParams,
                            };
                            let files_root_revision = match call_response(
                                &mut client,
                                RpcCall::FilesStat(FilesStatParams {
                                    context: remote_workspace.clone(),
                                    entry_id: root_entry,
                                    file_revision: None,
                                }),
                                2,
                            ) {
                                RpcResponse::Result {
                                    result: RpcResult::FilesStat(meta),
                                    ..
                                } => meta.file_revision,
                                other => panic!("files.stat failed: {other:?}"),
                            };
                            let _request = send_request(
                                &mut client,
                                RpcCall::FilesCreate(FilesCreateParams {
                                    mutation: FileMutationContext {
                                        operation_id: OperationId::from_bytes(
                                            writer.files_fence_operation(),
                                        )
                                        .unwrap(),
                                        context: remote_workspace.clone(),
                                    },
                                    parent_entry_id: root_entry,
                                    parent_revision: files_root_revision.clone(),
                                    name: "fenced.txt".to_owned().try_into().unwrap(),
                                    destination: DestinationState::Absent,
                                }),
                                3,
                            );
                            // A fenced effect is withheld: closed, never answered.
                            loop {
                                match client.socket.read() {
                                    Err(_) | Ok(Message::Close(_)) => break,
                                    Ok(Message::Ping(_)) => client.socket.flush().unwrap(),
                                    Ok(Message::Pong(_)) => (),
                                    other => panic!("fenced create emitted data: {other:?}"),
                                }
                            }
                        }
                    }
                    drop(client);
                    tx.send(None).unwrap();
                    return;
                }
                let request = send_request(&mut client, call, 2);
                let receipt = if let Some(rejection) = rejection {
                    let message = client.message();
                    assert_eq!(message.kind, MessageKind::RpcResponse);
                    assert_eq!(message.id, 2);
                    match lomi_remote_protocol::decode_response_for(&message.bytes, &request)
                        .unwrap()
                    {
                        RpcResponse::Error { error, .. } => {
                            assert_eq!(
                                error.code(),
                                match rejection {
                                    Rejection::StaleRevision => ErrorCode::RevisionConflict,
                                    Rejection::StaleSession => ErrorCode::StaleEpoch,
                                    Rejection::MissingTarget => ErrorCode::ResourceNotFound,
                                }
                            );
                            assert_eq!(error.effect(), Effect::None);
                        }
                        other => panic!("expected a pre-effect rejection, got {other:?}"),
                    }
                    // The connection survives: the next request is served.
                    let again = send_request(
                        &mut client,
                        RpcCall::WorkspaceGet(WorkspaceReadParams {
                            context: remote_workspace,
                        }),
                        3,
                    );
                    assert!(matches!(
                        read_result(&mut client, &again, 3),
                        RpcResult::WorkspaceGet(_)
                    ));
                    None
                } else if round < 2 && !fault {
                    let receipt = match (case, read_result(&mut client, &request, 2)) {
                        (EditFixture::Rename, RpcResult::TerminalRename(receipt)) => receipt,
                        (
                            EditFixture::MoveSameTabBefore | EditFixture::MoveCrossTabAfter,
                            RpcResult::TerminalMove(receipt),
                        ) => receipt,
                        (EditFixture::Create, RpcResult::TerminalCreate(receipt)) => receipt,
                        (EditFixture::Split, RpcResult::TerminalSplit(receipt)) => receipt,
                        (EditFixture::Close, RpcResult::TerminalClose(receipt)) => receipt,
                        (EditFixture::Restart, RpcResult::TerminalRestart(receipt)) => receipt,
                        _ => panic!("receipt method differs from original request"),
                    };
                    assert_eq!(receipt.state(), OperationState::Succeeded);
                    assert_eq!(receipt.effect(), Effect::Committed);
                    assert_eq!(
                        receipt.stored_rights().original_method(),
                        request.call.method()
                    );
                    assert_eq!(
                        receipt.stored_rights().actor().to_bytes(),
                        context.grant.consumer_authorization_id
                    );
                    Some(receipt)
                } else {
                    if writer == FaultWriter::ExecFailure
                        && matches!(case, EditFixture::Create | EditFixture::Split)
                    {
                        // execve really failed before anything existed: a known
                        // no-effect failure, answered as an ordinary error that
                        // names the operation instead of closing the connection.
                        let message = client.message();
                        assert_eq!(message.kind, MessageKind::RpcResponse);
                        assert_eq!(message.id, 2);
                        match lomi_remote_protocol::decode_response_for(&message.bytes, &request)
                            .unwrap()
                        {
                            RpcResponse::Error {
                                error,
                                operation_id,
                                ..
                            } => {
                                assert_eq!(error.code(), ErrorCode::HostBusy);
                                assert_eq!(error.effect(), Effect::None);
                                assert!(operation_id.is_some());
                            }
                            other => panic!("expected a no-effect error, got {other:?}"),
                        }
                        drop(client);
                        tx.send(None).unwrap();
                        return;
                    }
                    // Changed binding is closed/withheld, never a fresh mutation
                    // or a receipt disclosure under an unverified hash.
                    loop {
                        match client.socket.read() {
                            Err(_) | Ok(Message::Close(_)) => break,
                            Ok(Message::Ping(_)) => client.socket.flush().unwrap(),
                            Ok(Message::Pong(_)) => (),
                            other => panic!("conflicting edit emitted data: {other:?}"),
                        }
                    }
                    None
                };
                drop(client);
                tx.send(receipt).unwrap();
            });
            let mut driver = Driver::with_coordinator(&f.stopping, Arc::downgrade(&coordinator));
            driver.script_ticket_for_test(Ok(ticket_response(&intent)), None, Duration::ZERO);
            driver.script_relay_for_test(
                lomi_host_http::RelayTransport::with_test_root(endpoint.clone(), root.clone())
                    .unwrap(),
            );
            assert!(driver.accept(handoff, auth, f.runtime(), &f.eligibility));
            driver.after_channel_step(&mut channel_worker, auth, f.runtime(), &f.eligibility);
            let until = Instant::now()
                + Duration::from_secs(
                    if matches!(
                        files,
                        Some(FilesMode::GitRead | FilesMode::GitFragmentRevoke)
                    ) {
                        30
                    } else {
                        4
                    },
                );
            let mut revoked_git = None;
            let mut git_fragment_revoked = false;
            let mut git_heartbeat = Instant::now();
            let received = loop {
                // This local fixture has no Cloud worker. Reuse the terminal
                // fixture's heartbeat emulation while real WASI reads run.
                if matches!(
                    files,
                    Some(FilesMode::GitRead | FilesMode::GitFragmentRevoke)
                ) && git_heartbeat.elapsed() > Duration::from_secs(1)
                {
                    f.eligibility.heartbeat.request_started = Instant::now();
                    f.eligibility.heartbeat.wall_at_request_start = f.now();
                    git_heartbeat = Instant::now();
                }
                driver.advance(auth, f.runtime(), Some(&f.eligibility));
                if matches!(files, Some(FilesMode::GitFragmentRevoke))
                    && !git_fragment_revoked
                    && driver.sent_git_diff_fragments_for_test() == 1
                {
                    let cancelled = AtomicBool::new(false);
                    let operation = crate::unix::owner_domain::Operation::new(until, &cancelled);
                    f.owner
                        .begin_unshare(&operation, f.workspace)
                        .unwrap()
                        .try_commit()
                        .unwrap();
                    git_fragment_revoked = true;
                }
                if matches!(files, Some(FilesMode::GitRevoke))
                    && revoked_git.is_none()
                    && let Some(cancellation) = driver.pending_git_cancellation_for_test()
                {
                    let cancelled = AtomicBool::new(false);
                    let operation = crate::unix::owner_domain::Operation::new(until, &cancelled);
                    f.owner
                        .begin_unshare(&operation, f.workspace)
                        .unwrap()
                        .try_commit()
                        .unwrap();
                    revoked_git = Some(cancellation);
                }
                if let Ok(receipt) = rx.try_recv() {
                    break receipt;
                }
                assert!(
                    Instant::now() < until,
                    "edit ingress did not settle: driver={:?} channel={:?}",
                    driver.failure_observation_for_test(),
                    driver.channel_step_observation_for_test()
                );
                thread::yield_now();
            };
            driver.discard();
            join.join().unwrap();
            if matches!(files, Some(FilesMode::GitFragmentRevoke)) {
                assert!(
                    git_fragment_revoked && received.is_none(),
                    "unshare after first physical fragment withheld the rest of the result"
                );
                break;
            }
            if matches!(files, Some(FilesMode::GitRevoke)) {
                assert!(received.is_none());
                assert!(
                    revoked_git
                        .expect("read admitted before unshare")
                        .is_cancelled(),
                    "read ticket cancelled when its connection is discarded"
                );
                assert!(
                    std::fs::read_to_string(files_root.join("git-project/hello.txt"))
                        .unwrap()
                        .contains("after")
                );
                break;
            }
            if matches!(files, Some(FilesMode::Fenced)) && writer == FaultWriter::CompletionFailure
            {
                assert!(received.is_none(), "a failed completion must not deliver");
                assert!(
                    files_root.join("fenced.txt").exists(),
                    "the file effect ran before its completion failed"
                );
                assert!(
                    crate::unix::rpc::ensure_workspace_settled(&coordinator, f.workspace).is_err(),
                    "an unsettled effect blocks the workspace"
                );
                let cancel = AtomicBool::new(false);
                let maintenance = crate::unix::owner_domain::Operation::new(
                    Instant::now() + Duration::from_secs(5),
                    &cancel,
                );
                crate::unix::rpc::reconcile_deferred_completions(&coordinator, &maintenance)
                    .unwrap();
                assert!(
                    crate::unix::rpc::ensure_workspace_settled(&coordinator, f.workspace).is_ok()
                );
                let store = f.store.lock().unwrap();
                let receipt = store
                    .lookup_operation(
                        binding.rights.actor(),
                        f.workspace,
                        OperationId::from_bytes(writer.files_fence_operation()).unwrap(),
                        &vec![
                            Capability::WorkspaceRead,
                            Capability::FilesRead,
                            Capability::FilesWrite,
                        ]
                        .try_into()
                        .unwrap(),
                    )
                    .unwrap()
                    .expect("recovery must persist the receipt");
                assert_eq!(receipt.state(), OperationState::Succeeded);
                assert_eq!(receipt.effect(), Effect::Committed);
                assert!(files_root.join("fenced.txt").exists());
                break;
            }
            if matches!(files, Some(FilesMode::Fenced)) {
                assert!(received.is_none(), "a fenced effect must not deliver");
                assert!(
                    crate::unix::remote_terminal_lifecycle::fault::planned(
                        writer.files_fence_operation()
                    )
                    .is_some(),
                    "the fault must have fired"
                );
                assert!(
                    !files_root.join("fenced.txt").exists(),
                    "the effect must not run"
                );
                let cancel = AtomicBool::new(false);
                let maintenance = crate::unix::owner_domain::Operation::new(
                    Instant::now() + Duration::from_secs(5),
                    &cancel,
                );
                crate::unix::rpc::reconcile_deferred_completions(&coordinator, &maintenance)
                    .unwrap();
                let store = f.store.lock().unwrap();
                let receipt = store
                    .lookup_operation(
                        binding.rights.actor(),
                        f.workspace,
                        OperationId::from_bytes(writer.files_fence_operation()).unwrap(),
                        &vec![
                            Capability::WorkspaceRead,
                            Capability::FilesRead,
                            Capability::FilesWrite,
                        ]
                        .try_into()
                        .unwrap(),
                    )
                    .unwrap()
                    .expect("the fenced attempt must leave a durable receipt");
                assert_eq!(receipt.state(), OperationState::Failed);
                assert_eq!(receipt.effect(), Effect::None);
                assert!(
                    !files_root.join("fenced.txt").exists(),
                    "settling must not run it"
                );
                break;
            }
            if let Some(mode) = files {
                assert!(received.is_none());
                let store = f.store.lock().unwrap();
                match mode {
                    FilesMode::Read
                    | FilesMode::Watch
                    | FilesMode::GitRefused
                    | FilesMode::GitRead => {
                        assert_eq!(store.events_after(0).unwrap().events.len(), events_before)
                    }
                    FilesMode::GitRevoke | FilesMode::GitFragmentRevoke => {
                        unreachable!("handled before projection checks")
                    }
                    FilesMode::Fenced => unreachable!("handled above"),
                    FilesMode::Mutate => assert!(
                        store.events_after(0).unwrap().events.len() > events_before,
                        "file operations are journalled"
                    ),
                }
                // Files never change the workspace projection or publish.
                assert_eq!(store.workspace(f.workspace).unwrap().state, before);
                assert!(store.pending_publications().unwrap().is_empty());
                break;
            }
            if rejection.is_some() {
                assert!(received.is_none());
                let store = f.store.lock().unwrap();
                assert_eq!(
                    store.workspace(f.workspace).unwrap().state,
                    before,
                    "a rejected request must not change anything"
                );
                let sent = lomi_host_store::OperationBinding {
                    rights: binding.rights.clone(),
                    parameter_hash: lomi_host_store::parameter_hash(&sent_call).unwrap(),
                };
                assert!(store.lookup(&sent, &rights).unwrap().is_none());
                assert!(store.lookup(&binding, &rights).unwrap().is_none());
                assert_eq!(
                    store.events_after(0).unwrap().events.len(),
                    events_before,
                    "a rejected request must journal nothing"
                );
                assert!(store.pending_publications().unwrap().is_empty());
                drop(store);
                if case.is_effect() && !matches!(case, EditFixture::Create) {
                    for target in &sessions {
                        assert!(
                            coordinator
                                .terminals
                                .snapshot(target.session_id, target.session_epoch)
                                .is_ok(),
                            "a rejected request must not stop any PTY"
                        );
                    }
                }
                break;
            }
            if fault && writer == FaultWriter::CompletionFailure {
                assert!(received.is_none(), "a failed completion must not deliver");
                let (spawn, stop) = crate::unix::remote_terminal_lifecycle::fault::planned(
                    mutation.operation_id.to_bytes(),
                )
                .expect("the hook must have recorded the plan");
                let alive = |t: &TerminalContext| {
                    coordinator
                        .terminals
                        .snapshot(t.session_id, t.session_epoch)
                        .is_ok()
                };
                // The physical effect ran; only its journal completion failed.
                assert!(spawn.iter().all(alive), "the spawn must have happened");
                assert!(
                    stop.iter().all(|t| !alive(t)),
                    "the stop must have happened"
                );
                {
                    let store = f.store.lock().unwrap();
                    assert!(
                        store
                            .lookup(&binding, &rights)
                            .unwrap()
                            .is_none_or(|receipt| !receipt.state().is_final()),
                        "the unfinished attempt has no final receipt yet"
                    );
                }
                assert!(
                    crate::unix::rpc::ensure_workspace_settled(&coordinator, f.workspace).is_err(),
                    "an unsettled effect blocks the workspace"
                );
                let cancel = AtomicBool::new(false);
                let maintenance = crate::unix::owner_domain::Operation::new(
                    Instant::now() + Duration::from_secs(5),
                    &cancel,
                );
                crate::unix::rpc::reconcile_deferred_completions(&coordinator, &maintenance)
                    .unwrap();
                assert!(
                    crate::unix::rpc::ensure_workspace_settled(&coordinator, f.workspace).is_ok()
                );
                let store = f.store.lock().unwrap();
                let receipt = store
                    .lookup(&binding, &rights)
                    .unwrap()
                    .expect("recovery must persist the receipt");
                assert_eq!(receipt.state(), OperationState::Succeeded);
                assert_eq!(receipt.effect(), Effect::Committed);
                let after = store.workspace(f.workspace).unwrap().state;
                drop(store);
                assert_effect_state(case, &coordinator, &before, &after, &sessions);
                break;
            }
            if fault && writer == FaultWriter::ExecFailure && matches!(case, EditFixture::Restart) {
                // The old PTY was stopped before the replacement failed inside
                // execve: a possible effect, so unknown, never replayed.
                assert!(received.is_none(), "an unknown outcome must not deliver");
                let (spawn, stop) = crate::unix::remote_terminal_lifecycle::fault::planned(
                    mutation.operation_id.to_bytes(),
                )
                .expect("the hook must have recorded the plan");
                let alive = |t: &TerminalContext| {
                    coordinator
                        .terminals
                        .snapshot(t.session_id, t.session_epoch)
                        .is_ok()
                };
                assert!(spawn.iter().all(|t| !alive(t)), "exec failed: no new PTY");
                assert!(stop.iter().all(|t| !alive(t)), "the old PTY was stopped");
                assert!(alive(&sessions[0]), "the untouched PTY survives");
                let store = f.store.lock().unwrap();
                let receipt = store
                    .lookup(&binding, &rights)
                    .unwrap()
                    .expect("the attempt must leave a durable receipt");
                assert_eq!(receipt.state(), OperationState::OutcomeUnknown);
                assert_eq!(receipt.effect(), Effect::Unknown);
                break;
            }
            if fault {
                assert!(received.is_none(), "a fenced effect must not deliver");
                let (spawn, stop) = crate::unix::remote_terminal_lifecycle::fault::planned(
                    mutation.operation_id.to_bytes(),
                )
                .expect("the fault must have fired");
                assert_eq!(spawn.is_some(), !matches!(case, EditFixture::Close));
                assert_eq!(
                    stop.is_some(),
                    matches!(case, EditFixture::Close | EditFixture::Restart)
                );
                let alive = |t: &TerminalContext| {
                    coordinator
                        .terminals
                        .snapshot(t.session_id, t.session_epoch)
                        .is_ok()
                };
                // The fence must leave the physical world exactly as it was:
                // nothing spawned, nothing stopped. (`Create`'s baseline pane
                // is a store fixture, not a real PTY.)
                let physically_unchanged = || {
                    spawn.iter().all(|t| !alive(t))
                        && (matches!(case, EditFixture::Create) || sessions.iter().all(alive))
                };
                assert!(physically_unchanged(), "a fenced effect must not run");
                let untouched =
                    |state: &WorkspaceState| {
                        let spawned = spawn.as_ref().map(|t| t.session_id);
                        state.tabs.0.len() == before.tabs.0.len()
                            && !matches!(state.tabs.0[0].layout, TerminalLayout::Split { .. })
                            && pane_sessions(state)
                                .iter()
                                .all(|s| Some(s.session_id) != spawned)
                            && state.tabs.0.iter().all(|t| {
                                t.name != "remote-create-once".to_owned().try_into().unwrap()
                            })
                    };
                assert!(untouched(
                    &f.store
                        .lock()
                        .unwrap()
                        .workspace(f.workspace)
                        .unwrap()
                        .state
                ));
                let cancel = AtomicBool::new(false);
                let maintenance = crate::unix::owner_domain::Operation::new(
                    Instant::now() + Duration::from_secs(5),
                    &cancel,
                );
                crate::unix::rpc::reconcile_deferred_completions(&coordinator, &maintenance)
                    .unwrap();
                let store = f.store.lock().unwrap();
                let receipt = store
                    .lookup(&binding, &rights)
                    .unwrap()
                    .expect("the fenced attempt must leave a durable receipt");
                assert_eq!(receipt.state(), OperationState::Failed);
                assert_eq!(receipt.effect(), Effect::None);
                assert!(untouched(&store.workspace(f.workspace).unwrap().state));
                assert!(physically_unchanged(), "settling must not run the effect");
                break;
            }
            if round == 0 {
                committed = received;
            } else if round == 1 {
                assert_eq!(received, committed);
            } else {
                assert!(received.is_none());
            }
            if !case.is_effect() && !matches!(case, EditFixture::Rename) {
                for target in &sessions {
                    let snapshot = coordinator
                        .terminals
                        .snapshot(target.session_id, target.session_epoch)
                        .unwrap();
                    assert_eq!(
                        snapshot.session_epoch.as_bytes(),
                        &target.session_epoch.to_bytes()
                    );
                }
            }
            let mut store = f.store.lock().unwrap();
            let after = store.workspace(f.workspace).unwrap().state;
            if case.is_effect() {
                if round == 0 {
                    assert_effect_state(case, &coordinator, &before, &after, &sessions);
                    settled_state = Some(after.clone());
                    settled_descriptors = Some(format!(
                        "{:?}",
                        store.terminal_descriptors(f.workspace).unwrap()
                    ));
                } else {
                    // Duplicate or conflicting retry: no second spawn/stop, no
                    // state, descriptor or journal change of any kind.
                    assert_eq!(
                        Some(&after),
                        settled_state.as_ref(),
                        "effect replayed or changed state after its durable receipt"
                    );
                    assert_eq!(
                        Some(format!(
                            "{:?}",
                            store.terminal_descriptors(f.workspace).unwrap()
                        )),
                        settled_descriptors
                    );
                }
                // admission + start + completion; never repeated.
                assert_eq!(
                    store.events_after(0).unwrap().events.len(),
                    events_before + 3
                );
            } else {
                assert_eq!(
                    after, expected,
                    "edit replayed or changed another tuple/layout field"
                );
                let retained_sessions = pane_sessions(&after);
                assert_eq!(retained_sessions.len(), sessions.len());
                assert!(
                    sessions
                        .iter()
                        .all(|session| retained_sessions.contains(session))
                );
                assert_eq!(
                    format!("{descriptors:?}"),
                    format!("{:?}", store.terminal_descriptors(f.workspace).unwrap())
                );
                assert_eq!(
                    store.events_after(0).unwrap().events.len(),
                    events_before + 1
                );
            }
            if round == 2 {
                let changed = lomi_host_store::OperationBinding {
                    rights: binding.rights.clone(),
                    parameter_hash: lomi_host_store::parameter_hash(&sent_call).unwrap(),
                };
                assert!(store.lookup(&changed, &rights).unwrap().is_none());
            }
            assert_eq!(
                store.lookup(&binding, &rights).unwrap(),
                committed,
                "wire receipt differs from actual durable journal"
            );
            if round == 0 {
                assert_eq!(store.pending_publications().unwrap().len(), 1);
                // Apply exact synthetic cloud ACK through actual Store APIs,
                // then install its real current binding/publication for fresh
                // GET/admission on new connections. Never clear pending flags.
                let publication = store
                    .prepare_host_publication(&f.eligibility.binding)
                    .unwrap();
                f.eligibility.binding = store
                    .acknowledge_host_publication(
                        &publication,
                        &PublicationResult {
                            runtime: publication.params.runtime.clone(),
                            publication_seq: publication.params.publication_seq,
                        },
                    )
                    .unwrap();
                f.eligibility.publication = store
                    .acknowledged_host_publication(&f.eligibility.binding)
                    .unwrap()
                    .unwrap();
            }
            assert!(store.pending_publications().unwrap().is_empty());
        }
    });
    peer::current_pairing_script::clear();
}
