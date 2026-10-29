# Host-owned terminal service

`TerminalService` owns the host's PTYs and one canonical `TerminalState` per
session. The host coordinator resolves a trusted `SpawnProfile`, persists intent,
and applies the final authorization gate before a shell can execute. This crate
has no database, remote command DTO, process adoption, or automatic input replay.

Each OS-authenticated connection receives an independent `AuthenticatedConnection`.
`attach` checkpoints the model and registers a bounded subscriber. A renderer must
acknowledge its snapshot before requesting control. A lease binds the acknowledged
attachment, connection, actor, token, and version; it controls input and resize
and is invalidated on disconnect, expiry, or attachment removal.

The reader updates the sole model independently of observers. Natural exit keeps a
read-only snapshot for existing attachments while rejecting control, input, and
resize for that session epoch. Restart uses a fresh epoch. Recovery never adopts
an old process or replays a command. Only the model produces terminal protocol
replies.

Subscribers are limited to 1 MiB and 128 events, with at most 64 attachments per
session and 32 sessions. Overflow tears down only the affected subscriber and
requires a fresh snapshot. Input is limited to 16 KiB. Receipts contain only
identifiers, byte counts, and outcome; they never retain keystrokes or payloads.
Partial writes and lost fences report an unknown outcome and are never retried
automatically.

The Unix production host uses a private worker process for each shell. A bounded
private socket carries the trusted spawn profile, startup authorization, PTY file
descriptor, and cleanup acknowledgement. The host retains the terminal parser,
input path, and resize path. Startup authorization runs immediately before exec;
loss of the host endpoint initiates owned cleanup. No PID file, process adoption,
old-worker reattachment, or command replay is supported.

Linux worker cleanup establishes subreaper ownership before shell startup and
tracks only owned process handles. macOS session-cleanup features remain disabled
by default and experimental. They do not establish complete descendant
containment or a supported OS-version guarantee. Windows ConPTY uses a suspended
child, retained process handles, and a non-breakaway kill-on-close Job. Timeouts
and uncertain cleanup preserve owned resources rather than claiming success.

The terminal profile remains experimental. The Rust engine and browser renderer
exchange structured grid state; the renderer does not parse raw PTY bytes. A
consumer must provide authenticated transport, render acknowledgement, input
classification, and current control-lease checks.
