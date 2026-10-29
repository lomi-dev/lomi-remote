# Product SCM runtime proof

Run `python3 tests/product-scm-windows/run_native.py` only against the explicitly
authorized, pinned Windows test machine. The controller freezes the eight product
crates, vendored terminal parser, harness, and dependency identities before upload.
It records separate binary digests and closed metadata under
`artifacts/product-scm-windows/`; terminal output and secret bytes are not evidence.

The temporary UUID service uses Manual start and explicit non-administrator
LocalService in Session 0. The observer example calls the production SCM dispatcher
and actual host coordinator, uses ordinary product IPC and PTYs, and checks two
clients, input, resize, Ctrl-C, stop, owner crash, Lost projection, and no automatic
shell restoration. A sibling private profile exercises the real user-scope DPAPI
provider with fixed synthetic bytes under that same account.

A separate phase switches the stopped temporary service to the default
`lomiremote.exe --internal-scm NAME ABSOLUTE_PROFILE` entry. That phase checks SCM
readiness, controlled stop, nonzero crash, and restart/cleanup without any observer
or feature hooks. PTY assertions apply to the observer example phase. The foreign
operator account must remain rejected by the unchanged exact-SID IPC policy.

The harness checks exact service identity, owner SID, Session 0, process identities,
owned descendant termination, descriptor removal, and an unrelated process sentinel.
Cleanup removes only the UUID service and recognized private profile contents after
process termination. Unknown contents, reparse points, uncertain completion, or a
failed proof preserve resources for inspection. Source/build outputs remain owned
by their separate UUID upload and are removed after successful native completion.

This is runtime evidence for the recorded Windows 10 LTSC machine/build, using
LocalService as a disposable test account. It does not qualify a production
dedicated account, Windows 11/Server, boot/autostart, reboot, logoff, or installation
and management CLI. No user credentials or machine-wide SCM policy are changed.
