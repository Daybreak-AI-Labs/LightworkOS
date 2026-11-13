# Local dashboard launcher

Dependency-free Rust library shared by the installer and desktop shell. It
launches `maverick dashboard --host 127.0.0.1 --port 8765`, adding
`--recovery-mode` for recovery launches. The caller can pin the installed binary;
otherwise the native lookup honors `MAVERICK_BIN`. The child receives the
caller's environment overrides plus `MAVERICK_DESKTOP_CONTROL=stdin-v1` and
`MAVERICK_SHUTDOWN_TIMEOUT` for coordinated shutdown. No webview-supplied command,
path, argument, or URL is accepted.
Existing listeners are reused, running owned children are not duplicated, and
failed/exited launches can be retried. Startup output is kept only in memory,
bounded to 32 KiB, and displayed through an explicit diagnostics action.

Run `cargo test --locked --manifest-path apps/desktop-runtime/Cargo.toml` from
the repository root. Tests launch only synthetic test subprocesses. A full
Tauri build additionally requires the platform SDK/linker; source checking this
crate does not verify packaged app startup, OS installers, or provider access.

Process cleanup retains the desktop shell's ownership boundary: only a child
started by this app is stopped on exit. The installer bootstrap's separate
process-tree cancellation and package-manager cleanup rules are unchanged.
