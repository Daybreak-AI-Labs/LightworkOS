# maverick-desktop

The [Windows desktop package candidate](../installer-msi/CUSTOMER.md) uses this shell
with `customer-runtime` to start its bundled, complete executable. It adds
**Lightwork → Install & updates** with explicit review, signature-verified
updates, immutable-version repair, protected completed-upgrade rollback and
in-app recovery logs. The default engineering build and developer
setup below continue to use the installed CLI. Native packaging and trusted
publisher acceptance must pass before the packaged candidate is distributed.

**Lightwork → Workspace recovery mode** opens a bundled confirmation window.
It switches only the owned runtime to an isolated recovery process, and offers
an explicit return to normal work. Independent services are never taken over.
See [workspace recovery](../../docs/workspace-recovery.md) for administrator
setup, restore checks and excluded storage. Native Windows acceptance is still
required. The packaged-install maintenance protocol uses a separate explicit global
administrator authorization covering every local workspace; it restores the
exact prior application and matching snapshot together. See the candidate
guide for its scope, failure recovery and unverified native release gates.

Native desktop window for the **local** Lightwork dashboard. A Tauri v2 shell:
the window opens on a bundled splash, the Rust side starts
`maverick dashboard --host 127.0.0.1 --port 8765` if nothing is listening
there, and the splash navigates to `http://127.0.0.1:8765` only after the native bounded `/healthz` handshake identifies Lightwork dashboard-v1 with ready/setup-required status.

```
  +--------------------+        spawn if 8765 closed        +----------------------+
  | Rust shell (lib.rs)| ─────────────────────────────────► | maverick dashboard   |
  |  owns the window   |        kill own child on exit      |  (user's installed   |
  +---------+----------+                                    |   Python CLI)        |
            │ loads                                         +----------+-----------+
            ▼                                                          │
  ui/index.html + app.js ── native identity IPC ── navigates ─────┘
                                                       http://127.0.0.1:8765
```

- **Dashboard already running?** The shell leaves it alone, only navigates;
  it never kills a process it didn't spawn.
- **Lightwork not installed / not found?** The splash points to the Lightwork
  installer, offers an actual launch retry, and can show/copy startup details.
  It keeps polling while the dashboard starts.
- **Native menu:** Reload Dashboard (Cmd/Ctrl-R), Open in Browser
  (Cmd/Ctrl-Shift-O), Reconnect Lightwork, Quit, plus a standard Edit menu so copy/paste/select-all
  work in the dashboard's text fields (required for clipboard on macOS).
  Reconnect returns a disconnected dashboard to the fixed bundled startup
  screen and tries the installed launcher. Remote dashboard pages receive no
  additional native command permissions.

Run `cargo test --locked --lib --manifest-path apps/desktop/src-tauri/Cargo.toml`
from the repository root for Tauri mock-runtime reconnect tests. These require
the platform build SDK and linker; they do not prove packaged app startup.

## Connection and startup behaviour

1. **Dashboard identity.** The bundled splash asks native IPC for a bounded
   fixed-loopback health probe. HTTP 200 alone and opaque browser responses
   cannot authorize navigation. An unrelated listener yields an actionable
   conflict; valid setup-required 503 remains available.
2. **Content Security Policy.** The splash script is an external `app.js`
   (no inline `<script>`), and the CSP grants `script-src 'self'` plus
   `ws://127.0.0.1:8765` for the dashboard's WebSocket firehose.
3. **Finding `maverick` on a GUI launch.** GUI launches (Finder/Dock/Explorer)
   get a minimal `PATH` without the pip/pipx install directories, so the shell
   checks `MAVERICK_BIN`, then `PIPX_BIN_DIR`, `~/.local/bin`, `~/bin`,
   `/opt/homebrew/bin`, `/usr/local/bin` and `/usr/bin` before falling back to
   the bare name (`apps/desktop-runtime/src/lib.rs`).
4. **Window and menu.** Branded splash with staged status and an actionable
   trouble card; a native menu; explicit `main` window label; sensible minimum
   window size.

## Icons (do this before bundling)

Only a placeholder `icons/icon.png` ships. Generate the full platform set
(`.icns`, `.ico`, sized PNGs) from a single 1024×1024 source, then expand the
`bundle.icon` list in `tauri.conf.json`:

```bash
cargo tauri icon path/to/maverick-1024.png   # writes src-tauri/icons/*
```

## Build & run

Needs Rust + the Tauri CLI (plus platform webview dev packages, e.g.
`webkit2gtk` on Linux). The first local build on each platform is its
smoke test.

```bash
cargo install tauri-cli            # once
cd apps/desktop
cargo tauri dev                    # hot-reload dev window
cargo tauri build                  # native bundles (see targets below)
```

No JS toolchain: `ui/` is plain static HTML/CSS/JS (`frontendDist: "../ui"`),
no bundler step.

Bundle targets (`src-tauri/tauri.conf.json`):
- macOS: `.app` + `.dmg`
- Windows: `.msi` + `.exe` (NSIS)
- Linux: `.deb` + `.AppImage`

## Troubleshooting

- **Splash stuck on "Still waiting…":** the CLI isn't being found. Either run
  `maverick dashboard` yourself in a terminal (the window then connects on its
  own), or point the shell at the binary explicitly:
  `MAVERICK_BIN=/full/path/to/maverick` in the app's environment.
- **Wrong port:** this shell targets `8765` (the dashboard default). If you run
  the dashboard on another port, run it yourself on `8765`, or change
  `DASHBOARD_PORT` in `src/lib.rs`, the `PORT` in `ui/app.js`, and the CSP
  hosts in `tauri.conf.json`, then rebuild.

## Status

This dashboard shell is distinct from `apps/installer-desktop`: this app opens
an already-installed Lightwork dashboard, while `installer-desktop` performs
the source installation. `.github/workflows/desktop.yml` runs its Rust unit
tests, and `.github/workflows/windows-customer.yml` packages it for Windows
through `apps/installer-msi/build-customer.ps1`.

On Linux, Tauri 2.12 uses Wry's GTK3 backend. The registry releases of its
GTK/GLib 0.18 crates carry the `glib` soundness advisory (GHSA-wrw7-89jp-8q8g,
also published as RUSTSEC-2024-0429) and the unmaintained `proc-macro-error`
(RUSTSEC-2024-0370). The build resolves reviewed local patches for both
instead; see [`vendor/README.md`](../../vendor/README.md). `osv-scanner.toml`
carries no advisory exceptions.

Locally produced bundles are **unsigned**, so SmartScreen (Windows) and
Gatekeeper (macOS) will warn until code-signing certificates exist.

## Protected maintenance and offline packages

Check for updates first. Workspace recovery reviews the exact version and
installer/runtime identities and writes an administrator-bound, expiring private
handoff. Load protected approval in Install & updates, review its administrator,
action and scope, then explicitly install. The manual code fallback uses the same
exact release review. The secret remains in OS-private local records and native
memory, not either webview. Harmless page navigation retains the pending release.

For offline repair, an administrator supplies a local folder with `new.msi` and
`downloads.json`. The metadata is the same bounded object used by online repair:
`public_key` (the compiled pinned key), `identity_transition: null`, and `new`
containing `version`, `signature`, `runtime_sha256`, `installer_sha256`. Keep the
exact signed release package and its release metadata together when distributing
an offline package. Local metadata does not confer trust: Minisign, Windows
Authenticode, registered product/package, publisher, exact version and bundled
runtime are all checked. Online URLs are unused. Select its folder under **Repair
without a network connection**, verify the displayed identities, then confirm.
A working separately bundled recovery executable/native pair can repair a missing
primary runtime. Missing both trusted copies requires the signed release installer.

**Choose a supported recovery** identifies changed protected files and coordinated
external-resource blockers. Repair preserves current data; workspace recovery
opens its explicit isolation confirmation and offers existing per-workspace export
and restore drill controls. Save the metadata-only plan for the responsible
administrators. Plan evidence never waives accounting or action-history checks.
