# Lightwork source bootstrap

Tauri GUI bootstrap for users who prefer not to drive
the source install from a terminal. A double-click app with one button: it runs
the same bootstrap the CLI
one-liners use (`deploy/desktop/install.{ps1,sh}`) behind a live
progress screen.

This is not a self-contained native installer. It clones a pinned commit from
the Lightwork GitHub repository, so network access is required, and the
installed Python source remains readable.

## How it works

```
  +------------------+   invoke('install')    +-------------------+
  | Svelte UI (TS)   | ────────────────────► | Rust shell (lib)  |
  |  Install button  | ◄───── events ──────── |  spawns bootstrap |
  +------------------+  install-log / -done    +---------+---------+
                                                          │
                                                          │ stdout/stderr
                                                          ▼
                                          deploy/desktop/install.{ps1,sh}
                                          (MAVERICK_NO_WIZARD=1):
                                          installs Python + git if needed,
                                          then pipx-installs Lightwork
```

The Rust shell owns the window and runs the bootstrap as a subprocess,
streaming each line to the UI as a Tauri event. **No Python is required
on the machine first** — the bootstrap installs it. This is why we shell
out to the existing scripts instead of embedding a Python runtime: those
scripts are already tested and are the single source of truth for "how
to install" (winget/brew/apt, PATH, pipx, PEP 668). When the bootstrap
finishes, **Open Lightwork** launches the local dashboard in an app window for
setup. Startup failures keep retry and bounded diagnostic output in the
installer. The shared `apps/desktop-runtime` crate owns that launch; its source
is included in the installer's commit-byte verification and provenance.

## Status

Builds **unsigned engineering workflow artifacts** on macOS / Windows / Linux
via `.github/workflows/desktop.yml`. The workflow verifies every raw source
byte against the triggering canonical Lightwork commit before running package
scripts, and the Rust build script repeats that gate before embedding the
committed bootstrap blobs. Git replacement refs and inherited `GIT_*` routing
variables are disabled for those checks.

Each uploaded artifact contains:

- a `.tar.gz` bundle package, so executable modes and symbolic-link metadata
  survive GitHub artifact transport; and
- a machine-readable provenance manifest with the repository/workflow/run
  identity, exact target, effective version override, committed bootstrap and
  icon/lock/config hashes, archive checksum, and bundle-entry checksums.

The upload paths are exact rather than wildcarded, and cached bundle output is
deleted before every build so a prior version cannot be mislabeled as the
current revision. These artifacts are still unsigned and are not attached to
product releases. A consumer-grade installer requires a signed-asset flow,
platform code signing, and real-machine install tests.

> **Needs real-machine testing.** CI confirms the bundle *builds*, but
> the actual install run (winget/brew, network, the GUI driving the
> bootstrap) has to be exercised on real Windows/macOS/Linux. Treat the
> first build as a release candidate to smoke-test, not a shipped
> artifact.

Cancellation owns and reaps the bootstrap process group on Unix and a
KILL_ON_JOB_CLOSE Job Object on Windows before the UI reports success. Package
managers or elevation brokers may cross that ordinary ownership boundary, and
an interrupted package operation may leave a partial dependency install.
Real-machine release testing must cover winget/brew/apt and elevation flows;
after cancellation, use the safe retry path (or the platform package manager's
repair/uninstall command) rather than assuming the machine was rolled back.

The Rust lockfile is current for Tauri 2.12, but its Linux dependency graph
still inherits Wry's GTK3 bindings. OSV Scanner 2.3.8 reports two advisories:
the medium-severity `glib` 0.18 soundness advisory (GHSA-wrw7-89jp-8q8g, also
published as RUSTSEC-2024-0429) and the unmaintained build-time
`proc-macro-error` (RUSTSEC-2024-0370) that the gtk/glib 0.18 macros pull in.
They have no compatible lockfile-only resolution: Wry 0.57 pins webkit2gtk
2.0.2, which requires GTK/GLib 0.18, and the `glib` fix begins at 0.20. Both
findings are Linux-only. The build resolves reviewed local patches for both
instead; see [`vendor/README.md`](../../vendor/README.md). `osv-scanner.toml`
carries no advisory exceptions. Keep Linux bundles engineering-only and
re-evaluate when webkit2gtk-rs and Wry move to gtk 0.19 / glib 0.20 or later.

## Local development

```bash
cd apps/installer-desktop
pnpm install
pnpm tauri dev
```

Hot-reloads the Svelte frontend. Clicking **Install Lightwork** runs the
bundled bootstrap, so test in a throwaway VM/container unless you actually want
Lightwork installed on your dev box. The desktop app embeds the installer
script blob directly from the git commit captured at build time and reports
that blob's SHA-256 in the install log. It pins the installed source to the
same commit; set
`MAVERICK_INSTALL_REF=<lowercase-full-40-character-commit-sha>` while building
only when you need to select an ancestor of the current commit intentionally.
Mutable tags, branches, unrelated commits, non-canonical repository origins,
Git replacement refs, and inherited Git object-routing variables are rejected
or disabled by the build. Release-grade bundle CI additionally byte-compares
the full installer source tree and both desktop bootstrap scripts with the
commit, including ignored and untracked files outside explicit generated
directories.

The five icon variants referenced by `tauri.conf.json` are committed build
inputs. If the source icon changes, regenerate the variants locally with
`pnpm tauri icon src-tauri/icons/icon.png`, review all six binary changes, and
commit them together. Bundle CI never regenerates or silently rewrites tracked
icons.

Before opening a pull request, run the same frontend checks as CI:

```bash
pnpm check
pnpm test
pnpm build
```

## Producing engineering source-bootstrap bundles

```bash
pnpm tauri build
```

The build script records `git rev-parse HEAD` as the install ref, so the GUI
installer does not fetch and execute a mutable `main` branch bootstrap at
install time. Workflow tag versions are passed through a temporary Tauri
configuration override after strict SemVer validation; tracked
`tauri.conf.json` is never rewritten.

Engineering outputs per platform:
- macOS: `.app` + `.dmg` (sign + notarize for distribution)
- Windows: `.msi` + `.exe` (NSIS)
- Linux: `.AppImage` + `.deb`

## Why Tauri vs Electron

| | Tauri | Electron |
|---|---|---|
| Bundle size | ~5 MB | ~150 MB |
| Memory at idle | ~50 MB | ~250 MB |
| Native webview | system (WebKit / WebView2 / WebKitGTK) | bundled Chromium |
| Rust shell | yes (security, smaller attack surface) | no |

Lightwork already needs Rust in the toolchain for the agent-shield
performance core, so adding Tauri is essentially free.

## Interrupted setup and dependency recovery

The app keeps a bounded local `bootstrap-recovery.json` journal in its OS app-data
directory. It records the pinned commit, last known phase, terminal outcome and
non-secret local dependency inventory. It does not store bootstrap log payloads,
GitHub credentials or AI keys. Launch or **Recheck dependencies** checks Git,
Python 3.11+, pipx and the installed Lightwork package report with owned processes,
eight-second deadlines and bounded output. A successful version response is
labelled **responded**, not proof of a complete dependency installation.

Before each start, a five-minute native review binds the inventory to this exact
bootstrap commit. After interruption, acknowledge that independent OS package or
elevation operations have finished. **Open OS application management** hands off
to the platform's existing controls; after repair, return and recheck. Linux uses
GNOME Software when present and gives manual OS-settings guidance otherwise.
macOS opens System Settings; dependencies installed by an external package manager
may still require that manager's administrator. The app never stops unowned OS
operations or claims a dependency rollback. Successful launch requires the native
Lightwork dashboard identity handshake, including legitimate onboarding.

## macOS/Linux engineering artifact verification

The only packaged installer candidate is the
[Windows desktop package](../installer-msi/CUSTOMER.md). macOS/Linux use the
engineering source setup: network access, dependency installation and readable
Python sources remain part of that journey. The GUI
above provides inventory, interruption recovery and in-app dashboard setup.
Unsigned workflow artifacts remain unsigned; do not relabel them as supported
installers or remove platform trust protections to suppress warnings.

Release operators can verify separately approved signed engineering packages with
`scripts/verify_desktop_artifact.py`. Supply a release-owner public key obtained
independently of the download and an expected commit/version/target. The tool
requires Python 3.11+ and [Minisign](https://jedisct1.github.io/minisign/) on the
operator's machine, verifies a bounded immutable signed manifest, and streams the
artifact SHA-256. It neither extracts nor executes the selected artifact, and it
never generates signing keys or changes credentials.

The signed manifest schema is `lightwork.signed-engineering-artifact.v1`, with
`repository: Daybreak-AI-Labs/LightworkOS`, full lowercase `commit`, exact `version`,
`target`, `support_channel: engineering`, `artifact_filename`, `artifact_sha256`
and integer `size_bytes`. Sign that manifest through the release owner's existing
approved process; no signing automation or release credentials are introduced here.

```bash
python3 scripts/verify_desktop_artifact.py --manifest release.json \
  --signature release.json.minisig --artifact Lightwork-engineering.tar.gz \
  --public-key "$REVIEWED_PUBLIC_KEY" --expected-commit "$REVIEWED_COMMIT" \
  --expected-version "$REVIEWED_VERSION" --target aarch64-apple-darwin
```

For Linux use the exact approved Linux target. The JSON receipt always labels
`customer_qualified: false` and `platform_signing_verified: false`. It proves the
selected signed bytes and release identity, not notarization or native install
acceptance. [Tauri's macOS signing guidance](https://v2.tauri.app/distribute/sign/macos/)
describes the separate platform-signing/notarization prerequisites. Production
certificates, notarization, supported target expansion, dependency
advisory resolution and exact native acceptance remain release prerequisites.
