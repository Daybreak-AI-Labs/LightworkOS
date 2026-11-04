# Windows desktop package candidate

The packaged build combines Lightwork Desktop, the full eight-package frozen
release runtime, and the offline WebView2 installer into one x64 MSI. The
user runs the installer and opens Lightwork from the Start menu; no Git,
Python, pip, Node, or source checkout is required on that computer.
Provider accounts and network-dependent product features retain their normal
requirements. The engineering `Package.wxs` bootstrap is separate.

**Qualification boundary.** The Windows candidate workflow
(`.github/workflows/windows-customer.yml`) exercises native installation,
repair, synthetic upgrade/rollback and WebView journeys. Those runs use
disposable signing identities and the same frozen runtime under different
fixture versions. They do not qualify a recognized publisher, a clean end-user
computer or a real release migration; a release also needs a release-pair
acceptance run on real release builds. This workflow produces candidates; it
does not publish an installer or activate an update channel.

## In-app maintenance

Open **Lightwork → Install & updates**. Checking updates does not install
anything. The app displays the offered version and release notes, then requires
an explicit **Install and restart** action. It downloads from the HTTPS channel
compiled into the app and requires the Tauri/minisign signature to match the
compiled public key before Windows Installer can run. Remote dashboard content
cannot choose the installer, key, download address, or native maintenance page.

**Repair installation** uses the immutable `versions/<installed-version>.json`
manifest beside the configured feed. The MSI installs byte-identical recovery
runtime and native-shell copies, retains the exact signed source MSI, and adds a
**Repair Lightwork** Start-menu entry. That recovery application can open the
same in-app maintenance controls when either primary executable is missing or
damaged. The app still downloads and verifies the exact current-version package
with the compiled updater key, then requires its SHA-256, Authenticode
publisher, ProductCode and PackageCode to match the retained registered source
before Windows Installer can run. The exact version manifest and package must
therefore remain hosted; this is not an offline-repair claim. File repair
preserves workspace data.

An upgrade that fails inside the MSI transaction is expected to restore the
previous application files. A fault-injection fixture tests this separately
from a successful upgrade. General downgrades remain disabled. **Protected
completed-upgrade rollback has a candidate implementation**, with explicit
whole-installation authority and matching application/state restoration:

1. A global administrator opens **Workspace recovery mode**, reviews the effect
   on **all local workspaces and shared administration**, and creates a private
   15-minute installation authorization. The normal dashboard cannot grant it.
2. In **Install & updates**, paste the authorization and confirm the exact new
   release. The app obtains both old and new immutable signed installers, stops
   only its owned recovery server, and acquires a fresh control-plane lock.
3. The frozen runtime independently verifies both Minisign signatures against
   the installed native application's compiled key, valid Authenticode trust,
   identical publisher thumbprints, product identity and exact versions. An
   explicitly admitted [dual-signed identity bridge](../../docs/windows-signing-identity-transition.md)
   may instead bind one exact reviewed publisher/key transition. It
   retains the old runtime and native recovery UI outside MSI ownership and
   captures an authenticated whole-home snapshot before installing.
4. To undo a completed protected upgrade, authorize that specific recovery point
   in Workspace recovery, then confirm **Return to the authorized release and
   snapshot** in the desktop controls. A separate safety snapshot keeps newer
   local state. The retained helper uninstalls the reviewed new MSI, reinstalls
   the exact old MSI into its original installation directory, checks the old
   runtime hash, and only then restores old local state. It never asks an older
   ledger reader to accept a newer accounting format.
5. A durable marker blocks ordinary work until binary and state checks finish.
   Interrupted operations offer **Resume this reviewed operation** and bounded
   **View installation logs** inside the app. A crash after a completion receipt
   requires exact binary and normalized SQLite snapshot checks before the block
   can be cleared; it does not blindly re-run the installers.

External stores, independent workers, remote key services, settings outside the
local data home, unbridged certificate/key rotation, network installation paths and MSI
argument paths of 240 characters or longer require coordinated administration.
Payload files within a supported home retain extended Windows path support.
Local maintenance snapshots are limited to 8 GiB expanded and 200 workspaces;
there are 20 usable recovery points with explicit administrator retirement.
An unprotected earlier upgrade has no retrospective rollback snapshot. This
candidate protocol still needs actual native MSI and release acceptance below.

Signing transitions are a separate default-off global setting and administrator
review in recovery mode. They require the existing trusted key and proposed key
to sign the exact release-pair policy; neither a feed nor a repair offer can
grant this authority. Admission expiry does not strand an already admitted
interrupted pair. See the [signing transition procedure](../../docs/windows-signing-identity-transition.md)
for preparation, in-app controls and the distinct native acceptance boundary.
The disposable hosted workflow has a separate two-publisher transition fixture
that uses actual signed MSI upgrade/rollback and a pre-execution process-resume
boundary. Its `publisher-transition-acceptance.json` must pass independently of
the same-identity gate. It uses one updater key and unchanged frozen runtime
bytes, and does not establish production certificate or migration acceptance.

**Accounting changes prevent automatic rollback.** Before preparing rollback,
and again before either MSI runs, the app compares the selected snapshot with
current spending, holds, provider/team/MCP budgets, signed budget receipt
sidecars, shared tenant controls and every SQLite database. Added, removed or
changed protected files require coordinated administrator reconciliation; no
override merges new-format ledgers into an older application or resets real
spend. SQLite comparison uses consistent online snapshots, but conservatively
also refuses unrelated database changes. A preparation refusal leaves the
current application usable and creates no installation startup block. A late
refusal preserves an existing recovery block and its evidence. Snapshots,
exports and temporary restore drills remain available. This candidate therefore
does not support automatic rollback after accounting or database state changes.

## Build and acceptance

The desktop also provides a separately started [local workspace recovery
mode](../../docs/workspace-recovery.md). Package acceptance starts its frozen
entry point and checks ordinary work is blocked. Same-build local snapshots are
a recovery prerequisite. Completed-upgrade rollback restores the exact prior
application and matching pre-upgrade state; it is not an arbitrary cross-version
state migration or a whole-production disaster-recovery claim.

Use `.github/workflows/windows-customer.yml` on a disposable Windows build
runner. Build tools run only there. Python dependencies come from the reviewed
constraints and regular installs of `release-cohort.toml`; Rust and frontend
dependencies use committed locks. `build/maverick.spec` freezes the complete
runtime. `stage_customer.py` rejects invalid MSI versions and existing staging
directories before executing its version, provider-runtime, dashboard and MCP
checks. Those checks use a disposable working directory, explicit empty config,
profile and cache paths, and an OS environment allowlist; they do not inherit
operator credentials, configuration overrides or the developer PATH. The runtime
size and SHA-256 are streamed before the checks, rechecked after each command,
and compared with the staged copy before its inventory is written. These checks
detect input drift; they do not provide atomic admission against hostile writers
or containment for untrusted binaries. Installed acceptance remains separate.
The packaged desktop pins the sibling `maverick.exe` and never falls back to
another executable from PATH or an environment override.

`build-customer.ps1` generates an isolated Tauri MSI configuration. It embeds
the runtime and offline WebView2 installer, disables downgrades and the elevated
updater scheduled task, and uses the stable UpgradeCode
`AB5BC260-7EC9-4B70-AF78-28F4067BC530`. Do not change this identity for subsequent
releases. Acceptance-only fault injection cannot be enabled without a
separate labelled fixture version and never enters the signed release artifact.

The CI acceptance script installs into a fresh directory under `RUNNER_TEMP`,
removes developer tools from PATH, checks all eight installed packages, deletes
only the installed runtime and verifies repair restores the exact bytes, injects
an MSI upgrade failure and requires exit 1603 plus the logged injected action's
error and failed completion before verifying the prior runtime survives, performs the
successful fixture upgrade, and checks the packaged dashboard setup page. It
uninstalls the fixtures afterwards. It also checks a real ephemeral updater
signature and rejects tampered installer bytes using the updater's verification
library. This is **CI acceptance with developer tools absent from PATH**, not a
claim that the GitHub runner is a clean end-user computer. Fixture upgrade
versions exercise installer behavior; they do not exercise a production data
migration between two independently released application versions.

`test-completed-rollback.ps1` adds actual frozen-runtime protocol acceptance on
the disposable Windows runner: a temporary locally trusted code-signing
certificate and real updater signatures protect separate fixture MSI copies;
the real authenticated recovery API grants an update, the helper captures all
local state and upgrades, a second grant captures newer safety state, and the
helper reinstalls the old MSI and restores two workspaces. Developer tools are
absent from the runtime PATH. Certificate/key material and trust are removed
afterwards; fixture-signed packages are never uploaded as release artifacts.
The installed native application's fixed channel query must report the base,
candidate and base versions in sequence, with the expected compiled public key.
Both fixture installers contain identical frozen Python runtime bytes; the
report labels that limitation and checks those bytes remain unchanged. This
exercises actual native package replacement and local state restoration, but
does not prove migration between independently released Python runtimes.
This is neither a publicly recognized signing identity nor a native WebView
automation test. The separate Chromium tests use fixed synthetic Tauri IPC;
they verify the rendered controls without executing an installer.

Focused checks from the repository root:

```powershell
python -m pytest -q apps/installer-msi/test_customer.py apps/installer-msi/test_customer_feed.py apps/installer-msi/test_wxs.py packages/maverick-core/tests/test_release_packaging.py
python -m pytest -q packages/maverick-core/tests/test_backup_accounting_guard.py packages/maverick-core/tests/test_installation_accounting_recovery.py
node --test apps/desktop/tests/*.test.js
cargo test --locked --manifest-path apps/desktop-runtime/Cargo.toml
cargo test --locked --lib --manifest-path apps/desktop/src-tauri/Cargo.toml
cargo build --locked --manifest-path apps/installer-msi/verify-update/Cargo.toml
```

Rust/Tauri checks require the Windows SDK and MSVC linker on Windows. Run
`test-customer.ps1` only on a disposable runner, never against an installed user
workspace. A local build-host invocation after the full frozen runtime and
locked Tauri CLI have been built is:

```powershell
./apps/installer-msi/build-customer.ps1 -Runtime C:/build/dist/maverick.exe -PublicKeyFile C:/build/customer-updater.pub -UpdateEndpoint https://updates.example.test/latest.json -StageDirectory C:/build/customer-stage
```

The endpoint above is illustrative and must be replaced with the organization's
real release channel. No placeholder endpoint qualifies a candidate for shipping.

## Signing and distribution inputs

The manual workflow input `customer_release=true` requires reviewed `main` and
the protected `windows-customer-release` environment. Configure that environment
with required reviewers and a main-only deployment branch rule. Build jobs never
receive publisher or production updater private keys. Pin and review all build
dependencies before allowing the protected signing job.

Repository variables available to the build job:

| Variable | Required value |
| --- | --- |
| `LIGHTWORK_WINDOWS_UPDATE_PUBLIC_KEY` | Public Tauri updater key to compile into the application |
| `LIGHTWORK_WINDOWS_UPDATE_ENDPOINT` | Accessible HTTPS update metadata endpoint, no embedded credentials |

Protected environment inputs:

| Input | Required value |
| --- | --- |
| Secret `LIGHTWORK_WINDOWS_CERTIFICATE_PFX` | Base64 export of an existing, trusted Authenticode certificate and private key |
| Secret `LIGHTWORK_WINDOWS_CERTIFICATE_PASSWORD` | Export password |
| Variable `LIGHTWORK_WINDOWS_CERTIFICATE_THUMBPRINT` | Reviewed 40-character certificate thumbprint |
| Variable `LIGHTWORK_WINDOWS_TIMESTAMP_SERVER` | Publisher's HTTPS timestamp service |
| Secret `LIGHTWORK_WINDOWS_UPDATER_PRIVATE_KEY` | Dedicated Tauri updater signing key matching the compiled public key |
| Secret `LIGHTWORK_WINDOWS_UPDATER_KEY_PASSWORD` | Updater key password when configured |
| Variable `LIGHTWORK_WINDOWS_INSTALLER_URL_TEMPLATE` | HTTPS immutable artifact address with exactly one `{version}` placeholder |

`sign-customer.ps1` requires a current code-signing certificate, applies a
timestamped SHA-256 Authenticode signature and validates its publisher identity,
then signs those final MSI bytes with the separate updater key. The workflow
removes imported private keys before verifying the updater signature with the
compiled public key. A separate signature verification record identifies the
final installer hash and certificate; the unsigned runtime staging inventory
remains an accurate record of that earlier phase.

The output includes `Lightwork.msi`, its `.sig`, `updater.pub`, `latest.json`,
`versions/<version>.json`, `SHA256SUMS`, runtime inventory, and CI
acceptance/signature records. Identical feed-generation reruns retain the
original publication date; immutable version conflicts leave `latest.json`
unchanged. Upload the
unchanged signed MSI to the versioned address, verify its downloaded bytes and
both signatures, then publish the immutable version manifest beside the feed
and publish the feed at the configured endpoint through the
organization's reviewed release process. Do not replace an existing version's
installer bytes. Feed publication is intentionally outside this candidate job.

Before calling this supported: pass the new native CI workflow; test a recognized
publisher's final signed MSI on a clean supported Windows 11 x64 VM without
developer tools or an existing WebView2 installation; exercise first launch,
in-app setup, update download/signature rejection, repair, upgrade failure,
successful protected update, completed-upgrade rollback, interrupted-operation
resume, installation logs, retirement, uninstall and retained data; record OS version, installer and
runtime hashes, signature identities and actual results. Disconnect networking
for initial installation to establish the offline dependency claim separately
from provider-dependent functionality. Exercise two independently versioned
production runtimes and their actual state formats for the rollback gate;
synthetic fixture versions alone cannot establish production migration safety.

The separate [real release-pair acceptance gate](../../docs/windows-release-acceptance.md)
pins an immutable previous release and an actual signed candidate with different
frozen runtime hashes. It preserves original metadata, runs real application
state readers and refuses relabeled fixture evidence. Its protected disposable
Windows runner and original prior-release inputs must be supplied by the release
owner; adding the gate does not establish a passed production upgrade or rollback.
