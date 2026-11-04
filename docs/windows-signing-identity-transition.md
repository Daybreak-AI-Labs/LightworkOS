# Reviewed Windows signing identity transitions

Lightwork supports a bounded bridge between two exact releases. The
installed updater key must authorize the bridge, and the proposed updater key
must independently sign the same policy. Both MSI files must still pass Windows
publisher verification. This does not recover a lost or compromised signing key,
enroll an untrusted certificate, or turn a different publisher into a trusted one.

The global **Signing identity transition** setting is off by default. It is also
an explicit installer-wizard choice. A tenant override cannot enable this
whole-installation authority. Enabling the setting permits review; it does not
approve an update. Ordinary same-key, same-publisher updates keep their existing
requirements.

## Release preparation

First distribute a bridge-capable source release through the existing unchanged
trust channel. An older application that does not implement this protocol cannot
be made bridge-capable by publishing a JSON proposal alone. Retain the original
source MSI and its immutable version manifest.

The release owner prepares the target native application with its intended new
compiled public key and channel, then builds and Authenticode-signs the target
MSI. Hash the final signed MSI bytes. Use immutable source and target inventories
to record both Python runtime hashes, both native executable hashes, exact
three-part versions, both certificate thumbprints and both encoded updater public
keys. No production signing keys belong in the repository or in any upload.

A schema-1 policy has exactly these fields:

```text
schema: 1
id: unique 32-character lowercase hexadecimal identifier
issued_at, expires_at: integer Unix seconds, positive interval at most 30 days
from, to:
  version: exact major.minor.patch (to must be newer)
  runtime_sha256, native_sha256: 64 lowercase hexadecimal characters
  publisher_thumbprint: 40 uppercase hexadecimal characters
  public_key: the encoded Tauri updater public key
new_installer_sha256: SHA-256 of the final signed target MSI
rollback: exact-retained-pair-only
```

Serialize that policy with Python's
`json.dumps(policy, sort_keys=True, separators=(",", ":"), allow_nan=False)` as
UTF-8, **without a trailing newline**. In the organization's separately controlled
signing systems, use the Tauri signer to sign those exact bytes with the old and
new updater private keys. The envelope contains only `policy`, `from_signature`
and `to_signature`, where the latter two are the encoded Tauri signature files.
Repeated or additional fields and envelopes larger than 64 KiB are refused.

The target MSI offered on the **old** channel must also have a Tauri signature
made with the old updater key. Its Authenticode signature is already final before
that signature is created. The separate target-channel artifact signature uses
the target key. These are distinct channel publications; keep their manifests and
signature files separate even when their MSI bytes are identical.

`apps/installer-msi/customer_feed.py` accepts `--identity-transition`,
`--transition-source-key` and `--transition-target-native` together with its normal
candidate arguments. It verifies both policy signatures, the old-key artifact
signature, target runtime/native/MSI hashes and target compiled public-key file
before adding the envelope to the feed. It never signs, distributes, or enrolls
trust itself. Conflicting immutable version metadata is refused without changing
the latest feed. Preserve the existing source version manifest; publish the
reviewed target version manifest and feed only through the organization's
authorized release process.

## Administrator and user workflow

1. In **Install & updates**, check the proposed newer release and use **Save
   signing transition for review**. This downloads public review material and
   grants no installation authority.
2. A global administrator enables **Signing identity transition** in Settings,
   enters the existing isolated **Workspace recovery mode**, and selects that
   file in **Installation recovery → Signing identity transition**.
3. Verify the file in the app. Compare the displayed source/target versions,
   publisher thumbprints, updater-key fingerprints and admission deadline with
   the release owner's independently supplied record. These fingerprints hash
   the encoded public-key text. Signature verification at this step is separate
   from Windows publisher trust checks performed on the actual MSI files.
4. Explicitly confirm both the signing transition and the impact on all local
   workspaces. The private 15-minute installation authorization binds the exact
   envelope digest and installed source identity. A changed file, account or
   failed authorization invalidates the displayed review.
5. Return to **Install & updates**, paste the authorization and confirm the exact
   offered update. The native offer, administrator grant, downloaded installers
   and retained recovery record must agree. The app verifies signatures and
   publisher identities, snapshots local state, and installs through the existing
   protected maintenance process. After installation, it checks the exact target
   runtime and native executable hashes, version and compiled key before marking
   the operation complete.

An ordinary protected upgrade without an admitted bridge must retain the old
updater key. If its installed native key changes unexpectedly, it is not reported
complete and the recovery block remains. The check does not claim to sandbox
code signed by an already trusted publisher. Same-version repair is an existing
old-key-signed immutable-release operation, not a supported identity-transition
mechanism; a repair offer carrying transition metadata is rejected. Release
owners must not republish changed bytes under an existing version.

## Expiry, interruption and rollback

Expiry and the default-off setting govern **new admissions**. Before publishing a
prepared recovery record, the app checks both again. Once that exact pair has
been admitted, its retained signed receipt permits **Resume this reviewed
operation** after expiry or after the setting is disabled. It does not authorize
a different installer, key, version or new operation. Every execution rechecks
the retained MSI bytes, both policy signatures and current Windows publisher
trust; disabling a certificate's trust can therefore block recovery too.

Completed-upgrade rollback uses only that originally admitted pair, after a new
explicit administrator rollback authorization. It rechecks the installed target
identity, restores the exact source MSI/runtime/native identity and the matching
pre-upgrade state. Existing accounting, external-action history and SQLite drift
refusals still apply. There is no merge of newer ledgers into an older runtime,
general downgrade permission, or automatic certificate-revocation bypass.
Interrupted operations retain their recovery point and in-app logs. Unbridged
releases, lost old signing authority, unavailable trusted installers and changed
protected state require coordinated administration.

## Reproducible checks and remaining acceptance

`packages/maverick-core/tests/test_release_identity_transition.py` uses real
signature verification for distinct old/new keys, unrelated keys, tampered
policy/artifacts, wrong source identity, expired fresh admission, explicit
consent, interrupted resume, exact-pair rollback and installed-key mismatch.
It also consumes `tests/fixtures/tauri_identity_bridge.json`, generated by actual
Tauri CLI 2.11.4. The fixture is synthetic public cryptographic evidence; its
historical admission time is fixed in the test, and it contains no private keys.

To independently regenerate disposable signer evidence without installing an
MSI, provide an already installed local Tauri CLI to:

```powershell
python scripts/acceptance/signing_identity_transition.py --tauri-cli apps/installer-desktop/node_modules/@tauri-apps/cli/tauri.js
python -m pytest -q packages/maverick-core/tests/test_release_identity_transition.py apps/installer-msi/test_customer_feed.py
```

The acceptance script generates three disposable updater identities, verifies
actual Tauri signatures, rejects the unrelated proof and deletes private keys
before publishing results. Python integration substitutes only Windows
inspection/installation and native identity queries; Chromium exercises the
actual maintenance assets with fixed synthetic IPC. These checks do not prove
Windows certificate trust, a real publisher rotation, installed native behavior
or production migration compatibility.

Before distributing a rotated release, run the exact old/new signed pair on a
protected disposable Windows machine. Record actual old/new publisher trust and
compiled updater identities, native version/hash observations, rejection of
unrelated/expired/tampered proposals, interrupted resume, and eligible completed
rollback. The [release-pair gate](windows-release-acceptance.md) currently covers
same-identity pairs; it does not substitute for this transition-specific native
acceptance. Recognized production certificates and actual release inputs remain
release-owner dependencies.

### Disposable hosted publisher-transition gate

The Windows desktop package workflow (`.github/workflows/windows-customer.yml`) also runs
`apps/installer-msi/accept_signing_transition_fixture.py` after the same-identity
acceptance. It copies the existing base and candidate MSIs, creates **two distinct
self-signed fixture publishers**, signs and verifies those copied packages using
Windows, and uses the existing compiled updater key for both policy signatures.
The two native hashes come from the separately preserved outputs of the existing
base/candidate builds; the gate does not build a third native executable. Source
MSIs and native build outputs must remain unchanged.

Only the exact GitHub-hosted Windows `build-and-accept` job can enter this mode.
Its fixture certificate creation, trust enrollment and deletion reuse the existing
guarded publisher helper. Cleanup is attempted for both exact recorded identities
even after an earlier stage fails, and any cleanup failure fails acceptance.
A 37-minute work deadline leaves time for bounded
process-tree termination and both cleanups inside the 45-minute workflow step.
Do not invoke this mode against a workstation or an installed user workspace.

The real frozen application starts an isolated recovery server and exercises
default-off refusal, invalid policy signatures, expired admission, and an
otherwise valid signed policy naming a publisher that does not match the actual
Windows-verified candidate MSI. The latter must fail before installation without
leaving a startup block. The positive case uses the actual administrator API,
verified MSI preparation, Windows Installer upgrade and exact retained rollback.
Native versions, compiled updater key and actual executable hashes are checked
at base, upgraded and rolled-back states. Synthetic files in two local workspaces
must return to their pre-upgrade contents.

After preparation, its first process exits and a separate retained helper must
resume the same admitted operation with a renewed private authorization. This
covers a process boundary **before MSI execution**, not a crash during an MSI
transaction. The profile keeps one updater key and one frozen Python runtime
while changing native package versions and actual publisher certificates, so it
does not establish a real installed key rotation or production release
compatibility.

The machine-readable result is
`customer-artifacts/publisher-transition-acceptance.json`. The orchestrator rejects
a zero exit without every required observation, exact envelope/artifact/native
bindings, honest fixture labels and successful cleanup. Bounded scrubbed stage
logs and the report are retained by the workflow. Adding this executable gate
does not itself establish a passed run: record the exact hosted run and report
before claiming distinct-publisher MSI acceptance.
