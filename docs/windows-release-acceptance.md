# Acceptance of an actual Windows release pair

`windows-release-acceptance.yml` is a separate, manually authorized gate for an
actual previous release and an actual signed candidate. It does not build,
relabel, sign or publish either installer. The normal `windows-customer.yml`
synthetic version fixtures remain useful packaging tests; they cannot satisfy
this gate because it requires increasing real cohort versions and different
frozen runtime hashes.

The gate requires an original previous production release, configured
production identities and an owner-provisioned clean Windows VM as inputs. Do not
replace those inputs with the same runtime under two MSI version numbers. A first
release has no previous release to accept against; that is an explicit boundary,
not a reason to manufacture upgrade evidence.

## Original inputs and authority

The release owner prepares one reviewed JSON plan. Every ID and digest refers to
existing bytes. The plan is passed as workflow input through an environment
variable, never interpolated into shell code. No private key, token, certificate
password, provider credential or customer data belongs in the plan or bundles.

```json
{
  "schema": "lightwork.release-pair-plan.v1",
  "previous": {
    "release_id": 0,
    "asset_id": 0,
    "tag": "REPLACE_WITH_ORIGINAL_TAG",
    "version": "REPLACE_WITH_ACTUAL_VERSION",
    "runtime_sha256": "REPLACE_WITH_ORIGINAL_RUNTIME_SHA256",
    "archive_sha256": "REPLACE_WITH_ORIGINAL_RELEASE_ZIP_SHA256"
  },
  "candidate": {
    "run_id": 0,
    "artifact_id": 0,
    "head_sha": "REPLACE_WITH_ACTUAL_MAIN_COMMIT",
    "version": "REPLACE_WITH_ACTUAL_NEW_VERSION",
    "runtime_sha256": "REPLACE_WITH_ACTUAL_NEW_RUNTIME_SHA256",
    "archive_sha256": "REPLACE_WITH_SIGNED_CANDIDATE_ARTIFACT_ZIP_SHA256"
  },
  "updater_public_key_sha256": "REPLACE_WITH_SHA256_OF_TRIMMED_UTF8_PUBLIC_KEY_TEXT",
  "publisher_thumbprint": "REPLACE_WITH_APPROVED_CERTIFICATE_THUMBPRINT",
  "compatibility_review": "Record the reviewed prior/candidate schema, key and recovery protocol compatibility, including unsupported state.",
  "state_profile": "facts-and-encrypted-draft-v1"
}
```

This example deliberately fails validation until real positive IDs, versions and
digests replace its placeholders. The previous input is a published, non-draft,
non-prerelease **immutable GitHub release** and its exact ZIP asset ID/digest. The
candidate is the exact unexpired `windows-customer-signed-candidate` artifact
from a successful `windows-customer.yml` manual run on `main`, with a successful
protected `sign-customer-candidate` job and the pinned source commit. Merely
attaching a file with that name to an arbitrary workflow does not qualify.

The original ZIP must contain the following files at its root, with the original
version-specific manifest in its subdirectory:

- `Lightwork.msi` and `Lightwork.msi.sig`
- `runtime-inventory.json`, `updater.pub`, `signature-verification.json`
- `versions/<actual-version>.json`

Existing `SHA256SUMS`, `latest.json`, `acceptance.json` and
`completed-rollback-acceptance.json` are permitted but are not substituted for
the immutable version manifest. Other files, aliases, duplicate names, encrypted
ZIP entries, symlinks, excessive members and oversized archives are refused.
The supported archive is at most 1 GiB. Original archives remain byte-for-byte
intact alongside the extracted allowlist. The manifest binds MSI hash, runtime
hash, version and updater signature; the inventory must describe all eight
actual release packages and must explicitly have `acceptance_fixture=false`.
An original release missing this metadata needs release-owner provenance work;
the gate will not invent it retroactively.

GitHub documents [immutable release asset protection](https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases),
[release metadata and asset digests](https://docs.github.com/en/rest/releases/releases),
and [artifact digests and workflow-run identity](https://docs.github.com/en/rest/actions/artifacts).
The helper uses these exact API identities, verifies downloaded hashes and drops
the workflow authorization header on permitted storage redirects. These checks
do not replace cryptographic verification of the installer itself.

## Disposable Windows runner preparation

The release owner provisions a **new disposable Windows 11 x64 VM** from a
reviewed image for each attempt. This is infrastructure preparation, not an
operation the workflow performs on a user's machine. The image needs current
Windows servicing, PowerShell 7 and an ephemeral GitHub Actions runner. It must
not contain Lightwork or developer tools on PATH (including Python store aliases,
Git, Cargo, Rust, MSVC or WiX). Image cleanliness is owner-attested; the script
checks the observed VM model, UUID, Windows edition/build, boot time, tool PATH
and existing Lightwork registry entries. Those observations do not independently
prove the image's entire history.

Register it only with labels
`self-hosted, Windows, X64, lightwork-clean-release-acceptance`. Configure the
`windows-release-acceptance` environment to require a release-owner reviewer,
restrict it to `main`, and prevent self-review. Copy the already reviewed public
identity variables into that environment:

- `LIGHTWORK_WINDOWS_UPDATE_PUBLIC_KEY`
- `LIGHTWORK_WINDOWS_CERTIFICATE_THUMBPRINT`

No signing secret is needed. The VM provisioner supplies the following process
environment value to the ephemeral runner, binding the actual VM UUID and the
immutable image digest. This is not accepted as a workflow-dispatch input:

```json
{
  "schema": "lightwork.clean-windows-acceptance-host.v1",
  "disposable": true,
  "clean_supported_windows": true,
  "image_name": "OWNER_REVIEWED_IMAGE_NAME",
  "image_sha256": "ACTUAL_IMAGE_SHA256",
  "instance_id": "ACTUAL_WIN32_COMPUTERSYSTEMPRODUCT_UUID",
  "created_at": "ACTUAL_UTC_CREATION_TIME"
}
```

The value is named `LIGHTWORK_CLEAN_VM_ATTESTATION`. VM creation and boot must be
within six hours of the attempt. The runner account needs the release owner's
authorized ability to install/uninstall these MSIs on this disposable VM. The
script does not import certificates, change certificate stores, generate signing
identities or disable security policy. Both original MSIs must already pass
Windows Authenticode verification with the approved non-self-signed leaf
certificate. The separately built, hash-bound native verifier checks both real
Tauri updater signatures again before either MSI is launched.

## What the job exercises

Dispatch **Windows real release pair acceptance** from `main`, paste the reviewed
plan, explicitly authorize the disposable VM operations and approve its protected
environment. The first job only downloads and validates immutable inputs and
builds the reviewed offline verifier. The disposable VM receives that exact
artifact; it does not check out source or install Python, Git or build tools.

The VM driver then:

1. Checks each MSI's actual `ProductVersion`, original artifact hashes, signatures
   and protected public identity before installation.
2. Installs the previous MSI and checks the native compiled version/channel,
   exact frozen runtime bytes, actual eight-package version output and runtime
   capability check.
3. Uses the previous application's authenticated APIs to create a real WorldModel
   SQLite fact and an encrypted recovery draft, reads them back, and verifies
   the draft's sealed on-disk format. It also retains a file in a second local
   workspace. All contents and the isolated home are explicitly synthetic; no
   provider request, model task or customer record is used.
4. Repairs that installation and reads the same records through the actual app.
5. Authorizes an upgrade through the actual isolated recovery API and runs the
   retained maintenance helper with the **original** installer signatures,
   versions and distinct runtime hashes. It reads the prior records using the
   candidate's application code.
6. Authorizes completed-upgrade rollback, verifies the exact previous runtime
   and both application records, and verifies that the second workspace's
   original file is restored without an unresolved startup block.
7. Upgrades again, changes the real database through the candidate API, then
   verifies that rollback preparation refuses before replacing the installation
   or blocking normal startup. The candidate and changed record must remain.
   Protected database, accounting and external-action history must never be
   erased to make this test pass.

The profile supports unchanged signing identities and the documented local
facts/draft recovery contracts. A schema migration that changes protected
database bytes may correctly prevent automatic rollback; that pair has not
passed this compatibility profile. Likewise, a previous version without the
required recovery protocol cannot be called a successful rollback test. Record
the exact boundary and use the supported administrator reconciliation path.
Signing-key or publisher rotation requires separately reviewed identity-transition
coverage; changing this plan's pins does not waive those controls.

## Evidence and remaining release gates

The workflow retains `original-release-pair-inputs` and
`real-release-pair-acceptance-evidence` for 90 days. The former contains the
unaltered original ZIPs, selected original metadata, reviewed plan, source/run
identity and native verifier. The latter contains the actual JSON result and MSI
logs. A failure is not converted into a passed report. Successful cleanup removes
the test installation; failure preserves the disposable VM for diagnosis. The
owner must destroy the VM after evidence collection. Do not upload its synthetic
home: it contains encryption keys and authenticated recovery state.

`release_pair_accepted=true` means this exact install/repair/upgrade/rollback
profile passed for these two runtime hashes and this owner-attested VM. It does
not mean the whole release is accepted. The report explicitly records that it
does not automate the native WebView journey or verify network-isolated install.
Native first launch/setup, offline WebView2 bootstrap, interrupted operations,
failed upgrade recovery, production signing-certificate acceptance, update download
behavior and the broader release checklist in
[`apps/installer-msi/CUSTOMER.md`](../apps/installer-msi/CUSTOMER.md) remain separate
evidence. No workflow is dispatched or MSI installed merely by adding this gate.
