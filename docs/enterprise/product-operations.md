# Updates and support for self-hosted deployments

A self-hosted deployment cannot assume internet access: it may run in a
locked-down VPC or a fully air-gapped enclave. Lightwork therefore gives
updates and support both a *connected* path and an *offline* path, and both
rely on the same primitive as the audit chain: **Ed25519 signing with offline
verification**. Nothing phones home; every update and support export is
signed, verifiable without a network, and recorded where the operator can
audit it.

| Capability | Connected (VPC with egress) | Change-controlled VPC | Air-gapped |
|---|---|---|---|
| **Updates** | signed feed → pull | signed artifacts, operations team pulls on schedule | **signed offline bundle, delivered out of band** |
| **Support** | opt-in OTel/metrics + bundle | redacted bundle | **redacted bundle, carried out by the operator** |

---

## 1. Updates

[`maverick/release_update.py`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/packages/maverick-core/maverick/release_update.py)
(tests: `tests/test_release_update.py`).

A **release manifest** is an Ed25519-signed document listing the `version`,
the `artifacts` (name, sha256 and size), the `min_from` version, and the
ordered **governed migrations** a release introduces. Manifests are signed and
verified by
[`maverick/release_manifest_signing.py`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/packages/maverick-core/maverick/release_manifest_signing.py)
(tests: `tests/test_release_manifest_signing.py`).

- `verify_manifest()` authenticates a release against the trusted publisher
  keys: `MAVERICK_RELEASE_PUBKEYS`, `[release] publisher_pubkeys` (also on
  **Settings > All settings > Server & deployment > Updates**) and any keys
  built into the release; the offline CLI's `--pubkey` replaces that set for
  one command. With no trusted key, every manifest is refused
  (`no_trust_anchor`).
- `verify_bundle()` verifies an **offline update bundle**: the manifest
  signature **and** every artifact's sha256, so a swapped binary is caught even
  if the manifest is authentic.
- `plan_upgrade()` blocks downgrades, no-ops and **version gaps** (below
  `min_from`, step through an intermediate release so migrations apply in
  order), and returns the migrations to run.
- `apply_bundle()` owns the governed order (**verify → plan → [snapshot] →
  migrate → install**) and is deployment-agnostic by injection: the caller
  passes `migrate(id)`, `install(dir, manifest)`, and optional `snapshot()` /
  `rollback(dir, manifest, handle)` callbacks (systemd, container tag, Tauri
  updater, workspace snapshot), so the risky swap only runs after the
  signature, hash and version-gap checks pass. When a `snapshot`/`rollback`
  pair is supplied, a failing migration or install **rolls back
  automatically** to the checkpoint (`ApplyResult.rolled_back`). Both hooks
  default to `None`.
- `rollback_bundle()` and the `rollback` CLI command (wired to
  `workspace_snapshot.restore_snapshot`) cover a bad release discovered after
  it was applied.

The offline CLI is
`python -m maverick.release_update {verify-bundle,plan,apply,rollback}`.

The governed migrations a manifest names are meant to resolve to the existing
**immutable, checksum-locked migrations** (`migration_governance`, with
`schema_migrations --ci` gating online/offline hot-deploy safety). Release
binaries also carry **Sigstore** signatures.

Per connectivity tier:

- **Connected:** a signed release feed with channels (stable/edge); desktop
  via a Tauri updater; cloud via a container tag bump and rolling restart.
- **Change-controlled VPC:** publish signed artifacts with release and
  migration notes; the operations team pulls on its own schedule, and
  `plan_upgrade()` plus governed migrations make each step auditable.
- **Air-gapped:** deliver a signed bundle out of band, run `verify_bundle()`
  offline, and apply under change control.

**Not built yet:** the concrete per-target `migrate`/`install` hooks (the
actual binary or container swap, blue-green), the release-feed publisher, and
channel configuration.

## 2. Support

[`maverick/support_bundle.py`](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/packages/maverick-core/maverick/support_bundle.py)
builds a **redacted** support bundle: versions, runtime, readiness checks,
providers, recent failures, and secret-scrubbed configuration, keyed by a
`correlation_id`.

- **Air-gapped / regulated:** the operator runs `maverick support`, reviews the
  redacted bundle, and delivers it out of band. There is no silent telemetry.
- **Connected and opt-in:** OpenTelemetry, Prometheus and Sentry (optional
  extras) for metrics and errors, without customer data, enabled per posture.
- `support_bundle.export()` writes the bundle to a file
  (`support-<correlation_id>.json` by default).
- `ticket_summary()` derives a compact, secret-free intake view (build,
  failing readiness checks, recent failure modes) from an already-redacted
  bundle: the fields an intake queue routes on, safe to send to a ticketing
  system.
- `maverick support -o` records a redacted **`support_bundle_exported`** audit
  event (correlation id and file name, never bundle contents) on the signed
  audit trail, so every support export appears in the deployment's own log.
  `collect()` stays pure; the audit emit lives in the CLI wrapper and is
  fail-soft.

**Not built yet:** a bridge from `ticket_summary()` into a ticketing system,
and the round trip from a support ticket to a hotfix release (§1).

---

## Publisher keys

Updates reduce to **signed, offline-verifiable documents against a publisher
trust anchor**, the same Ed25519 substrate as the proof pack and the audit
chain. Manage that keypair carefully, because it is the root of trust for
updates: generate it offline, store it in an HSM or KMS, rotate with an overlap
window, and distribute only the public key(s).

### Known limitations

- **Migration linkage is caller-wired** (see §1): `apply_bundle` gates on
  signature, hash and version, then delegates each migration to the injected
  `migrate` hook. Wiring that hook to `schema_migrations` is the deployment's
  responsibility until an automatic linkage exists.
