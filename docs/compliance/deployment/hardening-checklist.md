# Compliant Deployment — Hardening Checklist

Frameworks: SOC 2 CC5/CC6/CC7; ISO 27001 A.8.*; ISO 42001 A.6/A.9.

This checklist covers the "enable the opt-in controls" step described in the
[compliance documentation](../README.md). Lightwork ships several controls
**off-by-default** so single-tenant local use is unchanged; a SOC 2 / ISO 27001
deployment must turn them **on and show them on**. Encryption at rest and audit
signing are on by default; the configuration sets them explicitly so the
posture does not depend on defaults. Apply
[`compliant-config.toml`](compliant-config.toml), then verify. Review the
checklist on every Lightwork upgrade.

## 1. Controls to enable

| # | Control | Set in config | Evidence key (`maverick soc2`) | Target |
| --- | --- | --- | --- | --- |
| 1 | Capability enforcement | `[capabilities] enforce = true` | `controls.capability_enforcement` | `enabled` |
| 2 | OIDC authentication | `[auth.oidc] enabled = true` (+ issuer/audience) | `controls.oidc_auth` | `enabled` |
| 3 | Tenant isolation | `[tenancy] by_user = true` | `controls.tenant_isolation` | `enabled` |
| 4 | Usage quotas | `[quotas] enforce = true` | `controls.usage_quotas` | `enabled` |
| 5 | Encryption at rest | `[encryption] at_rest = true` | `controls.encryption_at_rest` | `enabled` |
| 6 | Audit signing | `[audit] sign = true` | `audit_log` | `ok` (not `unsigned`) |
| 7 | Signing key present | (auto on first signed write / external key) | `audit_signing_key` | present |
| 8 | Container-only sandbox | `[sandbox] require_container = true` | (via `enterprise verify`) | enforced |
| 9 | Human-oversight gates | `[governance] require_human_min_risk`, `deny_min_risk` | (policy; audited) | set |
| 10 | Continuous fairness monitoring | `[fairness_monitor] enable = true` | (`FAIRNESS_ALERT` events) | enabled |
| 11 | Enterprise data boundary | `[enterprise] mode = true` | `maverick enterprise verify` | all pass |

## 2. Pre-deployment checklist

- [ ] `compliant-config.toml` applied to `~/.maverick/config.toml`; placeholders filled.
- [ ] OIDC issuer/audience point at the real IdP; a test login succeeds.
- [ ] Encryption key is **externally managed** (`MAVERICK_ENCRYPTION_KEY` / KMS), not just the auto-generated on-disk key.
- [ ] **Off-host audit signing key** set via `MAVERICK_AUDIT_SIGNING_KEY` (or `..._WRAPPED`) from your KMS/secrets manager — **required** under `[enterprise] mode = true` (Lightwork refuses a local-disk key). Without it the chain writes unsigned and `audit_log != ok`. Back up the key in a separate trust store.
- [ ] A provider API key is present (so `/healthz` is not degraded), or self-hosted inference configured.
- [ ] Postgres backend + `maverick tenant rls-preflight` + `backfill` run if using DB-enforced isolation (`[world_model] rls = true`).
- [ ] Cloud provider attestations (SOC 2 / ISO) collected for inherited physical controls (A.7).
- [ ] Your sub-processor register reviewed and current (LLM providers, hosting, KMS).

## 3. Verify posture

Run the bundled checks (see [`verify-posture.sh`](verify-posture.sh)):

```bash
maverick soc2                       # exits non-zero unless all required controls are ready
maverick enterprise verify --require # exercises the regulated-deployment guarantees
maverick compliance --strict        # maps configured controls to GDPR / EU AI Act
maverick doctor                     # environment sanity
```

`maverick soc2` is the gate: it serializes `collect_soc2_evidence()` and exits
non-zero unless every required control is `enabled`, `audit_log` is `ok`, and the
signing key is present. Wire it into your deploy pipeline.

## 4. Post-deployment

- [ ] Capture a `maverick soc2 --json` snapshot as dated evidence (repeat on a schedule through the SOC 2 Type II observation window).
- [ ] Confirm `audit_log = ok` on a periodic job (chain + anchors verify).
- [ ] Record the deployment in your change log, under your change-management process.

## 5. Evidence to retain

The `maverick soc2 --json` snapshots, `enterprise verify` output, OIDC login
test, and the change record together evidence design + operating effectiveness of
the technical controls for the audit.
