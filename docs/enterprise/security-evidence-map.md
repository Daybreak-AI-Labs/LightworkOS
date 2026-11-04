# Security and compliance evidence map

A single entry point for technical and security review. Each row maps a
question a reviewer will ask to the artifact that answers it and, where it
exists, the command that **verifies** the claim on a live install — so a "yes"
can be exercised, not just asserted.

This page separates status explicitly: **code-enforced** controls ship and are
testable; **organizational** controls belong to the operating organization,
outside this repository; items **not verified against live services** are
named, not implied.

## Posture in one paragraph

Lightwork is a governed, self-hostable AI agent runtime designed for
private/regulated data. Enterprise mode provides application-layer egress
controls, fail-closed consent, capability scoping, and encryption at rest; a
hard no-egress boundary additionally requires sandbox and host/OS/VPC policy
(see [security-overview.md](security-overview.md)). Safety is defense-in-depth
(detection + action-layer containment), measured and reproducible
([shield benchmark](../security/shield-benchmark.md)). Evidence is
tamper-evident (Ed25519 hash-chained audit). Lightwork is licensed under the
Apache License 2.0 ([LICENSE](../../LICENSE)).

## Evidence map

| Area | What reviewers ask | Artifact | Verify |
|---|---|---|---|
| **Data handling / residency** | Can our data reach a third party? | Application egress controls and required deployment boundary — [security-overview.md](security-overview.md#application-egress-controls-enterprise-mode) | `maverick enterprise verify` (application controls) + independent sandbox/OS/VPC egress verification |
| **Encryption at rest** | Are sensitive stores encrypted? | [encryption.md](../encryption.md) (AES-256-GCM) | `maverick enterprise verify`; `maverick encryption migrate` |
| **Access control** | AuthN/Z, least privilege, tenancy? | [security-overview.md §Identity & access](security-overview.md#identity--access) (OIDC, RBAC, attenuating capabilities, per-tenant) | capability + OIDC + tenancy test suites (see [audit-readiness.md](../security/audit-readiness.md#security-test-suites-by-area)) |
| **Audit & evidence** | Tamper-evident, exportable logs? | [security-overview.md §Audit](security-overview.md#audit--evidence) | `maverick audit verify` (validates the hash chain); `maverick audit export` |
| **Threat model** | What's defended, what isn't? | [threat-model.md](../security/threat-model.md) (STRIDE, trust boundaries, out-of-scope) | n/a (design doc; cross-referenced by the test suites) |
| **AI/agent safety** | Prompt-injection / unsafe actions? | [shield-benchmark.md](../security/shield-benchmark.md) (layered detection + a decode/defang pre-pass that defeats base64/hex/homoglyph obfuscation on input, tool-call, and output surfaces + confirm-gated writes + container-isolated shell + budget caps) | `python benchmarks/security/detector_score.py`; latency/ReDoS CI gate |
| **Roster governance invariants** | Do the safety rails hold across *every* agent? | Roster-wide governance invariant test suite — six invariants verified across all 2,031 built-in specialist packs (tool-reachability, autonomy dial, capability attenuation, compartment isolation, hard refusals, budget caps), each fault-injected with a non-vacuous control, plus hostile-argument fuzzing of all connectors/tools | governance invariant suite in CI (each invariant has a fault-injection control proving it is non-vacuous) |
| **Vulnerability mgmt** | Deps, SAST, secrets? | [audit-readiness.md §Static-analysis gates](../security/audit-readiness.md#4-reproducible-verification-harness) | `pip-audit`; `bandit`; detect-secrets baseline; all blocking in CI |
| **Supply chain** | SBOM, provenance, third-party code? | SBOM produced in CI (CycloneDX); plugin tool-call isolation under enterprise + **content-hash lockfile** checks (drift refused after a lockfile exists; plugin import/discovery still runs in-process) | CI `audit` job artifact; `[plugins] isolation` / `lock_policy` |
| **SOC 2 readiness** | Control coverage + gaps? | [soc2-controls.md](../compliance/soc2-controls.md) (CC1–CC9, A/PI/C/P mapping + gap list) | `python -c "from maverick.soc2 import collect_soc2_evidence as c; print(c())"` |
| **Deployment / topology** | How does it run in our env? | [security-overview.md §Reference architecture](security-overview.md#reference-architecture-self-host--air-gap) (laptop / VPC / k8s / air-gap) | `maverick enterprise verify` on the target host |
| **Regulatory mapping** | GDPR / EU AI Act / DSAR? | [regulated-deployment.md](../regulated-deployment.md); `ai_act.py`; DSAR via `dsar.py` | `maverick compliance --strict` |
| **Licensing** | Under what terms is the code available? | [LICENSE](../../LICENSE) (Apache-2.0), dependency licenses | CI license gate (denies strong-copyleft) |
| **Data grounding / outbound connectors** | What primary-source data do agents reach, and can it leak? | Primary-source data grounding — 37 read-only, GET-only public-data connectors (SEC EDGAR, FRED, Treasury, World Bank, FDIC, Census, BLS, EIA, openFDA, NPPES, ClinicalTrials, USAspending, SAM.gov, CourtListener, Federal Register, GLEIF, OpenCorporates, NWS/NOAA, EPA, Climatiq, …) auto-granted per analyst pack by suite (`SUITE_DATA_CONNECTORS`, layered in `domain_capability`); low-risk, deferred, ON by default; separate from the 2,877 write-capable long-tail enterprise connectors | kill-switch `[workforce] data_grounding = false` / `MAVERICK_WORKFORCE_DATA_GROUNDING=off`; installer wizard step; hostile-argument connector fuzzing in the governance invariant suite |

## Status

**Code-enforced and verifiable:** egress lock, fail-closed consent,
capability scoping, encryption at rest, OIDC SSO, per-tenant isolation,
hash-chained signed audit, SBOM + dependency/secret/SAST CI gates, the shield's
layered detection + obfuscation-decoding pre-pass + action-layer containment,
container-default sandbox and plugin tool-call isolation + hash-lock checks under the
enterprise profile, and the SOC 2 evidence collector. The whole regulated posture
is selectable with one knob (`MAVERICK_PROFILE=enterprise`), each control still
individually overridable.

**On by default (secure-by-default):** at-rest encryption and audit signing are
**enabled out of the box** (`security_defaults.py`) and need no action unless
explicitly disabled — so a fresh install already reports `encryption_at_rest =
enabled` and writes a signed audit log.

**Must be enabled for a compliant deployment (opt-in by design):** the
deployment-specific controls — capabilities, tenant isolation, quotas, and OIDC —
ship off by default so single-tenant local use is unchanged. A regulated
deployment turns them on — `maverick compliance --strict` gates on the
[`REGULATED_PROFILE`](../regulated-deployment.md), and the evidence snapshot must
show `audit_log = ok` (signed), not `unsigned`.

**Organizational controls (owned by the operating organization, outside this repo):** change-management
policy, vendor/sub-processor management (incl. LLM providers), incident-response
program, HR controls, physical/environmental security (inherited from the
hosting provider's SOC 2), and a documented risk-assessment program. These are
enumerated in [soc2-controls.md §Gap summary](../compliance/soc2-controls.md).

**Not verified against live services:** SAML SSO and SCIM provisioning ship
alongside OIDC (see [security-overview.md](security-overview.md)) and are tested
against the protocol test suites in this repository; they are not certified
against a live identity provider. SOC 2 and
penetration-test attestations require external auditors and are the operating
organization's responsibility.

## Reproduce the whole verification pass

```bash
maverick enterprise verify          # egress lock + at-rest sealing actually hold
maverick compliance --strict        # regulated profile is fully enabled
maverick audit verify               # audit hash-chain is intact
python benchmarks/security/detector_score.py   # shield detection numbers (offline)
# CI also runs, blocking: pip-audit, bandit, detect-secrets, license gate, SBOM
```

No hyperscaler dependency and no product telemetry; everything above runs inside
the operator's boundary.
