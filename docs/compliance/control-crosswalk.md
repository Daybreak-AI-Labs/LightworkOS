# Control Crosswalk: SOC 2 ↔ ISO 27001 ↔ ISO 42001

This document maps Lightwork's technical controls to SOC 2, ISO/IEC 27001 and
ISO/IEC 42001. Each row is a control theme mapped across the three frameworks,
to the concrete Lightwork control(s) that address it, and to the codebase
evidence. An organization deploying Lightwork can use it to show its auditor
which requirements the software covers and which it must meet with its own
processes.

**Status legend** (same as [`soc2-controls.md`](soc2-controls.md)):

| Status | Meaning |
| --- | --- |
| **Implemented** | A concrete, enforced technical control exists in code. |
| **Implemented (on by default)** | Exists and enforced in a default install; an operator can turn it off explicitly (for example `MAVERICK_SECURE_DEFAULT=0`). |
| **Implemented (opt-in)** | Exists and enforced, but off-by-default — must be enabled for a compliant deployment. |
| **Partial** | A control exists but is scoped or incomplete. |
| **Process** | Satisfied by an organizational process that the organization deploying Lightwork operates; not provided by the code. |
| **Gap** | No control today; to be built or established. |

Framework references: SOC 2 = AICPA Trust Services Criteria (2017, rev. 2022).
ISO 27001 = ISO/IEC 27001:2022 Annex A (93 controls, themes A.5 Organizational /
A.6 People / A.7 Physical / A.8 Technological). ISO 42001 = ISO/IEC 42001:2023
Annex A (AI controls A.2–A.10).

---

## 1. Governance, policy & control environment

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Security/AI policy mandate | CC1.1, CC2.2 | A.5.1, Cl.5.2 | A.2.2, A.2.3, Cl.5.2 | Documented security and AI policies | Process | Operator's policy set |
| Org structure, roles, accountability | CC1.2–1.5 | A.5.2, A.5.3, A.5.4 | A.3.2, A.3.3 | Role definitions, governance bodies | Process | Operator's organization chart and role definitions |
| Integrity & ethics | CC1.1 | A.5.1 | A.2.x | Anti-test-cheating verifier; conduct standard | Partial | `maverick/verifier.py`; `CODE_OF_CONDUCT.md` |
| Internal/external communication | CC2.2, CC2.3 | A.5.1, A.6.8 | A.8.x | Art.50 AI disclosure; public docs; disclosure channel | Partial | `maverick/compliance.py`; `SECURITY.md`; `docs/` |

## 2. Risk management

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Risk assessment process | CC3.1–3.4 | Cl.6.1, 8.2; A.5.x | Cl.6.1; A.5.2 | Operator's risk methodology and register; structured assessment engine | Process + Implemented | `maverick/assessment.py` |
| AI risk & impact assessment | — | — | A.5.2, A.5.3, A.5.4, A.5.5 | EU AI Act classifier; AIRA persona | Implemented | `maverick/ai_act.py`; `maverick/tools/ai_act_classifier.py`; `maverick/domains/itgrc_aira.toml` |
| Risk → control mapping | CC3.2 | Cl.6.1.3 | A.5.4 | Control-lookup tool maps risks to frameworks | Implemented | `maverick/tools/control_tools.py` (`find_controls_tool`) |
| Tool/action risk classification | CC3.1 | A.8.x | A.6.2, A.9.x | Tool risk model; capability `max_risk` ceilings | Implemented | `maverick/safety/tool_risk.py`; `maverick/capability.py` |
| Change-in-risk evaluation | CC3.4 | A.8.32 | A.6.2 | Eval-gated CI; chaos testing | Partial | `.github/workflows/`; `maverick/chaos.py` |

## 3. Identity & access control

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Authentication | CC6.1 | A.5.16, A.5.17, A.8.5 | A.4.x | OIDC ID-token verifier (asymmetric-only, alg-confusion hardened); SAML SSO; reverse-proxy auth | Implemented (opt-in) | `maverick/oidc.py`; dashboard `auth.py`, `oidc_login.py`, `saml.py`; `maverick/proxy_auth.py` |
| Authorization / least privilege | CC6.1, CC6.3 | A.5.15, A.5.18, A.8.2, A.8.3 | A.4.x | Signed attenuating capabilities (tool/path/host scope, max_risk, expiry); least-privilege on spawn | Implemented (opt-in) | `maverick/capability.py` |
| Role-based access / SoD | CC6.1–6.3 | A.5.15, A.5.18 | A.3.2 | Dashboard RBAC (admin/operator/auditor/viewer; auditor read-only = SoD) | Implemented | `packages/maverick-dashboard/maverick_dashboard/rbac.py` |
| Per-user/channel authorization | CC6.2 | A.5.15, A.8.3 | A.9.x | Tool ACLs; consent/HITL gating | Implemented | `maverick/safety/tool_acl.py`, `consent.py` |
| Secure MCP/3rd-party auth | CC6.1 | A.5.17 | A.10.2 | OAuth for MCP integrations | Implemented | `maverick/mcp_oauth.py` |

## 4. Cryptography & data protection in transit/at rest

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Encryption at rest | CC6.7, C1.1 | A.8.24 | A.7.x | AES-256-GCM on world DB + memory stores | Implemented (on by default) | `maverick/crypto_at_rest.py` |
| Key management / KMS | CC6.1 | A.8.24 | — | Per-tenant envelope encryption (DEK+KEK); AWS/GCP/Vault wrapper | Implemented | `maverick/tenant/kms.py` |
| Tamper-evidence (integrity) | CC2.1, PI1.5 | A.8.24, A.5.33 | A.6.2, A.8.x | Ed25519 Merkle hash-chain + cross-file anchors | Implemented (on by default) | `maverick/audit/signing.py` |
| Confidentiality of stored records | C1.1 | A.5.33, A.8.24 | A.7.x | AES-256-GCM sealing of closed audit days | Implemented (opt-in) | `maverick/audit/sealing.py` |
| Secret protection / leakage prevention | CC6.7 | A.8.12 | A.7.x | Secret scrubber; detect-secrets CI gate | Implemented | `maverick/secrets.py`; `.secrets.baseline` |

## 5. Data governance, privacy & retention

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| PII protection / privacy | P1–P8, C1.1 | A.5.34 | A.7.4, A.7.5 | PII/secret detectors; anonymous mode | Implemented | `maverick/safety/pii_detector.py`, `secret_detector.py`; `maverick/privacy.py` |
| Subject access / portability | P5 | A.5.34 | A.7.x | DSAR export (GDPR Art.15/20) | Implemented | `maverick/dsar.py` |
| Deletion / erasure | C1.2, P4 | A.8.10 | A.7.x | GDPR erase + re-sign chain; erasure verifier | Implemented | `maverick/audit/erase.py`; `maverick/erasure_verify.py` |
| Retention & disposal | P4 | A.5.33, A.8.10 | A.7.x | TTL retention policy; retention check tool | Implemented | `maverick/audit/retention.py`; `maverick/tools/retention_check.py` |
| Multi-tenant confidentiality | C1.1 | A.8.3 | A.7.x | Per-tenant data dirs; per-user owner scoping | Implemented (opt-in) | `maverick/paths.py`; `maverick/world_model.py` |
| Data quality & provenance (AI) | PI1.2 | — | A.7.2, A.7.3, A.7.6 | Fleet memory provenance tagging (`vendor:agent_id`), scope-gated, audited | Implemented | `maverick/fleet_memory.py` |

## 6. System operations, logging & monitoring

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Audit logging | CC2.1, PI1.5 | A.8.15 | A.6.2, A.9.x | Append-only NDJSON audit log; signed, chained, WORM | Implemented | `maverick/audit/` |
| Monitoring / anomaly detection | CC4.1, CC7.2 | A.8.16 | A.9.x | OpenTelemetry; health checks; circuit breakers; `capability_denied` events | Implemented | `maverick/observability.py`; `maverick/circuit_breaker.py` |
| Security event evaluation | CC7.3 | A.5.25, A.8.15 | A.10.x | Audit-chain verification; shield/consent events | Implemented | `maverick/audit/signing.py` (`verify_chain`/`verify_anchors`) |
| Capacity management | A1.1 | A.8.6 | — | Budget caps; usage quotas; concurrency limits | Implemented | `maverick/budget.py`, `quotas.py`, `net_concurrency.py` |
| Backup, recovery & resilience | A1.2, A1.3 | A.8.13, A.8.14 | — | Durable checkpoint/resume; job queue; chaos testing | Implemented | `maverick/checkpoint.py`, `job_queue.py`, `chaos.py` |

## 7. Threat protection & secure development

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Boundary protection / threat detection | CC6.6 | A.8.16, A.8.23 | A.9.x | Agent Shield (prompt-injection/exfil/jailbreak); host-scope capabilities; SSRF guards | Implemented | `packages/maverick-shield/`; `maverick/capability.py` |
| Secure development lifecycle | CC8.1 | A.8.25–A.8.30 | A.6.2 | Secure coding rules; verifier; threat model | Partial / Process | `maverick/verifier.py`; `docs/security/threat-model.md` |
| Separation of environments / isolation | CC5.2 | A.8.31 | A.6.2 | 8 sandbox backends; enterprise deny-local; docker hardening | Implemented | `maverick/sandbox/` |
| Vulnerability management | CC7.1 | A.8.8 | — | Dependabot; detect-secrets; ruff/vulture CI gates | Partial / Process | `.github/dependabot.yml`; `.github/workflows/ci.yml` |
| Supply-chain integrity | CC9.2 | A.5.21, A.8.30 | A.10.2 | MCP command hash-pinning; plugin allowlist + hash-pin | Implemented | `maverick/plugin_manifest.py`; `maverick/mcp_oauth.py` |

## 8. Change & configuration management

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Change authorization & testing | CC8.1 | A.8.32 | A.6.2 | Eval-gated CI; PR review; conventional-commits gate; custom CI gates | Partial | `.github/workflows/` (`ci.yml`, `conventional-commits.yml`) |
| Config change/vuln detection | CC7.1 | A.8.9, A.8.8 | — | Preflight checks; eval-gated CI | Partial | `maverick/preflight.py` |
| Change-management *process* | CC8.1 | A.8.32 | A.6.2 | Documented approvals, prod sign-off, SoD | Process | Operator's change-management policy |

## 9. Incident management & resilience

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Incident containment | CC7.4 | A.5.26 | A.10.x | Killswitch (file + in-process, cluster-wide); circuit breakers | Implemented | `maverick/killswitch.py`; `maverick/circuit_breaker.py` |
| Evidence collection / forensics | CC7.3 | A.5.28 | A.10.x | Tamper-evident audit log; chain verification | Implemented | `maverick/audit/` |
| Incident recovery | CC7.5 | A.5.29 | — | Durable checkpoint/resume; job queue | Implemented | `maverick/checkpoint.py` |
| Incident-response *program* | CC7.4 | A.5.24–A.5.27, A.6.8 | A.10.x | Runbooks, on-call, escalation, notification SLAs | Process | Operator's incident-response policy |
| Vulnerability disclosure | CC7.4 | A.5.5, A.6.8 | — | 90-day coordinated disclosure; reward tiers | Implemented (Process) | `SECURITY.md` |

## 10. Supplier & people controls (predominantly Process)

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Supplier/sub-processor management | CC9.2 | A.5.19–A.5.23 | A.10.2, A.10.3 | Vendor reviews, DPAs, sub-processor inventory | Process | Operator's supplier-security policy |
| HR security (screening, training, NDAs) | CC1.4 | A.6.1–A.6.6 | A.3.2, A.4.6 | Background checks, training, offboarding | Process | Operator's HR security policy |
| Physical & environmental security | CC6.4, A1.2 | A.7.1–A.7.14 | — | Inherited from cloud provider (document via their SOC 2/ISO) | Process | Cloud provider attestations |

## 11. AI-specific governance (ISO 42001 / EU AI Act)

| Theme | SOC 2 | ISO 27001 | ISO 42001 | Lightwork control | Status | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| Human oversight | PI1.3 | — | A.9.2 | Governance engine ALLOW/DENY/REQUIRE_HUMAN; consent gates; configurable two-person approval | Implemented | `maverick/governance.py`; `maverick/safety/consent.py`; `maverick/safety/dual_control.py` |
| Transparency to affected parties | CC2.3 | — | A.8.2, A.8.3 | Art.50 first-turn AI disclosure; right-to-explanation | Implemented | `maverick/compliance.py`; `maverick/tools/right_to_explanation.py` |
| AI system lifecycle | — | — | A.6.2 | Governed learning loop: dreaming, hindsight (snapshot-replay regression), calibration gating, atomic rollback | Implemented | `maverick/dreaming.py`, `hindsight.py`, `calibration.py` |
| Learning audit / provable change | CC2.1 | A.8.15 | A.6.2 | Ed25519 signed, cross-language-verifiable learning audit | Implemented | `maverick/audit/signing.py` |
| Model selection & management | — | — | A.6.2 | Role-based model selection (never hard-coded) | Implemented | `maverick/llm.py`; `maverick/config.py` (`get_role_model`) |
| Bias / fairness evaluation | — | — | A.6.2, A.5.x | On-demand group-fairness metrics (four-fifths, demographic parity); red-team corpus | Implemented | `maverick/tools/bias_eval.py`; `packages/maverick-shield/` (`redteam`) |
| Continuous fairness monitoring | — | — | A.6.2.6 | Rolling-window monitor: four-fifths breach + drift detection, signed `FAIRNESS_ALERT` audit row | Implemented | `maverick/fairness_monitor.py`; `maverick/audit/events.py` (`FAIRNESS_ALERT`) |
| Model card documentation | — | — | A.6.2, A.8.x | Per-model documentation of intended use, limitations, oversight and evaluation results | Process | Operator's model documentation |
| AI system retirement / decommissioning | — | — | A.6.2 | Decommissioning decision, data disposition and record of who decided | Process | Operator's decommissioning procedure; data disposition uses the erasure controls in the Deletion / erasure row (`maverick/audit/erase.py`) |

---

## Cross-framework gap summary

What a deploying organization has to supply or switch on:

**Process controls the deploying organization operates (shared across SOC 2 / ISO 27001 / ISO 42001):**
change-management process · vendor/sub-processor management · incident-response
program · HR security · documented risk-assessment program · vulnerability
management & pen-test cadence · physical security (cloud-inherited).

**Opt-in controls to enable:** capabilities, tenant isolation, quotas and OIDC
(encryption at rest and audit signing are on by default unless disabled) — for
any compliant deployment. See [`soc2/README.md`](soc2/README.md).

**ISO 42001 controls the deploying organization operates:** model-card
documentation and AI-system decommissioning are process controls. Continuous
rolling-window fairness monitoring with four-fifths/drift alerts is implemented
(`maverick/fairness_monitor.py`).
