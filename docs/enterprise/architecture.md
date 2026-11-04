# Governed agent control plane

This page describes how Lightwork governs fleets of agents: the oversight
control plane every consequential action passes through, the compliance
profiles that tighten it, the fleet model, and the tenancy and scaling
substrate underneath. Module paths are relative to
`packages/maverick-core/maverick/` unless noted.

## 1. Why a single control plane

Organizations that run many agents need two things before they can deploy
them:

1. **Oversight.** A way to see, govern, and intervene in what the agents do.
2. **Evidence of compliance.** Records showing that the agents operate within
   the obligations that apply to the deployment, such as the EU AI Act, the
   NIST AI RMF, US state laws, and sectoral rules like HIPAA, GLBA and FCRA.

Implementing logging, access control and human oversight separately for each
framework produces redundant controls and gaps where they meet. Lightwork
routes every agent action through **one control plane** and expresses each
regime as a **profile** that compiles onto the same set of enforceable
primitives.

## 2. Overview

```
  Owner (a human principal)
    └─ Fleet (named, role-scoped agents: researcher, coder, ops, analyst…)
         every action ─▶ ┌──────────────────────────────────────────────┐
                         │        OVERSIGHT CONTROL PLANE                │
                         │  policy engine: allow / deny / require-human  │
                         │  + operator console (/oversight)              │
                         │  + signed record of every decision (Art 12)   │
                         └──────────────────────────────────────────────┘
                                        ▲ policy = strictest-wins union of
                         ┌──────────────┴───────────────┐
                    Compliance profiles and finance regime packs:
                    HIPAA · GDPR · EU AI Act · NIST AI RMF ·
                    ISO/IEC 42001 · SOC 2 · SR 11-7
```

## 3. Three layers

### Layer A — Oversight control plane

`governance.py` is the policy decision point. Each consequential action is
evaluated against the principal's capability and the organization's policy and
yields one decision: **`allow`**, **`deny`**, or **`require_human`** (pause for
human sign-off, the EU AI Act Art 14 gate). Decisions are strictest-wins
(`deny` > `require_human` > `allow`) and carry a machine-readable rule and a
human-readable reason, so the choice lands in the signed audit record.

With no `[governance]` policy configured, the engine allows whatever the
capability already permits, so a deployment that does not use it behaves as
before. Policies are set directly in `[governance]` (`deny_actions`,
`require_human_actions`, risk floors and per-action amount thresholds) or come
from the compliance profiles in Layer B.

The control plane builds on attenuating capabilities (`capability.py`),
consent and human-in-the-loop approval (`safety/consent.py`), and the signed
audit chain (`audit/signing.py`). The dashboard's **`/oversight`** page is the
operator console: org-policy denials and human-approval holds, shield blocks,
capability denials, egress-lock and consent denials, and killswitch halts in
one view, next to the live halt state and the pending approval queue.

### Layer B — Compliance profiles

Controls are not implemented per law. Each regime is a **profile** an operator
turns on per deployment (`[compliance] profiles` or
`MAVERICK_COMPLIANCE_PROFILES`); `compliance_profiles.py` compiles each one to
a governance policy and names the protection floors it requires (PII
redaction, encryption at rest, egress lock, audit log). Selecting several
profiles unions them strictest-wins, together with any finance regime packs
(`[finance] regimes`, `finance/regimes.py`).

The shipped profiles are `hipaa`, `gdpr`, `eu_ai_act`, `nist_ai_rmf`,
`iso_42001`, `soc2` and `sr_11_7`. HIPAA is a PHI-handling posture; GDPR and
the EU AI Act supply legal-runtime overlays. The NIST AI RMF, ISO/IEC 42001,
SOC 2 and SR 11-7 profiles are bounded compatibility postures: they enforce
only the tool-gate controls they name and do not assert full framework
coverage, certification or attestation.

Because regimes are configuration, a deployment enables exactly the profiles
its jurisdiction and sector require.

### Layer C — Agent fleets

`fleet.py` defines a **fleet**: an owner (a human principal) plus a roster of
named, role-scoped agents that do ongoing and scheduled work. Each agent's role
drives its capability through `[roles.<role>]` RBAC, and the whole fleet runs
under the Layer A control plane. Fleets are stored per tenant
(`~/.maverick/fleets/<name>.json` under the tenant's data directory), so one
tenant's roster never reaches another. `maverick fleet` manages them from the
command line; the dashboard's `/fleets` page shows them.

## 4. Compliance mapping

Each obligation below maps to a Lightwork control. The controls supply
technical evidence; they do not determine whether a deployment is compliant.

| Regime | Key obligation | Lightwork control |
|---|---|---|
| **EU AI Act Art 12** (record-keeping) | append-only logs, hash-chained, retention | Ed25519-signed, hash-chained audit (`audit/signing.py`), offline verification, and retention enforcement (`maverick retention enforce`) |
| **EU AI Act Art 14** (human oversight) | monitor / intervene / override; explicit automation boundary | consent/HITL, capability risk ceilings, the `require_human` governance gate, and the `/oversight` operator console |
| **EU AI Act Art 50** (transparency) | disclose AI; mark AI-generated content | first-turn AI disclosure on channels and an AI-written label on every agent answer sent to a chat app or by email (`compliance.py`) |
| **EU AI Act** conformity readiness | risk classification and technical documentation | a default-off conformity-readiness workflow (`ai_conformity_workflow.py`) that tracks evidence; it does not classify a system as a matter of law or perform a conformity assessment |
| **NIST AI RMF** | Govern / Map / Measure / Manage | audit, capabilities, budgets and quotas, the evaluation harness, and the bounded `nist_ai_rmf` profile |
| **NYC Local Law 144** and similar employment rules | consequential-decision logging, human review, bias audit | decision records in the audit chain, `require_human` gates, and a default-off audit/notice readiness package (`ai_regulated_verticals.py`); it does not perform an independent bias audit |
| **HIPAA / GLBA / FCRA** (sectoral) | restrict and log sensitive-data handling | capability path/host scopes, the egress lock, tenancy, and the `hipaa` profile's required protection floors |
| **GDPR** | data residency and erasure (Art 17) | egress lock to EU or local providers, DSAR erasure (`audit/erase.py`), tenancy, and the `gdpr` profile |

**Compliant is not certified.** "Compliant" here means "provides the technical
controls and evidence that compliance requires", not legal certification.
Mapping your obligations to your risk tier needs counsel; Lightwork supplies
the enforceable controls and the audit evidence, and makes the posture
auditable.

## 5. Primitives the control plane builds on

- **Signed, tamper-evident audit** (Ed25519-signed hash chain with offline
  verification): the evidentiary backbone for every regime above.
- **Attenuating capabilities**: least privilege that can only narrow as it
  propagates to sub-agents.
- **Consent / human-in-the-loop**: the Art 14 intervention substrate.
- **Execution sandboxes, egress lock, tenancy, quotas, OIDC/proxy SSO, RBAC
  and SIEM export**: the operational surface. The sandbox backends are local,
  Docker, Podman, gVisor, devcontainer, Kubernetes, SSH, Modal, and a
  Firecracker scaffold.
- **Roster-wide governance invariant suite**: six governance invariants
  (tool-reachability, autonomy dial, capability attenuation, compartment
  isolation, unstrippable hard refusals, budget caps) verified across all
  2,031 built-in specialist packs, each with a fault-injection control proving
  the test is non-vacuous, plus hostile-argument fuzzing of every connector
  and tool.
- **Primary-source data grounding**: analyst packs are granted their suite's
  subset of 37 read-only, GET-only public-data connectors (SEC EDGAR, FRED,
  Treasury, World Bank, FDIC, Census, BLS, EIA, openFDA, NPPES, CourtListener,
  Federal Register, GLEIF, OpenCorporates, NWS/NOAA, EPA, …), so consequential analysis
  is grounded in authoritative sources rather than model memory. On by default;
  kill-switch `[workforce] data_grounding = false` /
  `MAVERICK_WORKFORCE_DATA_GROUNDING=off`.
- **The recursive swarm**: the multi-agent substrate that fleets are built
  from.

## 6. Workspaces, tenancy and scaling

- **Workspaces.** `workspace.py` gives each business (tenant) its own home
  under `~/.maverick/tenants/<tenant>/`: its domain packs, its document
  knowledge store and its world database. Selecting a tenant is explicit
  (`MAVERICK_TENANT` or the dashboard's workspace selection); with no tenant,
  paths fall back to the single-tenant `~/.maverick/` layout.
- **Postgres world model.** `[world_model] backend = "postgres"` moves the world
  model to Postgres, tenant-stamped on every root table. `[world_model] rls =
  true` (or `MAVERICK_PG_RLS=1`) adds database-native row-level security keyed
  on the session's tenant; only the table owner can install the policy, and
  `maverick tenant rls-preflight` checks the setup.
- **Per-tenant keys.** `tenant/kms.py` gives each tenant its own data
  encryption key, stored only wrapped by a key-encryption key held in a KMS
  (a local KMS by default; cloud KMS backends implement the same interface).
- **Per-tenant egress.** `tenant/egress.py` applies a host allow/deny plane per
  tenant (`[tenancy.egress.<tenant>]`, falling back to `[egress]`) to every tool
  the tenant's agents run, composed with the per-tool network policy.
- **Out-of-process workers.** The `QueueDispatcher` sends goals to a job queue
  that separate `maverick worker` processes drain, so processing capacity
  scales independently of the dashboard.
- **One control-plane replica.** Postgres centralizes the world model, but other
  durable control-plane stores are still file-backed. Run one
  dashboard/control-plane replica and scale only the worker tier; see
  [Operations](../operations.md) and the
  [deployment playbook](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/enterprise/deployment-playbook.md)
  for the runtime lock and
  Helm guard that enforce this.

## 7. Caveats

- The controls above are technical. Legal classification, conformity
  assessment and certification remain the operator's responsibility.
- Regulatory timelines change. Because regimes are configuration, a deployment
  can enable or disable profiles as its obligations change; the strictest-wins
  union keeps multi-jurisdiction deployments safe by default.
