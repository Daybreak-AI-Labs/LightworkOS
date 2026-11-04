# Model Risk & AI Assurance Officer

Lightwork's integrated Model Risk & AI Assurance Officer governs declared AI
assets across their lifecycle. It inventories models, agents, tools, datasets,
and providers; records human-owned declarations and evidence; produces
deterministic findings; tracks incidents, risk acceptances, promotion
authorizations, and deployment lineage; and exports signed assurance packs.

The officer is assurance infrastructure, not a regulator, auditor, certifier,
or automated legal decision-maker. NIST AI RMF 1.0, ISO/IEC 42001:2023, and
Regulation (EU) 2024/1689 references are versioned advisory metadata. EU AI Act
role, scope, and applicability remain undetermined until a named human records
an assertion with a timestamp, rationale, and basis version.

## Enable the integrated officer

The evidence graph is a required dependency. The installer wizard writes these
settings when the officer is selected:

```toml
[governed_records]
backend = "auto"       # auto | local | postgres

[evidence_graph]
enable = true

[model_risk_assurance]
enable = true
gate_promotions = true
```

`backend = "auto"` keeps the single-replica compatibility posture local and
selects the configured Postgres authority when required. Enterprise or
multi-replica deployments fail closed unless a shared Postgres governed-record
backend, an explicit tenant context, application encryption, and an externally
injected fleet key plus its pinned SHA-256 digest are available. Shared
governed-record ciphertext always uses that deployment key, even when ordinary
tenant data uses per-tenant envelope encryption; it never falls back to a
node-local tenant DEK. Explicit Postgres selection has the same key-identity
requirement even for a declared single replica, and node-local keyring rotation
is refused.

The current encryption boundary protects disclosure from storage snapshots;
database-integrity controls and RLS remain responsible for preventing an
administrator from transplanting an intact ciphertext row between tenant or
namespace coordinates. Bind those coordinates as AEAD associated data before
treating a hostile database administrator as in scope.

Inventory, declaration, evidence, incident, and deployment reads each enforce a
5,000-record namespace limit. Reaching the limit returns an explicit operational
error instead of issuing an unbounded Postgres response or silently truncating
an assurance decision.

The officer is available at `/security/assurance`. Its authenticated REST
surface is under `/api/v1/security/assurance/model-risk/` and covers inventory,
declarations, evidence and reviews, findings and risk acceptance, incidents,
promotion authorizations, deployments, and assurance-pack export.

## DGM promotion gate

Setting both `enable = true` and `gate_promotions = true` adds the officer's
verification to the self-improvement promotion gates. The gate recomputes the
candidate identity and payload binding, then requires a current, exact
promotion authorization backed by current approved evidence. Missing,
unreadable, revoked, expired, stale, or mismatched authority denies the
promotion. The officer does not create a promotion authorization by itself.
For durable artifact changes, the exact binding is journaled at PREPARE and
re-read under the artifact lock immediately before apply, again before COMMIT,
and during crash recovery; lost authority cannot be converted into a governed
promotion receipt.

Leaving either switch off preserves compatibility and does not enable the DGM
gate. Once enabled, malformed or unreadable deployment-global policy is treated
as denial at the enforcement boundary.

## Evidence and decision boundaries

- Observations, declarations, evidence, incidents, decisions, and deployments
  are revision-CAS governed records with tenant scope and a durable audit
  outbox.
- Collected evidence does not satisfy assurance by itself. A current human
  review must approve the exact evidence authority projected into the evidence
  graph.
- A risk acceptance is time-bounded human authority; it does not erase or
  close the underlying finding.
- Assurance packs bind the current records and citations and are signed with
  the platform audit key. Verification requires an external trusted-key
  registry rather than trusting a key disclosed by the pack itself.

### Specialist-model training evidence

A weights-rung promotion has a stricter evidence floor than a prompt, policy,
or code change. It requires current, human-approved, passing evidence of all
four kinds:

- `training_run` — a verified tenant-private training receipt;
- `data_assessment` — scoped to the receipt's exact training-dataset digest;
- `evaluation` — bound to the approved artifact and evaluator;
- `red_team` — bound to the same approved artifact and evaluator.

Generic evidence writes cannot self-assert `training_run`. An authenticated
operator registers a receipt through
`POST /api/v1/security/assurance/model-risk/evidence/training-receipts`.
Lightwork resolves the receipt only from the active tenant's private append-only
store, verifies every chain row through the selected receipt, resolves the
separate platform and human signatures only through protected server-side
audit and global approver registries, checks that it covers the observed
artifact bytes, and persists only its content-free public commitment. Request
bodies cannot nominate trust keys. The
receipt still needs a separate Model Risk evidence review; registering it is
not approval.

The weights promotion gate revalidates the receipt commitment, dataset scope,
evaluator identity, evidence-graph authority, expiry, revocation, and promotion
authorization at use time. The adapter promotion pointer separately binds the
exact receipt identities and qualification decision into the externally signed
activation authority. Neither path silently selects or reroutes a runtime
model.

The activation pointer stores only the approver fingerprint, re-resolves it
through deployment policy at use time, and stops routing after revocation. The
row chain detects mutation, deletion before a later row, insertion, and
detached-row substitution. Detecting rollback of a valid signed tail requires
publishing or otherwise externally anchoring the latest public commitment.

## Standalone product

`demo/model-risk-ai-assurance-officer/` is a self-contained, loopback-only
standalone application. Run it with:

```bash
cd demo/model-risk-ai-assurance-officer
python -m pip install -r requirements.txt
bash run_standalone.sh
```

The standalone product provides local declared inventory, deterministic
findings, human reviews and risk acceptances, and a non-executing DGM readiness
report. Its JSON store is unsigned and local. It has no discovery, provider,
promotion, deployment, rollback, ticketing, filing, or other external-effect
route, and it does not claim the integrated platform's tenant authority,
evidence graph, governed approvals, or signed audit.
