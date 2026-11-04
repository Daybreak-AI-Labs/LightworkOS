# Operator first run

This is the shortest path from an installed Lightwork build to a working
runtime and an evidence-visible operator cockpit. It separates deterministic
configuration checks from live connectivity checks so a deployment script can
fail for the right reason.

## 1. Initialize once, retry safely

Interactive:

```bash
maverick init
```

Recommended defaults, without prompts:

```bash
maverick init --fast
```

Reviewed headless configuration:

```bash
maverick init --from-file ./config.toml
```

All three paths are safe to retry. When generated config and secret files are
byte-for-byte equivalent (ignoring platform line endings), the installer
verifies their private custody and leaves their inode, modification time, and
watcher state unchanged. A changed file is still backed up before replacement.

Advanced local setup provisions and checks the selected workspace before
reporting success. Generated files are published through private temporary
files and atomic replacements; an ordinary publication failure restores the
previous secret file. The config and secret file are separate replacements,
not a crash-atomic two-file transaction. Retain the backups and inspect both
files after an interrupted setup.

New setup does not generate a per-task dollar or step limit. Review preserved
settings on upgrades and choose any explicit task cap separately from the
organization allowance; see [task limits](task-limits.md).

`init`, `preflight`, `doctor`, `version`, and `config-lint` do not resolve or
open the world database. They therefore remain usable when a malformed client
binding or config file is the problem you need to repair.

## 2. Run the offline deployment gate

For a normal agent run:

```bash
maverick preflight
```

For the dashboard, AI Evidence-Ready Gateway, evidence graph, and Model Risk &
AI Assurance Officer:

```bash
maverick preflight --profile cockpit
```

The cockpit profile also requires an explicit company boundary. Set
`MAVERICK_TENANT` for a selected tenant, or configure `[client] id` for a
single-company deployment. The gateway never falls back to unscoped evidence
storage.

For CI, an installer, or an infrastructure pipeline:

```bash
maverick preflight --profile cockpit --json
```

The command has stable check ordering and no generated timestamp. It makes no
network request and creates no runtime state. It exits non-zero when the
selected profile has a blocker. Each blocker carries one copyable remediation.
The JSON schema is `lightwork.operator-preflight.v1`.

Offline preflight verifies configuration, routed provider dependencies, local
storage permissions, package presence, and the selected feature dependency
chain. It cannot prove that a provider API, Postgres server, proxy, or container
daemon is reachable.

The cockpit profile also performs a secret-free, read-only gateway custody and
integrity check. It does not create keys, directories, lock files, indexes, or
ledger state. A fresh writable parent is first-use attention; an unwritable
parent is a blocker. If receipt or packet ledgers already exist, their signed
state, physical rows, read-only index, and public trust registry must verify.
Preflight reports corruption rather than repairing it.

## 3. Verify live dependencies

```bash
maverick doctor
```

`doctor` performs the live and environment-sensitive checks. Fix red rows and
re-run it. Yellow rows need operator judgment but do not necessarily block a
normal run.

After starting the dashboard, deployment probes have distinct meanings:

- `GET /livez` — the process accepts traffic.
- `GET /healthz` — database, provider configuration, and runner health.
- `GET /readyz` — health plus deeper client-binding, Shield, agent-trust, and
  replica-safety posture.

Do not use liveness as a readiness gate.

## 4. Reach first value

```bash
maverick dashboard
```

Open `http://127.0.0.1:8765/start`. The checklist reflects actual workspace
state:

1. a provider credential or self-hosted endpoint is configured;
2. a reusable workflow or governed agent exists;
3. a goal has run or an automation is armed.

The page exposes separate **runtime** and **assurance deployment** preflight
results. Completing the three workspace steps is reported as runtime-ready
only when the normal `run` profile is ready. Runtime readiness never implies
that the stricter cockpit/assurance profile is ready, and an assurance blocker
does not contradict an otherwise runnable workspace.
Run a first task from the UI or:

```bash
maverick start "Summarize the deployment controls and list unresolved gaps."
```

## 5. Make AI evidence visible

Open `http://127.0.0.1:8765/security/assurance`.

The cockpit prioritizes one next action and tracks four production-evidence
milestones:

1. production policy bound to model and context digests;
2. first governed delivery receipt recorded;
3. receipt signatures and both receipt chains verified;
4. regulatory impact queue current.

Integrity failures outrank queue work. Synthetic demo records never count
toward those four production milestones.

To inspect the API contract, use `/docs`. The normal production sequence is:

```text
PUT  /api/v1/security/assurance/gateway/policies/{policy_id}
POST /api/v1/security/assurance/gateway/deliver
GET  /api/v1/security/assurance/gateway/summary
GET  /api/v1/security/assurance/gateway/regulatory-impacts?pending_first=true
GET  /api/v1/security/assurance/gateway/regulatory-impacts/{impact_id}
POST /api/v1/security/assurance/gateway/assurance-packet  (Idempotency-Key required)
```

The cockpit stores and displays hash-only interaction receipts; it does not
render raw prompts or generated content.

Impact list responses are cursor-paginated and action-needed first, so pending
reviews remain reachable beyond the first 500 records. Retrying packet issuance
with the same tenant, actor, profile, and `Idempotency-Key` returns the exact
original bytes and does not append a second attestation.

### Synthetic demo safety

The no-network demo is available only when the tenant is empty or already
contains the same deterministic demo scenario. Use an empty or dedicated demo
tenant. Every demo record is labeled synthetic, the cockpit reports “Synthetic
demo only,” and no production assurance conclusion is shown.

## 6. When something still fails

Create a locally inspectable, secret-redacted support bundle:

```bash
maverick support
```

Review the JSON before sharing it. Provider credentials are never included.
The offline preflight likewise reports only presence and dependency state, not
credential values.

The cockpit and packet are evidence surfaces, not legal certification. A
qualified human remains responsible for regulatory classification, impact
disposition, and reliance on exported evidence.
