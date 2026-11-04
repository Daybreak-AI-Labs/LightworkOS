# Research lab source execution

The Research lab provides an authenticated, tenant-scoped queue for bounded
Python source experiments. A researcher submits source without executing it. A
named installation administrator opens the exact source, reviews it, and starts
one container attempt. A controller-owned exact-output evaluator records the
result outside the candidate process.

This is a local source integration. Passing its unit, ASGI, or browser tests does
not establish real Docker containment, production qualification, scientific
improvement, deployment acceptance, or benchmark validity.

## In-app workflow and installation setup

The **Research lab** page is `/research`. It is not a navigation entry:
`ui_visibility.py` registers it with `ready: False`, so it keeps its route and
permission gate but is not offered in the sidebar, the page finder or the
Settings visibility matrix. People reach it from links on other pages: the
release-decision links in Workflow pilots, the release-review links in flow
comparisons and flow requalification, the Research lab step of the
installation setup guide, the workflow-release links on the request-program
and teach-a-flow pages, the dataset-version link on knowledge sources, and the
product-operations Copilot actions that open it. On the page, researchers can:

- select up to 64 UTF-8 source files totaling at most 256 KiB;
- choose a supplied Python entrypoint and an installation-owned evaluator;
- explicitly confirm submission; and
- inspect their durable status, evaluation outcome, next action, and cancellation
  controls even while execution is disabled.

Installation administrators additionally see the cross-user review queue. The
queue summary does not carry dispatch authority. Opening one job returns its
exact source and a fresh review SHA-256 bound to the source, job revision,
workspace, submitter authority, administrator authority, profile, evaluator,
entrypoint, and expiry. **Run reviewed source** stays disabled until that exact
review is open, execution is currently available, the caller can dispatch, and
the administrator checks the confirmation box. The server repeats every check.

Administrators can enable, repair, or disable the global profile on the same
page. Saving uses a compare-and-swap settings digest so a stale browser cannot
overwrite a newer profile. Disabling accepts a minimal recovery request even if
the old image or evaluator fields are malformed. Existing jobs and cancellation
remain available when the profile or settings store is unavailable.

The advanced installer also has a **Research lab** step. It is off by default.
When enabled, the installer records one immutable image, one deterministic
evaluator, and the queue lifetime. More evaluators and bounded resource limits
can be managed in the app.

## Operator configuration

Only global installation sources can define `[research_execution]`; tenant
overlays cannot enable execution or replace the oracle. The base config,
dashboard-owned config, and optional operator overlay are considered in that
precedence order. An explicit table in a higher-precedence global source
replaces the entire lower-precedence research table. This replacement behavior
means removing an evaluator in the app actually removes it instead of merging a
stale definition back from the base config. If the optional operator overlay
owns the table, the app shows a redacted safe projection but keeps setup
read-only; the dashboard overlay cannot override that higher-precedence source.

| Setting | Accepted value |
| --- | --- |
| `enable` | Exactly `true` to admit new submissions and dispatch; false disables it |
| `image_id` | `sha256:` followed by 64 lowercase hexadecimal characters |
| `queue_seconds` | Integer 30–86400; default 3600 |
| `evaluators.<id>.version` | Operator-controlled version identifier |
| `evaluators.<id>.stdout_sha256` | SHA-256 of the exact expected UTF-8 stdout |
| `limits` | The bounded `ResearchLimits` fields below |

Between one and 32 evaluators are required while enabled. IDs and versions are
1–64 ASCII letters, digits, underscores, or hyphens and begin with a letter or
digit. Unknown settings and executable evaluator commands are refused. Changing
any profile field invalidates an earlier review instead of silently changing its
oracle.

Defaults are 10 seconds of candidate wall time, 64 KiB of combined captured
output, 128 MiB memory, 16 MiB each for scratch and shared memory, 32 processes,
and 0.5 CPU. Overrides remain inside fixed bounds. A fresh `Budget` covers Docker
readiness, image inspection, candidate execution, and cleanup; it permits one
tool call and no model tokens or provider spend. Deployment and tenant budget
authority are also bound to submission and rechecked before effects.

The administrator must provision and review a locally present Linux image and
enter its immutable ID. The controller does not start Docker, pull an image, or
fall back to host execution.

## Authenticated API and durable queue

All JSON routes are under `/api/v1/research`. Callers need a named signed-in
`user:` identity, an explicitly selected active workspace, and current tenant
membership with `operate` or `admin`. Global administrator status does not
replace tenant membership. SCIM status, session revocation, permission
definitions, workspace-selection generation, and tenant budget authority are
re-read by the requestless controller.

`GET /api/v1/research` returns the caller's jobs, execution readiness, evaluator
IDs and versions, and current context. An administrator also receives the
cross-user review queue and a settings projection. Expected-output hashes are
visible only in that administrator settings projection or an exact-source review;
ordinary researcher responses never expose them.

`POST /jobs` requires `context`, `confirm: true`, an `idempotency_key`, an
`evaluator_id`, source files, and an optional `entrypoint` (default `main.py`).
Mutations require same-origin and expected-workspace checks. The entrypoint must
be a supplied Python file. Traversal, aliases, device names, host paths, image or
environment overrides, tenant/principal claims, and evaluator definitions are
refused. Invalid-input errors do not echo source.

Submission creates a governed record and never runs candidate code. Repeating
the same principal/idempotency key and exact request returns the prior job;
changing the request is a conflict. Each workspace retains at most 256 jobs.
Automatic deletion and retention release are not implemented.

`GET /review/{id}` is administrator-only and returns exact source plus the fresh
dispatch review digest. `POST /jobs/{id}/run` requires that digest, current job
revision, context, confirmation, and separately resolved installation-admin
authority. `POST /jobs/{id}/cancel` lets the owner cancel their own job or an
administrator cancel a job visible in the tenant review queue.

| State | Meaning and recovery |
| --- | --- |
| `queued` | Durable submission; no candidate execution has occurred |
| `running` | Atomic claim committed before runner setup or candidate effects; never automatically replayed |
| `cancel_requested` | Running cancellation requested; bounded execution and cleanup finish, evaluation is suppressed |
| `cancelled` | Queued execution was prevented or a completed run was discarded |
| `review_required` | Authority, source, expiry, image, evaluator, or profile changed; submit and review a new job |
| `completed` | Cleanup and provenance passed; the controller recorded an exact-output pass or failure |
| `uncertain` | Runner or controller outcome is uncertain; inspect cleanup and never replay this job |

Every claimed attempt receives an append-only public execution history. It
records claim, start, and safe terminal provenance such as image, source and
policy digests, entrypoint, exit status, byte counts, and cleanup result. Raw
stdout, stderr, source, credentials, and evaluator expectations are excluded.
Authority drift after the container returns still preserves the finished attempt
record before moving the job to `review_required`.

An abruptly lost process can leave a job `running`. A new controller instance
can read the durable state but cannot reclaim or repeat it. An administrator must
inspect containers named `lightwork-research-*` and the tenant's retained
`research-snapshots` before authorizing new work. Cancellation is cooperative
and bounded; it is not an immediate process kill.

## Candidate and evaluator boundary

Source stays inside its tenant's governed-record namespace. On dispatch, only the
submitted bytes are materialized under that tenant's private
`research-snapshots` directory. The unique candidate directory is mounted
read-only and removed only after verified container cleanup. Tenant credential
directories, controller configuration, evaluator expectations, production
files, the Docker socket, host environment, and oracle code are not mounted.

The Linux primitive uses UID/GID 65532, a read-only root, network none, dropped
capabilities, no-new-privileges, private bounded scratch and shared memory, and
finite process, CPU, memory, output, and wall-time limits. It inspects the actual
created container before start. The Docker daemon, host, and operator-provisioned
image remain trusted.

The oracle executes in the controller after candidate exit and verified cleanup.
A pass requires zero exit status, completed execution, valid UTF-8 stdout, and
an exact match to the operator's expected stdout digest. Candidate-provided
`passed` JSON, JUnit, pytest prose, and evaluator files have no authority. A
digest mismatch is a completed experiment with one failed check.

Authenticated evidence binds a fresh request nonce to the candidate, job,
submitter authority, dispatcher authority, image, complete inspected policy,
entrypoint, and evaluator version/digest. This evidence passes through the
governed record and audit boundary; it is not an external attestation signature.

## Persistence and remaining limits

The queue uses the repository's configured governed-record backend. It can use
the admitted local single-replica backend or the shared Postgres backend and
inherits that layer's tenant binding, encryption, authoritative-time, and
compare-and-swap rules. No real shared-Postgres end-to-end experiment has been
run, and shared-worker execution is not qualified.

Dispatch currently runs through the dashboard service's bounded worker thread;
there is no separately deployed least-privilege research worker. The UI accepts
browser-selected UTF-8 files rather than cloning a repository, installing
dependencies, mounting datasets, or providing candidate secrets. The built-in
oracle supports deterministic exact-output checks, not hidden research datasets,
performance measurement, arbitrary trusted test suites, or scientific claim
validation.

Real opt-in Linux-container tests are still required on every intended runtime.
Automated orphan reconciliation, job retention management, a dedicated worker,
shared Postgres integration acceptance, external datasets, dependency packaging,
and richer independently governed evaluators remain unfinished. None of those
claims should be inferred from source-only or doubled-runner tests.
