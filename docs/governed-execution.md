# Governed execution: session kernel, self-refinement, run forking

Three runtime planes let an agent do more than call fixed tools: write and run
its own code, propose changes to its own operating instructions, and branch a
run to try the other way. Each one is a capability an ungoverned runtime hands
out for free and an audited deployment cannot accept for free. Lightwork ships
them with the evidence attached — every statement receipted, every refinement
approved and reversible, every branch kept on the record beside the one that
shipped.

| Plane | Module | Config | Default | Where you see it |
| --- | --- | --- | --- | --- |
| Session kernel | `governed_repl.py` | `[repl]` | **off** | `repl_exec` agent tool; `maverick repl`; `repl_executed` audit rows |
| Self-refinement | `harness_refine.py` | `[harness_refine]` | **off** | Approval queue (`/approvals`); `maverick refine`; the standing brief; signed learning audit |
| Run forking | `session_tree.py` | `[session_tree]` | **on** | **Branches** page (`/run-tree`); `maverick run-tree` |

All three are asked in the installer wizard's advanced flow (**Governed
session kernel?**, **Governed self-refinement?**, **Run forking?**), and
everything below is editable later in `~/.maverick/config.toml` — see
[Configuration](configuration.md).

## The governed session kernel

A model that writes **code** against a live namespace converts more capability
per token than one composing tool schemas: a loop, a filter and a join are
three lines instead of thirty tool calls. The price is that the work stops
being legible — and arbitrary code is exactly what an audited deployment
cannot admit. The kernel pays that price rather than skipping it.

Every statement is:

- **hashed** — SHA-256 over the exact source; the digest is the statement's
  identity everywhere it is recorded;
- **screened** — `memory_guard.injection_markers` runs before anything
  executes, and a broken screen refuses just like a hit (a screen that cannot
  answer is not an answer of "clean");
- **receipted** — a PREPARE link on the tamper-evident lineage chain *before*
  the effect and a COMMIT link after, both written with `strict=True` so a
  tampered chain refuses rather than extends. No receipt, no execution;
- **audited** — one `repl_executed` row carrying the digest, the exit code and
  the wall time, never the code itself;
- **appended to the session ledger** — a per-session `ledger.jsonl` that
  survives the session's close.

The code IS the audited artifact.

### Enabling

```toml
# ~/.maverick/config.toml
[repl]
enable = true          # off by default -- this admits arbitrary code execution
max_seconds = 30.0     # per-statement wall ceiling
max_output_chars = 8000
max_state_bytes = 262144
max_statements = 200   # per session
```

`MAVERICK_REPL=1` also turns it on. A missing or malformed `[repl]` section
fails closed: the kernel reports itself disabled and every entry point
refuses.

!!! warning "The sandbox backend is the containment boundary"

    Statements run through `sandbox.exec()` like every other shell in
    Lightwork, so whatever `[sandbox] backend` is configured is what contains
    model-written Python. Run a container backend (`docker`, `gvisor`,
    `podman`); `local` runs that code on the host with your privileges.

    The kernel writes its driver, the statement and a result file into the
    sandbox workdir, so the backend must **share that workdir with the host**.
    `docker`/`gvisor`/`podman` bind-mount it; `ssh` and `kubernetes` do not and
    cannot host a session in v1.

### Using it

Three ways in, all through the same governed path.

**The agent.** When `[repl] enable` is on, the tool registry gains a
`repl_exec` tool and the agent can write Python instead of composing tool
schemas. One session is opened per goal and reused for the rest of the run,
so state built in one call is still bound in the next. The tool is registered
only when the knob is on — while it is off the tool does not appear in the
catalog at all, so it costs no prompt tokens and cannot be called. It is
classified `high` risk alongside `shell`, and it is never parallel-safe.

**The CLI**, for operators and for trying it by hand:

```console
$ maverick repl exec 'rows = [1, 2, 3]'
$ maverick repl exec 'print(sum(rows))' --session <id>
6
$ maverick repl transcript <id>     # the append-only statement ledger
$ maverick repl close <id>
```

**The module API**, for embedding:

```python
from maverick import governed_repl as repl

session = repl.open_session(goal_id=42, principal="ops@example.com")
repl.execute(session, "rows = [1, 2, 3]", goal_id=42)
result = repl.execute(session, "print(sum(rows))", goal_id=42)
# {'ok': True, 'stdout': '6\n', 'stderr': '', 'exit_code': 0,
#  'statement_sha256': '...', 'wall_seconds': 0.05,
#  'truncated': False, 'dropped': []}

repl.transcript(session)      # the append-only ledger, oldest first
repl.close_session(session)   # True only if this call closed it
```

`execute` never raises for ordinary user-code failure: a traceback comes back
on `stderr` with `ok=False` and `exit_code=1`, and the session stays alive.
`ReplError` is reserved for governance refusals — see
[Troubleshooting](#troubleshooting).

Output is secret-redacted host-side (`safety.secret_detector`) before it is
returned or stored, and capped at `max_output_chars` with `truncated` telling
you it happened. Closing a session removes the working state and statement
bodies but keeps the ledger: an audit artifact that disappears when the
session ends proves nothing.

### The persistence model: JSON namespace carry

Sandbox backends expose a one-shot `exec(cmd, timeout=)`. There is no
long-lived kernel process to attach to, and inventing one would put a host
process outside the sandbox chokepoint. So the namespace is carried
**explicitly**: a small stdlib-only driver loads the prior namespace from a
JSON state file, executes the new statement in it, and re-dumps the globals
that survive `json.dumps`.

The obvious alternative — replaying the session's prelude before each
statement — re-runs every side effect the session already performed (one
`send_invoice()` becomes N). Carrying the namespace instead means a
side-effecting statement runs **exactly once**.

**The documented limitation:** values that cannot cross a JSON boundary do not
survive to the next statement. Modules, functions and classes, open files and
sockets, and any object `json.dumps` rejects are dropped — and **named** in
the result's `dropped` list and in the ledger row, so the caller can see
exactly what the next statement will not find:

```python
result = repl.execute(session, "import json\ndef helper(): return 1\nkeep = [1, 2]")
result["dropped"]   # ['helper', 'json']  -- 'keep' survives
```

Re-import the module or re-define the function in the statement that needs it.
If the carried namespace would grow past `max_state_bytes`, the statement is
refused *after* it ran (the effect already happened, and the record says so)
and the previous state is left unchanged.

### No tool bridge

The kernel gets plain Python and nothing else. A kernel that could reach the
`ToolRegistry` would dispatch tools outside `tool_authz.authorize` —
unauthorized, unpriced, and invisible to the dispatch-contract CI gate that
fails the build on exactly that pattern. Any tool bridge would have to route
every call *through* the authorization seam, not around it.

### Where it lands on disk

`~/.maverick/repl/<session>/` (tenant-scoped to
`~/.maverick/tenants/<t>/repl/…` when a tenant is active), mode `0600`:
`meta.json`, the carried `state.json`, each `stmt_N.py`, and `ledger.jsonl`.

## Governed self-refinement

An agent reads a failure, decides what guidance would have avoided it, and
writes that guidance down. The capability is unremarkable; what makes it
deployable is that none of the writing happens on the agent's own authority.

### The lifecycle

```text
propose ──▶ pending ──(human approval)──▶ apply ──▶ applied ──▶ revert ──▶ reverted
```

**`propose(observation, *, goal_id=None, proposed_by="")`** takes
`{failure, target, name, change, rationale}`. `target` is a closed set —
`prompt`, `skill`, `memory` — so a proposal cannot widen its own blast radius
by naming a new one. Every free-text field is bounded (2000 characters),
screened for injection tripwires, and secret-redacted before storage. **A
tripwire hit refuses the whole proposal**: quarantining it would keep
attacker-authored text in a queue whose only exit is "write this into the
agent's own instructions". Nothing is stored unless every field survives, the
pending queue refuses when full (`max_pending`) rather than evicting evidence,
and a proposal whose `harness_refinement_proposed` audit row cannot be written
is discarded.

**`apply(proposal_id, *, applied_by="", approval_id=None)`** refuses unless
the proposal is still pending, its stored change still matches the digest it
was approved under, the killswitch is clear, the evaluator ground-truth
anchors verify, and — with `require_approval` on — an approved, unspent
approval bound to *this* target and name exists. Then it snapshots the overlay
**before** writing, so a failure part-way through restores the harness instead
of leaving it half-written, and emits both `harness_refinement_applied` and
`learning_update`, so learned-state verification covers a self-refinement
exactly like a dream cycle.

**`refinements(target=None)`** is the read seam: the applied overlay, newest
first. A governed write nothing reads would be inert — so the orchestrator
consumes it. Applied `prompt` refinements are folded into the agent's
standing brief on every run, under a heading that says a human approved
them, after the same redaction and Shield pass the facts block gets (the
observation behind a refinement can originate in an untrusted run). The
block is bounded like every other standing section: the newest 20 entries,
500 characters each. An unreadable overlay yields an empty block rather than
failing the run.

The whole lifecycle is also available as CLI verbs, so a headless install can
drive it:

```console
$ maverick refine propose --failure "cited no sources" \
    --change "Always cite the source file for a claim."
proposal 7f3c… · pending
awaiting approval #128 (decide it in the dashboard queue)
$ maverick refine apply 7f3c… --approval-id 128
$ maverick refine show      # what the agent is actually being told
$ maverick refine revert 7f3c…
```

In the approvals queue a refinement is labelled **self-refinement · changes
the agent's instructions**, so an approver can see at a glance that this is
the agent asking to rewrite its own guidance rather than an ordinary task.

### Enabling

```toml
[harness_refine]
enable = true            # off by default
require_approval = true  # default; a malformed value also resolves to true
max_pending = 20
```

`MAVERICK_HARNESS_REFINE=1` also turns it on. The wizard asks the approval
gate as a follow-up and writes `require_approval = false` only if you decline
it. `require_approval` fails **closed** on a typo — a malformed value can
never disarm the gate.

### The approval walk-through

1. The agent proposes. `propose` parks a real world-model approval at **high**
   risk with provenance `harness_refine`, action
   `harness-refine:<target>:<name>`, and the change digest in the detail. The
   quorum is `safety.dual_control.required_approvals("high")` — one approver
   by default, N distinct approvers under `[security] approvals_required`.

    ```python
    from maverick import harness_refine
    proposal = harness_refine.propose({
        "failure": "The agent emailed the customer before the quote was approved.",
        "target": "prompt",
        "name": "quote-approval",
        "change": "Confirm the quote is approved before contacting the customer.",
        "rationale": "Three blocked goals in a row carried an unapproved quote.",
    }, goal_id=42, proposed_by="agent:sales")
    proposal["approval_id"]   # the parked decision
    ```

2. A human decides it in the dashboard **Approvals** queue (`/approvals`,
   `operate` permission) or over the API:

    ```console
    curl -X POST http://127.0.0.1:8765/api/v1/approvals/17/approve \
      -H "Authorization: Bearer $MAVERICK_DASHBOARD_TOKEN"
    ```

    Every vote lands in the signed audit chain. Under a quorum above one,
    segregation of duties applies: the principal recorded as `proposed_by`
    cannot cast an approving vote on its own proposal unless self-approval is
    explicitly allowed.

3. Apply it. The approval is **one-shot** — spent before the effect, so a
   failure afterwards burns it rather than letting one decision authorize two
   refinements. Propose again to park a new one.

    ```python
    harness_refine.apply(proposal["id"], applied_by="ops@example.com")
    harness_refine.refinements(target="prompt")   # now in force
    ```

4. Reverting restores the snapshot the refinement was applied over:

    ```python
    harness_refine.revert(proposal["id"], reverted_by="ops@example.com")
    ```

    Restoration is **wholesale** — the overlay returns to exactly its bytes at
    apply time, so reverting an older refinement also drops the ones applied
    after it. That is the point of a snapshot rather than an inverse patch.
    `revert` returns `False` when there is nothing applied to undo (reverting
    twice is a no-op) and is deliberately **not** gated on `enable`: turning
    the capability off must never strand an applied refinement. The last 50
    snapshots are retained; a revert whose snapshot has aged out refuses
    rather than restoring the wrong generation.

Reverting does **not** un-burn the consumed approval: the proposal ledger sits
outside the snapshot set on purpose.

### Where it lands on disk

`~/.maverick/harness-refine/` (tenant-scoped as above), mode `0600`:
`proposals.json` (the queue plus the spent-approval record),
`refinements.json` (the overlay in force), and `snapshots/` — a base of its
own, never the shared dream snapshot store, so a dream rollback can never
delete learned state on our behalf and vice versa.

## Run forking and the run tree

Agent shells let an operator branch an append-only session — "go back three
turns and try it the other way" — and throw the losing branch away. The
governed version has to answer a harder question months later, when a reviewer
asks *why the agent did A and not B*: the record has to hold both branches.

`fork()` creates a **new goal**, copies the parent's event trail up to a
chosen decision point onto it so the branch opens from the same visible state,
appends a marker event naming its origin, records the lineage, and audits
`session_forked`.

**Nothing is re-executed.** A replayed event is a record row copied onto the
child's trail — the same text a reviewer already read on the parent. Forking
calls no tool, spends no token, and never touches the sandbox. The child is an
empty run pre-loaded with context, driven from there like any other goal.

```python
from maverick import session_tree

child = session_tree.fork(42, at_event=1180, label="skip the discount check",
                          forked_by="ops@example.com")
session_tree.lineage(child)   # {'goal_id', 'parent', 'children', 'depth', 'root', …}
session_tree.tree(42)         # the nested branch tree under a root
session_tree.roots(limit=50)  # runs that have been forked, newest fork first
```

The same three operations exist as CLI verbs — `maverick run-tree fork
<goal> --at-event <id> --label "…"`, `maverick run-tree show <goal>`, and
`maverick run-tree list` — alongside the read-only **/run-tree** dashboard page.

`at_event` is an absolute **`goal_events.id`**, not an offset: `goal_events.id`
is a global autoincrement with no per-goal sequence column, so an offset would
mean something different on every read. An id that is not on the parent's
trail — including one belonging to a different goal — is refused. `None`
carries the whole trail (up to the first 500 events, which is also the read
window).

Lineage lives in a tenant-scoped JSON sidecar (`~/.maverick/session_tree.json`,
mode `0600`) rather than a `goals` column: released world-model migrations are
immutable, and fork provenance is metadata *about* runs rather than part of
one. Forked children deliberately do **not** set `goals.parent_id`, so a
counterfactual branch never shows up as a decomposition sub-goal in the plan
tree. A missing or corrupt sidecar degrades to "no known forks" with a
warning — the runs themselves are still whole, and a lineage read must never
take a review page down.

### Reading it

The **Branches** page (`/run-tree`, Insights group) lists every forked run and
renders the branches under one root as a plain nested list — it reads in
source order for a screen reader and prints straight into an audit pack. It is
read-only and owner-scoped like the goal listings, and it renders the empty
state rather than failing when lineage is unreadable.

`GET /api/v1/run-tree/{goal_id}` returns
`{enabled, goal_id, root, lineage, tree}`. Both ends are access-checked: a
caller who may not read the root gets the subtree they asked for instead. An
un-forked run answers with itself and no children — missing lineage is not an
error.

### Enabling

```toml
[session_tree]
enable = true    # default; lineage only, never changes execution
max_depth = 10   # how deep a chain of forks may go
```

Because forking only records lineage between runs that already exist, it is on
by default; the wizard's **Run forking?** question writes a line only if you
turn it off.

## Cost of the record

These planes write to the same evidence surfaces every other governed action
uses — lineage receipts, world-model approvals, the signed audit chain. What
that machinery costs is measured, not asserted:
`benchmarks/eval_harness_overhead.py` runs identical task steps with the
controls engaged and disengaged and reports the difference — zero extra model
calls and zero extra tokens (the controls are deterministic code, not an LLM
critic), against a measured wall-clock overhead per durable evidence artifact.
See the benchmark suite's README for the numbers and how to reproduce them.

## Troubleshooting

Every refusal below is deliberate and leaves the system in a defined state.
`governed_repl` raises `ReplError`, `harness_refine` raises `RefineError`, and
`session_tree` raises `SessionTreeError`; a killswitch halt raises
`killswitch.Halted` instead.

| Message | Meaning | Fix |
| --- | --- | --- |
| `governed repl is disabled` | `[repl] enable` is false, or the section could not be read (fails closed) | Set `[repl] enable = true` / `MAVERICK_REPL=1`; check the config file parses |
| `unknown repl session '…'` | Bad id, or the session directory is gone | Open a new session; ids are 16 hex characters |
| `repl session … is closed` | The session was closed; the ledger stays readable | Open a new session — `transcript()` still works on the closed one |
| `repl session … reached its N-statement cap` | `max_statements` consumed (a crashed statement still counts) | Raise `[repl] max_statements`, or open a fresh session |
| `repl statement refused: injection markers …` | The statement carries injection tripwires | Inspect the source; this is the boundary between model text and code we run |
| `repl statement refused: the injection screen failed …` | The screen itself errored — fail closed | Check the `memory_guard` install and logs, then retry |
| `repl statement refused: the PREPARE receipt could not be persisted` | The lineage chain could not be extended or did not verify | Check the lineage store's permissions/integrity; nothing ran |
| `repl statement refused: the carried namespace would reach N bytes` | The namespace exceeded `max_state_bytes` | Raise the cap or drop large values; the statement ran, the state did not change |
| `no sandbox available for the repl kernel: …` | `build_sandbox` failed (backend policy, missing daemon) | Fix `[sandbox]`; under enterprise mode `local` is refused by policy |
| `the statement driver produced no result` (on `stderr`, `ok=False`) | The driver never wrote its result file — timeout, killed process, or no `python3` in the image | Raise `max_seconds`, or use an image with a Python interpreter and a shared workdir |
| `harness self-refinement is off` | `[harness_refine] enable` is false | Set it (or `MAVERICK_HARNESS_REFINE=1`); `revert` keeps working while off |
| `unknown refinement target '…'` | Target outside `prompt` / `skill` / `memory` | Use one of the three; the set is closed by design |
| `refinement name '…' must be 1-96 characters` | Name outside `[A-Za-z0-9][A-Za-z0-9._-]*` | Rename the artifact the refinement targets |
| `observation field '…' is required` / `is N characters; the ceiling is 2000` | Empty or oversized field | Supply all five fields; trim to the bound |
| `observation field '…' tripped the injection screen` | The observation came from a run an attacker may have influenced | Refused, not quarantined — nothing is stored; investigate the source run |
| `the pending refinement queue is full` | `max_pending` proposals already parked | Decide the parked proposals; the queue refuses rather than dropping evidence |
| `the refinement ledger is unreadable` / `the refinement overlay is unreadable` | Corrupt store — refuses rather than starting from a blank queue | Restore the file from backup; a blank queue would let a spent approval work twice |
| `approval #N is pending` / `is denied` | The decision has not been made (or was refused) | Approve it in `/approvals`; under a quorum every distinct approver must vote |
| `approval #N was granted for '…', not '…'` | The approval is bound to one target and name | Use the approval parked by this proposal, or propose again |
| `approval #N has already applied a refinement` | Approvals are one-shot | Propose again to park a new one |
| `proposal '…' no longer matches the digest it was approved under` | The stored change was edited underneath the approval | Propose the new wording; the old approval cannot cover it |
| `evaluator anchors fail their integrity lock` | Ground truth is edited, missing, or unlocked | `python -m maverick.evaluator_evolution --ci` names the problem; regenerate the lock deliberately |
| `could not snapshot the harness` | The pre-apply snapshot failed | Check the data dir's permissions and free space; nothing was applied |
| `snapshot '…' is no longer retained` | Older than the last 50 snapshots | Restore by hand; the proposal stays marked applied |
| `killswitch.Halted` on apply | `~/.maverick/HALT` is set | Clear the killswitch; recovery paths (`revert`) stay outside the halt boundary |
| `session forking is off` | `[session_tree] enable = false` | Re-enable it; the Branches page shows the same state as a badge |
| `goal #N does not exist` | Unknown parent | Fork a run that is on the record |
| `event #N is not on goal #M's trail` | Fork point is not one of the parent's event ids | Read the ids from the run's trajectory — `at_event` is a `goal_events` id, not an offset |
| `would reach depth D, past the [session_tree] max_depth` | Chain of forks too deep | Raise `max_depth`, or fork closer to the root |
| `the fork-lineage sidecar is full` | 5000 lineage links recorded | Archive old run trees before forking again |
| `fork lineage for goal #N is cyclic` | The sidecar was hand-edited or corrupted | Repair the sidecar; reads report the goal as its own root meanwhile |

## See also

- [Configuration](configuration.md) — every section and knob in one place.
- [Safety](safety.md) — the sandbox backends, approval floors, and Shield.
- [Operations](operations.md) — running the dashboard and the audit surfaces.
- [External agents](external-agents.md) — the same governance seam applied to
  agents built on other platforms.
