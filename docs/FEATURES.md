# Lightwork - Shipped Features

What Lightwork **does**, grounded in the current repository code. This is the
catalogue of built features and tools.

> Conventions: capabilities are grouped by concern. Module paths are relative to
> `packages/maverick-core/maverick/` unless noted. CLI verbs are shown as
> `maverick <verb>`.

<!-- toc:start -->
## Contents

| Section | Entries |
| --- | ---: |
| [Agent kernel and orchestration](#agent-kernel-and-orchestration) | 215 |
| [Tools](#tools) | 10 |
| [Channels](#channels) | prose |
| [Sandboxes](#sandboxes) | prose |
| [LLM providers and routing](#llm-providers-and-routing) | prose |
| [MCP and agent interop](#mcp-and-agent-interop) | 20 |
| [Safety and security](#safety-and-security) | 52 |
| [Governed agent runtime and onboarding](#governed-agent-runtime-and-onboarding) | 37 |
| [Hosted control plane and multi-tenancy](#hosted-control-plane-and-multi-tenancy) | 11 |
| [Evaluation and benchmarks](#evaluation-and-benchmarks) | prose |
| [Observability and reliability](#observability-and-reliability) | prose |
| [UX surfaces](#ux-surfaces) | 50 |
| [Packaged governance, evidence and external privacy control planes](#packaged-governance-evidence-and-external-privacy-control-planes) | 4 |
| [Software development: the code vault](#software-development-the-code-vault) | 2 |
| [Information-flow control](#information-flow-control) | 1 |
| [Adaptive immunity](#adaptive-immunity) | 5 |
| [Unified cross-suite audit projection](#unified-cross-suite-audit-projection) | 6 |
| [Distribution and install](#distribution-and-install) | 19 |
| [Customer workflow completion and readiness](#customer-workflow-completion-and-readiness) | 22 in 24 subsections |

454 entries in 19 sections. This block is generated: `python scripts/features_toc.py --write` (the test suite fails when it is stale).
<!-- toc:end -->

## Agent kernel and orchestration

- **Conversation alternatives** — Try again, Edit and resend, and Branch from
  here open a complete review before starting a separate conversation. The
  original stays intact; the selected prior messages, answered clarifications,
  files and named account restrictions are retained. Answer only is the default;
  repeating connected actions requires a separate choice and review. Settings
  and the installer expose `[chat_message_actions] enabled`. Copilot opens the
  same protected form. Interrupted admission reads its original receipt without
  repeating work; copied content keeps its sources' current access rules.

- **Complete workflow-pilot controls** — ordinary forms and Copilot prepare
  unstarted tasks, freeze a paired plan, record time and complete cost evidence,
  and obtain an independent review. Each write has a complete consequence review
  and a pure original-outcome reader. Prepared tasks are admitted atomically on
  SQLite and PostgreSQL; pilot-plan creation currently requires the local
  governed-record backend. Task start and release publication remain separate.
  Reported measurements do not by themselves establish causal improvement.

- **Decision checks and joint observation planning** — Decision evidence accepts
  named possible situations, choices, exact decimal losses and observation costs.
  It checks whether a choice stays acceptable across every remaining declared
  situation, then finds the least-cost joint observation batch whose possible
  answers each support a choice, within the entered limits. UI and Copilot share
  check, reservation, acknowledgement and original-outcome controls. The bounded
  model supports eight facts, sixteen cases, four choices and 128 situations;
  it records operator premises and requests, without executing business actions.

- **Employee companion preview** - default-off `[features] employee_companions`
  adds an explicitly enrolled employee's private conversation and workspace-admin
  policy/metadata page. A separate policy grant enables draft replies through the
  configured writer model, with optional permitted own-task context and bounded
  retained history. Deterministic task status stays available alongside work.
  No agent tools execute; request receipts prevent automatic paid replay, and
  authority is rechecked before dispatch/publication. History retention is optional
  and encrypted; connector retrieval,
  learned memory, actions and voice are unavailable. The preview is not
  qualified for production and does not change legacy administrator access to
  ordinary task/chat content.
  See [scope and qualification gaps](employee-companions.md).

- **Guided restored-connection review** — recovery uses ordinary outcome,
  evidence and date controls instead of editing a data object. Recovery Copilot
  hosts the same current-authority form locally. Interrupted recording can
  finish the exact retained review without repeating old work; normal startup
  still requires separate completion. Manual source-position selection and
  whole-platform Copilot coverage remain incomplete. See
  [review boundaries](recovery-connected-services.md).

- **Copilot product controls** — the default-off
  `[features] copilot_operations` catalog shares selected native product
  writers, complete consequence reviews and original-outcome recovery with
  ordinary pages. Named choices replace technical request editing; protected
  handoffs retain entered work where the complete native form is required.
  Native authority, source/version, permission and deadline checks remain at
  the effect. Settings and the installer expose the catalog and its permitted
  operation families. Ordinary controls retain their own feature requirements
  independently of Copilot.

- **Checked answer regions** — optional `[features] applicability_regions`
  adds ordinary Learning controls for two exact versions of an owned taught
  rule. It executes both over the complete declared finite input grid, retains
  current permitted comparison evidence and separately reviewed hypothetical
  answers, and shows where the original, proposed, both or neither answer is
  supported. Unknown and conflicting answers stay unresolved. A minimal
  axis-split routing tree is checked against an independent full-grid lookup;
  trying a checked route runs the chosen native rule without publishing it.
  Copilot shares full review, private authoring, withdrawal and exact originals.

- **Rewrite and check local rules** — optional
  `[features] governed_rule_evolution` adds ordinary controls for constructing
  native decision routes from one owned published taught rule and improving
  the order of complete checks against declared wrong-answer examples. A
  separate unchanged complete-domain gate remains outside both artifacts.
  Full comparison, separate owner acceptance, separately authorized publication,
  active-release checking and exact retained-release restoration use the native
  workflow store. Copilot uses those same reviewed controls and original
  outcomes. This changes supported local rule graphs; it does not modify host
  source, plugins, provider models or arbitrary code.

- **Complete task search** — Tasks and `tasks.find` continue through protected
  parts of the current owned task range instead of treating the latest 1,000
  records as the whole history. Search progress and unfinished reads stay
  visible; interrupted parts can be retried without replacing newer search
  words. Ordinary task-list continuation also preserves distinct older rows.

- **Reviewed agent removal and reset** — Agent Factory distinguishes deleting
  a custom agent from restoring a built-in agent. Full current and resulting
  definitions, exact source versions and the original request are retained
  through review, native removal and interrupted replies. A damaged saved
  definition has an explicit discard review with its true resulting behavior;
  it is not presented as an editable working agent. Copilot shares current
  authority, complete review and original-outcome recovery.

- **Gradual rollout of changed specialists** (`specialist_canary.py`,
  `[agent_tests] canary_percent`, off by default) — with a share from 1 to 50,
  publishing changed instructions for an existing specialist makes them a trial
  beside the current version. New goals use the trial for that share, chosen
  from the goal id, and every goal records the version it used. Workforce shows
  goal counts and feedback per version, and Promote or Roll back are reviewed,
  audited actions. `canary_auto_rollback` can roll a failing trial back after 10
  finished goals. A new specialist publishes normally. Limits are in
  `docs/configuration.md`.

- **Additional-work capability qualification** — the optional
  `[features] commitment_capability_learning` setting adds guided Promise
  review forms for competing material/capacity/shared-setup explanations,
  jointly offered work and inclusion-minimal hypothetical additions. Completed
  attributed trials or exact owned published local-rule tests narrow those
  explanations within one shared test/effort allowance. Every surviving model
  must protect all accepted commitments. Native UI and Copilot retain current
  sources, consent, exact originals and unknown attempts without replay or
  allowance refund. Own history remains readable after disable or archive.
  This supports conditional planning under entered premises; it does not verify
  physical capacity, make purchases, establish revenue or claim a new algorithm.

- **Compliance studio protected draft saves** — guided risk, control, vendor
  and evidence record design reviews the complete supported current and
  proposed draft before the existing native Save. Interrupted create/replace
  replies recover the exact original request; uncertain admission never repeats
  a write. Current source, actor/workspace and expiry are rechecked after native
  writer waits. Copilot opens the protected form without replacing newer
  choices. Independent review, approval, publication and connected-destination
  delivery remain separate operations.

- **Share preparation safely** — guided per-case confidentiality groups and
  deadlines allow eligible preparation to be shared across two to eight permitted
  original local-rule cases. Each case also receives a separate complete native
  run. Work, source checks and receipts share one allowance. Ordinary controls
  and Copilot preserve case choices and original outcomes; disabled operation
  retains authorized history. This does not move connected effects or approvals.

- **Share and qualify local rule structures** — export reviewed anonymous
  operations, input types and repeated-value relationships without source names,
  literal thresholds or private cases. Import through a file chooser, automatically
  search target bindings, qualify against target-owned cases and the complete
  declared finite input domain, then run the qualified local rule in its owned
  receipt. Qualification does not create or publish an independent workflow.

- **Reuse complete rule-behavior evidence** — optional complete native evaluation
  of every declared eligible input allows prior case output to be reused across
  a rule rewrite with identical typed behavior. Both the finite checks and a
  separate complete workflow comparison count toward the existing work allowance.
  Current case, source, policy and reuse permission remain mandatory. Unsupported
  or ambiguous rules use ordinary checking; no research or speed advantage is
  implied by finite-function equivalence.

- **Private task calculations** — choose an owned native task attachment, enter
  ordinary bounded conditions, review a local calculation and separately approve
  its fixed outward answer. Current analysis/export purpose and inherited source
  permissions remain mandatory. Exact originals, spent uses and one allowed
  release follow the physical source across copies and removal; uncertain work
  never repeats automatically. Private names, rows and traces stay local.

- **Understand a missing reply** — use isolated fictional native sign-offs to
  enumerate the complete declared bounded situations, find shortest histories
  with identical visible status but different original obligations, and identify
  a permitted observation that separates them. Original-result readback cannot
  rerun the practice. This changes no live approval and establishes no remote
  delivery guarantee or advantage over the matched exhaustive comparison.

These five capabilities are separate, default-off feature choices in ordinary
Settings and the installation wizard.

- **Run a learned workflow from Copilot** — on a saved workflow's designer page,
  the closed catalog checks the published release and opens the same labelled
  input form as Run. The form pins that release; the native run endpoint rechecks
  access and publication before accepting work. Copilot reports an accepted run
  as in progress, with a link to its status, rather than claiming the business
  outcome is complete. This is a local journey, not installed-app acceptance or
  whole-platform operation coverage.

- **Bounded audit reads and explicit coverage** — live tails seek a bounded
  suffix; newly sealed history uses authenticated 1 MiB frames without changing
  signed bytes. Export supports separate coverage receipts and optional segment
  chain verification. Partial/unreadable evidence is visible and exits nonzero;
  legacy monolithic seals remain readable with their whole-blob cost reported.
  See [audit read coverage](audit-read-coverage.md) for limits and proof scope.

- **Customer navigation** — Tasks (`/goals`), Connections (`/connections`),
  Knowledge (`/knowledge-access`), Results (`/deliverables`), and Settings (`/settings`)
  retain existing routes and data permissions. Navigation and direct page
  requests deny unreadable role policy. Connections requires workspace admin;
  Settings and technical Learning/Benchmarks/Performance pages require
  installation admin. Their JSON snapshots and feature-switch inventory use the
  same authority. Knowledge exposes only exact, currently eligible registry
  versions, not all company data. Existing tenant-scoped customer assessment/benchmark-exchange
  results retain their own permissions.

- **Recursive multi-agent swarm** — orchestrator decomposes a goal and spawns
  specialist sub-agents (researcher / coder / writer / verifier / revisor /
  reflector), run in parallel (`orchestrator.py`, `agent.py`, `swarm.py`).
- **Durable, resumable execution** — checkpoint / rewind / `maverick resume`
  (`checkpoint.py`), opt-in via `[durable]`.
- **Workspace mutation journal** (`workspace_journal.py`, opt-in `[workspace]
  journal`) — every file-tool write (write_file, the str_replace editors,
  ast_edit share one chokepoint) records the file's PRE-mutation state:
  existed-or-not, bytes, sha256. `maverick journal list | diff | revert
  --goal N` then restores a goal's workspace to its pre-run bytes,
  newest-entry-first, with no snapshot planned in advance — reversibility as
  a property of the harness, not a habit of the model. Per-goal
  (tenant-scoped store), byte/entry-capped (`journal_max_*`); an incomplete
  journal refuses a full revert (`--partial` to restore what was captured),
  each real revert writes one signed `workspace_revert` audit row and
  archives the journal so it can't replay, and revert re-validates every
  recorded path (no traversal, no writes through symlinks) so a tampered
  journal can't become an arbitrary-write primitive. `journal_strict = true`
  refuses any write whose pre-image can't be journaled — reversibility as a
  guarantee for regulated deployments. Shell-driven mutations are out of
  scope (the audit trail records those commands); default off, wizard step
  under *Workspace journal*.
- **Reviewed task-file recovery in the app** (`task_file_recovery.py`, the
  existing `workspace.journal` plus `journal_strict` controls) — a named task
  owner can enable capture with an administrator, review exact changes and
  restore the latest captured local file-tool originals from the task page.
  Encrypted originals bind the real runtime folder; stopped-task checks,
  process leases, path protection, per-file drift checks and retained requests
  guard review and interrupted retry. No shell or external-action rollback is
  claimed. See [task-file recovery](task-file-recovery.md) for limits.
- **Loop-guard suppression tier** — the long-standing repeated-identical-call
  nudge (`MAVERICK_LOOP_GUARD_THRESHOLD`) also covers byte-identical
  *successes* (a poll loop whose output never changes is burning budget on
  zero information), and past `MAVERICK_LOOP_GUARD_BLOCK` (default 6,
  clamped above the nudge threshold so advice always precedes enforcement,
  0 disables) the next byte-identical call is refused WITHOUT executing.
  Per-call only — changed arguments or a different tool clears it — so
  legitimate polls that vary anything keep working. Built for the
  open-weight lanes (ollama / vllm / tgi), where smaller models grind
  identical retries through the whole tool budget.
- **Session forking + run tree** (`session_tree.py`, default-on
  `[session_tree] enable`, depth-capped by `max_depth`) — branch a run at one
  decision point so Oversight can read what the agent chose *beside* the
  alternative instead of only the branch that shipped. `fork(goal_id,
  at_event=…)` creates a new goal, copies the parent's event trail up to an
  absolute `goal_events` id (ids, not offsets — there is no per-goal sequence
  column), appends a marker event naming its origin, and audits
  `session_forked`; `lineage` / `tree` / `roots` read it back. **Nothing is
  re-executed** — a replayed event is a record row, so forking calls no tool,
  spends no token, and never touches the sandbox. Lineage lives in a
  tenant-scoped `session_tree.json` sidecar (released migrations are
  immutable) and deliberately does *not* set `goals.parent_id`, so a
  counterfactual never appears as a decomposition sub-goal; a corrupt sidecar
  degrades to "no known forks" rather than taking a review page down. Read-only
  **Run Tree** dashboard page (`/run-tree`, owner-scoped) +
  `GET /api/v1/run-tree/{goal_id}` (both ends access-checked).
- **Kernel lifecycle hooks** — `PreToolUse` / `PostToolUse` / `UserPromptSubmit`
  (`hooks.py`), registrable from plugins.
- **Optional task limits and metered usage** — explicit dollar, elapsed-time,
  token, tool-call and step limits are enforced; ordinary tasks receive no
  generated limits. Settings can suppress saved task defaults reversibly.
  Organization allowance checks remain independent and admit each physical
  provider attempt against current recorded spend plus durable holds. Reported
  provider cost can exceed its projection and is still recorded. Certified
  allowance refusals before orchestration preserve resumable workflow progress;
  later stops remain conservative about prior effects. Goal cancellation is
  checked during model/tool awaits, with execution owned until cleanup finishes. See
  [task limits and spend accounting](task-limits.md).
- **Killswitch** — `~/.maverick/HALT` aborts all running goals (`killswitch.py`).
- **Long-horizon review checkpoint** — opt-in `[safety] review_checkpoint`
  (`review_checkpoint.py`): the root agent fires a human-review heartbeat every
  N dollars / M tool calls / T wall-seconds; continuation is gated through the
  consent/approval path with silent auto-approval disabled, so a reviewer denial
  or missing explicit approval stops the run cleanly. Distinct from the hard
  budget cap; inert and behavior-identical when unconfigured.
- **Verifier default-on** across goal types (`verifier.py`); **reflexion** retry
  loop with cross-session failure memory (`reflexion.py`).
- **Planning topologies** — tree-of-thought (`tree_of_thought.py`), debate
  (`debate.py`), **plan-execute-reflect** loop (`plan_execute_reflect.py`,
  `maverick plan-reflect GOAL`): a planner decomposes the goal, an executor runs
  each step, a reflector decides done/revise/continue and loops until done, the
  iteration cap, or the budget runs out — speculative decode/finalize
  (`speculative.py`), latency-aware best-of-N that cancels laggards
  (`latency_best_of_n.py`), shared-scratchpad blackboard (`blackboard.py`),
  cross-agent bus (`agent_bus.py`), and a read-only **observation channel**
  (`observation_channel.py`) — a live push/subscribe broadcast of the swarm's
  event stream for an external observer (monitoring agent, dashboard,
  supervisor) that doesn't join the control flow; `blackboard.post` tees into
  it, a slow observer drops its oldest events rather than stalling the swarm,
  and it's a no-op (lock-free subscriber check) when nobody is watching.
- **Context lifecycle** — deferred tool loading + `find_tools` with a
  role- and pack-aware short catalog (`[tools] exposure`, default `core`:
  ~30-40 tools per turn instead of ~240), cross-session
  `memory` tool (`tools/memory.py`), programmatic tool calling
  (`tools/code_exec.py`), structural/retrieval-augmented compaction
  (`compaction/__init__.py`, `context_compactor.py`), and a **long-context retrieval
  router** (`long_context_router.py`) that shards an oversized payload (e.g. a
  document pasted into a goal) and keeps only the query-relevant shards instead
  of overflowing the model window — zero-dep lexical ranking by default, an
  injected Chroma/Qdrant store for embedding-quality retrieval; opt-in via
  `[context] retrieval_router`.
- **Complete tool-result delivery** (`tool_result_stream.py`,
  `tool_result_artifacts.py`) — bounded 16 MiB collection; safe progress before
  whole-result screening; encrypted tenant/principal/goal-scoped artifacts for
  results larger than model previews; `read_tool_result` slices under existing
  tool ACLs. Programmatic `code_exec` receives complete screened values, and
  partial streams/cleanup failures require reconciliation. See
  [tool result lifecycle](tool-result-lifecycle.md) for quotas, seven-day
  retention and cancellation ownership.
- **Model-scaled context** (`context_scaling.py`, on by default; `[context]
  model_scaled = false` pins the legacy fixed bounds) — history windows,
  per-turn caps, compaction targets, the retrieval-router threshold, tool-result
  caps, and per-turn `max_tokens` all derive from the **driving model's real
  context window** (`preflight.context_limit`) instead of constants tuned for a
  200k model: a 1M-window model gets 1M-window bounds, a 32k model routes
  before overflowing. Legacy values are the floors (nothing shrinks), explicit
  `[context]` keys/env vars still win, and unknown/self-hosted models declare
  their window via `[context.model_windows]` or
  `MAVERICK_MODEL_CONTEXT_WINDOW`.
- **Compaction plug-in API** (`compaction/plugins.py`) — register a custom
  context-compaction strategy (graph-structured, domain summarizer, a learned
  model) under a name and select it via `[context] compaction_strategy`; the
  shipping heuristic registers as the default `"heuristic"`, and `compact_with`
  **fails safe** to it when a configured strategy is unknown (a typo degrades to
  working compaction, never none) — so the kernel's compaction is extensible
  without a fork. Four strategies ship registered in this one dispatcher (and
  are reachable from `agent.py`'s per-turn compaction): **`learned`** (LLM
  summary with a self-tuning prompt picker scored by an outcome ledger),
  **`multimodal`** (replaces heavy image/audio blocks with text stubs that keep
  the media fact + dimensions), **`streaming`** (an incremental running summary
  with a persisted per-conversation cursor — folds only new turns), and
  **`graph`** (an entity-relation digest); each degrades deterministically
  without an llm and is selected by name via `[context] compaction_strategy`.
- **Governed session kernel** (`governed_repl.py`, opt-in `[repl] enable` /
  `MAVERICK_REPL=1`, OFF by default) — an agent writes **Python** against a
  live namespace instead of composing fixed tool schemas, and the code is the
  audited artifact: every statement is SHA-256 hashed, injection-screened
  (`memory_guard`, fail-closed on a broken screen), receipted on the
  hash-chained lineage ledger PREPARE-before/COMMIT-after (`strict=True`, so a
  tampered chain refuses rather than extends — no receipt, no execution),
  audited as `repl_executed` with the digest and never the source, and
  appended to a per-session `ledger.jsonl` that outlives the session. Runs
  through `sandbox.exec` like every other shell, so the configured backend is
  the containment boundary; per-statement wall/output/state/statement-count
  caps come from `[repl]`, and output is secret-redacted host-side. Continuity
  is an explicit **JSON namespace carry** (a stdlib driver re-loads and
  re-dumps the serializable globals), so a side-effecting statement runs
  exactly once — no prelude replay — and values that cannot cross that
  boundary (modules, callables, arbitrary objects) are dropped and **named**
  in the result and the ledger. There is no tool bridge, deliberately: a
  kernel that reached the registry would dispatch outside `tool_authz.authorize`.
  The module API (`open_session` / `execute` / `transcript` / `close_session`)
  is the entry point — no CLI verb, no dashboard page. Documented in
  [`governed-execution.md`](./governed-execution.md).
- **Governed learning defaults on** — the in-process learning loops are enabled
  on a clean install and can be disabled individually or together from the
  dashboard Learning page. Higher-authority actions do not inherit that default:
  generated executable tools, third-party MCP acquisition, extra task/result-
  bearing provider calls, verbatim cross-conversation user notes, live flow
  auto-apply, model-weight adoption, and DGM code self-modification retain
  separate gates.
- **Local continuous learning** — distill successful run trajectories into a
  validator-compliant `SKILL.md` suggestion under the active tenant's
  `learned-skills` store (`skill/distillation_local.py`), default-on via
  `[self_learning] distill_local`. A suggestion does not enter agent recall
  automatically. An administrator reviews its full instructions and shared
  source tasks on Skills, then explicitly admits one exact version into the
  installed-skill store; the guarded Copilot learning actions use the same
  admission and withdrawal services.
  Gated distillation (`skill/distillation.py`) adds two quality gates so the loop stays
  useful: it won't distill from fewer than N successful trajectories (a one-off
  success is noise), and it dedups a candidate against the learned-skills store
  by lexical containment so near-duplicate lessons don't accumulate — the
  orchestrator uses the gated path.
- **DPO preference-pair mining from real runs** — the offline DPO fine-tune
  (`maverick.training.rlaif`, the L3 rung) is trained on preference pairs built
  from donated run records, not hand-labels. Two objective gradient sources:
  (1) a verifier-**rejected draft** paired against the accepted final within one
  `task_family`, and (2) **best-of-N candidate mining** — `run_goal_best_of_n`
  scores each of N coding attempts by whether the task's real tests pass
  (`--fail-to-pass`/`--pass-to-pass`) and donates the pass-vs-fail spread as a
  pair with a ~1.0 reward margin (no verifier rejection needed; a strong
  proposer + strong verifier rarely rejects, so the objective signal is the
  robust one). A pair is written only when the attempts *diverge*; an all-tie
  run logs `best-of-N: no DPO pair donated` and writes nothing. Candidate
  patches an agent applied via tools (no diff in the final answer) are recovered
  from the workdir (`_capture_workdir_diff`, `__pycache__`/binary noise
  excluded) and each attempt is isolated by a reset to clean HEAD. Donation is
  opt-in and metadata-only unless `donate_text` is set (`[telemetry]
  donate_trajectories` / `donate_text`, thresholds `donate_min_entropy` /
  `donate_min_confidence`); `maverick start --repeat N` re-runs one task N times
  so its attempts share a `task_family`. End-to-end recipe in
  [`self-learning-runbook.md`](./self-learning-runbook.md).
- **Dreaming (offline consolidation)** — `maverick dream` (`dreaming.py`,
  default-on `[dreaming] enable`) replays recent successes + failure reflexions
  while the swarm is idle, attributes them to departments (domain packs),
  distills recurring wins into learned skills per department (via the gated
  v2 distiller), clusters recurring failures into *dream insights*
  (`~/.maverick/dreams/insights.ndjson`) that the orchestrator recalls on the
  next similar goal — a domain run is boosted toward its own department's
  insights — and prunes stale near-duplicate reflexions. Deterministic and
  LLM-free, so consolidation can't be steered by injected trajectory text.
  Reflexions also carry the recording run's department (`reflexion.py`
  `domain` field), and same-department lessons outrank equally-similar
  generic ones at recall time.
- **Self-harness (model-specific harness learning)** — `maverick self-harness`
  (`self_harness.py`, default-on under the conservative `risk_limited` profile)
  mines one model's
  recurring failure reflexions into weakness *signatures*, proposes a *minimal*
  operating-guidance line for each, and regression-validates it on held-in AND
  held-out cases (rejecting an edit that overfits its own examples). Survivors
  are gated through the self-improvement ladder on the `prompt` rung — so
  promotion inherits the evidence floor, the calibration-freeze interlock,
  reversibility, and the signed audit, and **requires `[self_improvement]
  enable`**. An accepted line is recalled into the system prompt for *that model
  only* (`recall_addendum`, keyed on the agent's resolved model), never a
  kernel-template mutation. Reflexions carry a `model_id` for the per-model
  mining. After *Self-Harness: Harnesses That Improve Themselves* (arXiv
  2606.09498); see the
  [sealed evaluation boundary](./self-learning.md#sealed-self-harness-evaluation-boundary).
- **Governed harness self-refinement** (`harness_refine.py`, opt-in
  `[harness_refine] enable` / `MAVERICK_HARNESS_REFINE=1`, OFF by default) —
  an agent **proposes** a change to its own operating instructions from an
  observed failure; a human **applies** it. `propose` accepts one observation
  (`failure/target/name/change/rationale`) against a closed target set
  (`prompt` / `skill` / `memory`, so a proposal cannot widen its own blast
  radius), screens every free-text field for injection tripwires (a hit
  **refuses** — untrusted text is never queued for a write into the agent's
  own instructions), secret-redacts it, and parks a real world-model approval
  at `dual_control.required_approvals("high")` bound to that one target and
  name. `require_approval` defaults ON and fails closed on a malformed value.
  `apply` refuses unless the proposal is pending, its change still matches the
  approved digest, the killswitch is clear, the evaluator anchors verify, and
  the approval is approved and unspent (one-shot, burned before the effect);
  it snapshots the overlay through the learned-state machinery first, so a
  mid-way failure restores rather than half-writes, and emits
  `harness_refinement_applied` **plus** `learning_update` so learned-state
  verification covers it like a dream cycle. `revert` restores the snapshot
  wholesale and is deliberately not gated on `enable` (turning the capability
  off must never strand an applied refinement); `refinements()` is the read
  seam. Stores are tenant-scoped and 0600, with their own snapshot base — never
  the shared dream store. The module API is the entry point in v1; the human
  half runs in the existing dashboard approval queue. Documented in
  [`governed-execution.md`](./governed-execution.md).
- **Evaluator co-evolution (promote a better judge, don't just freeze)** —
  `maverick.evaluator_evolution` (default-on
  `[self_improvement] evaluator_evolution`)
  extends the calibration interlock from *freeze-on-drift* to *promote-on-drift*:
  a challenger evaluator replaces the incumbent only when its agreement with a
  fixed ground-truth **anchor**, measured by the conservative epsilon-best-belief
  lower bound (the eps-quantile of a `Beta(1+S,1+F)` posterior), beats it. Routed
  through the self-improvement ladder on a dedicated `evaluator` rung, so a swap
  inherits the evidence floor, the calibration freeze, reversibility, human
  approval (it sits above the default `max_auto_rung`), and the signed audit; an
  evaluator only scores, so it carries no capability-escalation surface. Each
  swap advances the slot's *epoch* and applies **selective erasure** — only the
  displaced judge's learning records are discarded, keeping the within-epoch
  signal stationary. The anchor is the guardrail, so released anchors are
  **immutable**: checksum-pinned in `evaluator_anchors.lock.json` and enforced by
  `python -m maverick.evaluator_evolution --ci` (a weak or mutable anchor would
  launder drift). The loop is enabled by default, but the evaluator rung remains
  above the default auto-promotion ceiling and therefore requires human approval.
  After *The Red Queen Gödel Machine:
  Co-Evolving Agents and Their Evaluators* (arXiv 2606.26294); see
  [evaluator co-evolution](./self-learning.md#evaluator-co-evolution).
- **Shared generic insight promotion** — when explicitly enabled with
  `[dreaming] promote_shared`, only recurring *unscoped* failures can become
  shared insights. Department-scoped failures remain compartment-local and are
  never synthesized into globally recallable `domain=None` insights.
- **Skill retirement (the forgetting loop)** — a dream phase moves learned
  skills with a decayed track record (`skill_stats.evictable`: enough uses
  AND the Wilson-score CONFIDENCE upper bound on win rate under the floor —
  not the raw win rate, so a thin sample near the floor is not retired on
  the point estimate alone) to `learned-skills/retired/` with a logged
  reason — out of the recall glob, reversible by moving the file back
  (`[dreaming] retire_skills / retire_min_uses / retire_below`).
- **Dream-time rehearsal** — dream cycles queue the biggest recurring
  failure patterns as practice cases (`[dreaming] rehearse`,
  `~/.maverick/dreams/rehearsals.ndjson`); `maverick dream --rehearse` runs
  them as budgeted `[rehearsal]`-titled goals and reports how many of those
  failure patterns complete. Refused while verifier
  calibration is frozen (the same interlock that gates maverick-evolve), so
  the system never practices against a distrusted grader.
- **Department-scoped routing memory** — a domain swarm's counterfactual
  credit is recorded both globally and per department
  (`role_stats.py` `<domain>::<role>` keys); a domain run's routing guidance
  prefers its own department's track record and falls back to the global
  signal when history is thin.
- **Controlled-evidence promotion** — `promotion_effect.py` compares outcomes
  within recorded context groups and reports overlap, a confidence interval,
  and a permutation p-value. Ordinary task history remains observational:
  matching by recorded fields cannot exclude unrecorded reasons why a change
  was tried on easier work. Such comparisons can surface candidates, but cannot
  authorize automatic promotion. A promotion-grade estimate requires
  prospectively randomized assignment, sufficient support in both arms, and
  an observed effect that clears the evidence margin. The receipt retains the
  assignment design, p-value, interval, and sample counts. The
  `[self_improvement] causal_promotion` interlock is on when self-improvement is
  enabled; the current trajectory-to-unit adapter does not assert randomization.
- **Capability grading on the promotion receipt** — the capability
  non-escalation gate refuses a widening change, and the durable receipt records
  *what the gate concluded*, so a third party reading the ledger can tell
  "proven bounded" from "never checked". Each `PromotionRecord` carries
  `capability_evidence` —
  `probed_bounded` (the capability algebra was walked over N tools, with N
  recorded), `declared_bounded` (the caller asserted it), or `unproven` (the rung
  required no proof and none was supplied) — which is what makes the portable
  attestation's bounded-self-improvement claim checkable rather than asserted.
  Additive and backward-compatible: an absent grading is emitted as an absent
  field, so receipts written before it existed re-serialize byte-identically and
  their hash-chained journal entries still verify. A verifier must read that
  absence as *unknown*, never as bounded; an unrecognised grading fails closed
  rather than being downgraded to a weaker one.
- **Model-based counterfactual rollouts** — when measured strata have no
  stratum has both arms (zero overlap), stratification is blind; g-computation
  over a tabular transition model fit from the logged `(state, action) ->
  next_state` records (`counterfactual_rollout.py`) simulates a possible effect by
  re-simulating each context with the decision forced to treated vs control and
  rolling forward to a terminal outcome. Returns the same `EffectEstimate`, so
  the gate is unchanged. Fail-closed by calibration: trustworthy only when the
  model predicts held-out one-step transitions, both actions have support, and a
  null-action placebo reads ~0. A model fit to observational trajectories still
  cannot establish a causal effect; the promotion gate requires independent
  controlled evidence. The tabular learning half of the Operating Twin uses the
  same `causal_promotion` knob.
- **Pre-execution rehearsal** — before a high-impact tool runs, compare it with
  the learned world-model (`rehearsal.py`). It is **observe-only by default**:
  an unfamiliar or poor prediction is logged but does not stop the action.
  Shield, capability, consent, and other approval checks still apply. An
  administrator can change the observation switch and mode under Settings >
  Safety. The explicit `mode = "hold"` choice retains the experimental refusal
  behavior, but there is no in-product approval path for that mode;
  it is not a customer-ready way to govern actions. Held calls are not counted
  as executed tool experience.
- **Human-override ingestion** — when a human declines an Art-14 approval
  gate, the refusal is persisted as a recallable lesson
  (`reflexion.record_human_override`, failure class `human_override`,
  department-tagged) so the next similar goal proposes an alternative or
  seeks approval earlier — and dreaming consolidates repeated refusals into
  department insights. Default-on via `[reflexion]`; the audit record is
  unchanged.
- **Signal capture across the run lifecycle** — goal rows persist their
  department (schema v14 `domain` column; resumes inherit it); a stall on a
  user question records WHAT was missing (`blocked_on_user`); a loop-guard
  tool-failure streak persists as `tool_flaky` (and `find_tools` demotes
  repeat offenders at discovery time); an explicit user correction of the
  prior answer becomes a `user_correction` lesson (`corrections.py`,
  deterministic phrase match over the triggering turn only); verifier
  critiques are mined out of donated trajectories into dream fodder.
- **Insight lifecycle management** — a recurring pattern *refreshes* its
  standing insight (ts + evidence) instead of duplicating; insights
  unconfirmed for `[dreaming] insight_ttl_days` age out; a failure insight
  contradicted by newer similar successes retires; opt-in fact pruning
  (`[dreaming] prune_facts`, default off — the only phase touching operator
  data) expires stale facts and caps the table.
- **Per-user preference notes** (`user_notes.py`) — explicit, deterministic
  preference statements ("I prefer tables", "call me Sam") distilled from
  recent conversations into briefing notes injected ONLY for their exact
  (channel, user) scope; the store rewrites every cycle, so deleted
  conversations stop feeding notes. Each person's own recent-conversation window
  is bounded independently; coworkers cannot evict it. Newest matching source
  turns take precedence over opposite preferences, source turn/version metadata
  is retained, and an unavailable rebuild preserves the last complete store.
- **Learned behavior selection** — `[planning] mode = "auto"` picks
  tree-of-thought per task class from a learned outcome record
  (`planning_stats.py`, bandit-lite + deterministic); budget task classes
  scope by department (`finance_sox::reconcile` learns finance-shaped
  caps); the learned compaction ledger scopes by department
  (`scope|kind` rows).
- **Verifier-scored rehearsal + evolve bridge** — `maverick dream
  --rehearse` grades each practiced case with the calibrated verifier, and
  `maverick-evolve --live --rehearsals` consumes the rehearsal queue as
  weighted eval cases so config evolution optimizes against the operator's
  own recurring failures. `maverick-evolve --adopt` overlays the archive's
  best config onto a domain pack (persona/description/models only —
  capability scopes are refused), diff-shown, `--yes`-gated, `.bak`-backed.
- **Learning-side canary** — probation retirement (a new skill that loses
  its first 3 decided uses outright is retired early) and a benchmark gate:
  while `continuous_benchmark` history shows a regression, a dream cycle's
  NEW skills are quarantined (reversibly) instead of going live.
- **Learning governance** — every dream cycle writes one tamper-evident
  `learning_update` audit row; `maverick dream --dry-run` runs the full
  cycle against temp copies and reports exact would-be changes; each CLI
  cycle snapshots all learned stores first (`--list-snapshots`,
  `--rollback latest|<name>` restore wholesale); with an active tenant,
  every learned store resolves under the tenant's data dir so one tenant's
  memory never feeds another's runs.
- **Client-controlled research DGM** — `[self_modify] enable` remains off by
  default and outside the blanket learning control. A deployment-global admin
  can arm it from the dashboard Learning page or `POST /api/v1/learning/dgm`
  after acknowledging that it is research-only. Arming does not run a cycle and
  never authorizes code adoption or deployment. A ready state requires a narrow
  editable surface, at least two discriminating `eval_tests`, and an external
  attested `ep:<name>` sandbox; every operator-run cycle repeats Git, budget,
  HALT, containment, and evaluator checks. If `MAVERICK_SELF_MODIFY` is set, the
  environment owns the setting and the dashboard control is read-only. An
  operator-owned `MAVERICK_CONFIG_OVERLAY` that sets the DGM bit likewise locks
  the dashboard control. Tenant overlays cannot alter the repo-global gate,
  editable surface, challenge corpus, or evaluator policy.
- **Governed Actions** (`governed_actions.py`, `governed_connectors.py`;
  opt-in, additive) — a consequential operation can be a typed `ActionSpec`
  rather than a free-form call: **simulated** before commit (effect preview,
  no side effects), **gated** on risk/approval (`[actions] require_approval_at`,
  default `high`), and **lineage-tracked** (a tamper-evident hash chain from
  outcome → action → inputs/sources/skills; `verify_lineage` / `trace`).
  `Connector`s expose a system of record as `<sys>.read` (low risk) /
  `<sys>.write` (high) governed Actions. `governed_rest.py` adapts the LIVE
  enterprise REST connectors (Salesforce, ServiceNow) into this surface — the
  write previews its effect without a network call, hits the approval floor,
  commits through the same SSRF-safe / egress-guarded path the tool form uses,
  and records lineage — so a real system-of-record write is governed, not just
  a confirm-gated tool call. Opt-in via `[governed_connectors] enable` +
  `connectors` (`MAVERICK_GOVERNED_CONNECTORS`; wizard step). Traceable
  action governance for self-improving agents.
- **Governed learning at scale** (`access_policy.py`; opt-in, additive) —
  **PBAC**: a skill declares `purposes:` and
  `relevant_skills` recalls it only under a matching run purpose
  (`purpose_scope` / `MAVERICK_PURPOSE`; default-open). On the run path, per-goal
  action **lineage** is recorded when `[actions] enable` is set (tenant-scoped),
  and `impact_of` answers "revoke X → what did it touch?". Inspect with
  `maverick governance lineage|impact`.
- **Specialist operating discipline** (`domain_discipline.py`, on by
  default; `[domains] discipline = false` opts out) — every domain pack's
  persona is augmented at spawn with a universal verification/escalation
  discipline plus its suite's professional guardrails (finance
  maker-checker + SoD, legal privilege, HR PII-minimization, IT/GRC
  chain-of-custody, ops safety interlocks, engineering tests-first, GTM
  no-overpromising, strategy source-grounding). One implementation point
  upgrades all 2,031 built-in packs AND operator/intake-generated packs;
  prompts only — hard limits stay with capabilities/governance.
- **Hard refusals** (`domain_refusals.py`, always on — a prohibited use is not
  an operator preference) — every pack's prompt carries a non-negotiable
  refusal block with **no approval path**: the EU AI Act Art-5 prohibitions for
  HR (workplace emotion inference, biometric categorization, social scoring),
  safety-critical actuation/interlock-override refusals for ops/manufacturing/
  utilities/logistics, autonomous clinical/insurance/banking adjudication,
  MNPI-crossing for capital-markets/strategy, and counsel-of-record for legal,
  plus a universal "never disable your own controls / impersonate a human".
  Packs add their own via a `refuse = [...]` field; the rails (capability /
  governance / Shield) still enforce independently — this makes the agent
  refuse *before* a rail is tested.
- **Pack consumption surface** — every one of the 2,031 packs declares an
  `[output]` contract (deliverable shape, consumers, cadence, sign-off gate) and
  an editable `[[workflow]]` playbook (the ordered procedure, each step naming
  only the pack's own tools and ending in the human gate). Rendered into the
  spawn prompt and the dashboard; intake-generated packs get them too.
- **Reasoning-effort right-sizing** (`effort` pack field, applied only when
  `[effort]` is enabled) — high-stakes judgment packs (SOX, AML/SAR, valuation,
  prior-auth, litigation, incident response, pharma) run deep; clerical
  high-throughput packs (status pages, chasers, hygiene) run light; the rest
  inherit the operator default. A pack tier beats the global default but defers
  to any per-role/env override, and never turns the feature on.
- **Department memory at every spawn depth** — `agent_from_profile` appends
  the department's recalled lessons (same-department reflexions + dream
  insights) to a specialist's brief, so a `spawn_specialist` child starts
  with its department's memory instead of blank (`[domains] memory`;
  no-op unless those loops are enabled).
- **Pack quality gate** — `maverick domains-lint [--ci --warnings]`
  (`domain.lint_profile`): errors for envelope holes (empty tool allowlist
  = ALL tools, missing/unknown `max_risk`, invalid `effort` tier), warnings
  for quality gaps (thin persona, allow∩deny overlap, no knowledge sources, a
  read-only pack not explicitly denying the `shell`/`write_file` floor, an
  `output.gate` lighter than the playbook's final sign-off). All 2,031 built-in
  packs lint clean (0 errors, 0 warnings); every pack carries at least a
  suite-level `knowledge_sources` grounding fallback.
- **Pack prose lint** — `python -m maverick.domain_prose_lint [--ci --fix]`
  (`domain_prose_lint`), run inside `domains-lint` so the CI catalog gate
  covers the words as well as the envelope. Errors: quote corruption
  (`company"s`), smart-quote/mojibake damage, the wrong article before a
  curated term list (`a IT/GRC`, `a HR`, `an SaaS`), two packs sharing one
  persona, a persona under 300 or a description under 30 characters, an
  empty TOML field, and a tool name absent from the registry, the risk
  catalog, and the audited abstract-adapter list. `--fix` rewrites the
  mechanical classes in place without re-serialising the TOML.
- **Pack deployment prerequisites** — tool-risk checks preserve the declared
  risk ceilings and denylists. Read-only workflows use `sql_query_read` and
  `spreadsheet_read`; these tools do not expose their mutable siblings' write
  operations. Deployment validates required workflow tools against the assembled
  registry, including custom adapters, and refuses missing requirements with
  adapter, enablement or approved-export guidance. Optional missing allowlist
  tools are reported separately. Some packs still name adapters that a fresh
  installation does not provide, so linted content is not proof that all
  2,031 packs are operational in a fresh installation.
- **Governance-posture audit** — `maverick domains-audit [--json <path>
  --suite <name>]` (`domain_audit.py`): the auditable inventory of "what can
  these agents do, and what stops them?" — per pack the compartment seal, risk
  ceiling, whether any state-mutating tool is *reachable* (0 across the drafting
  roster), which irreversible actions it denies (segregation of duties), its
  refusals, and the human sign-off on its deliverable. Flags + exits non-zero if
  a drafting pack could reach a mutator; `--json` exports for a GRC system.
- **Safety-posture & FinOps export** — `maverick safety [--json]` prints the
  live posture (shield status, sandbox backend + container isolation, egress
  policy) to assert deployment safety in CI; `maverick spend [--json]` exports
  total + per-goal + per-tag run cost for BI/chargeback; and the dashboard
  `/billing` view shows a tenant's accrued charges, period-over-period trend,
  and an itemized CSV invoice.
- **Per-pack behavioral evals** — `maverick domains-eval [--check]`
- **Roster-wide governance invariant suite** (verified across ALL 2,031 packs,
  fault-injected with a non-vacuous control) — six invariants proven non-vacuously
  (each carries a fault-injection control that fails when the guarantee is
  removed): (1) **tool-reachability** — no drafting/non-builder agent can reach
  a state-mutating tool; (2) **autonomy dial** — an onboarding agent is never
  autonomous, and a high-risk action is never autonomous even once a pack is
  graduated; (3) **capability attenuation** — a spawned child can never exceed
  its parent's grant (no privilege escalation); (4) **compartment isolation** —
  a quarantine seal never bleeds across compartments/suites; (5) **hard
  refusals** — the universal refusal floor is unstrippable; (6) **budget caps**
  — configured limits retain their refusal behavior. This test scope does not
  guarantee that a provider's actual invoice stays within a projected charge.
  Plus hostile-argument fuzzing of every
  connector and tool.
- **Robustness against malformed input** — connectors return an ERROR string
  on a non-string op/path/query instead of raising; `Skill.parse` raises `ValueError` (not `AttributeError`) on
  malformed/untrusted frontmatter; `format_money` degrades gracefully on a
  None/empty currency.
- **Bounded shared connector attempts** — REST/GraphQL factories preserve
  sanitized status and attempt metadata until the retry decision. Explicit REST
  GET retries are bounded and charged to the active Agent tool budget; uncertain
  writes require reconciliation and arbitrary GraphQL documents do not retry.
  Streaming wire/decompression/JSON limits and per-socket absolute deadlines
  apply before rendering. Existing consent, credentials, DNS pinning, 202 and
  truncation semantics remain; synchronous DNS itself is not interruptible.
  See [connector limits and qualification](operations/connector-attempts.md).
- **SQL result completeness and execution ownership** — `database` and
  `sql_query` share explicit row/cell/output completeness, bounded valid JSON
  previews, and correct limited-RETURNING cursor/commit ordering. SQLite and
  psycopg 3 support owned query deadlines/cancellation; other drivers report
  unsupported cancellation honestly. Closed snapshots do not expose an invented
  continuation cursor. See [SQL contracts and limitations](operations/sql-query-execution.md).
  (`domain_eval.py`): golden cases that test a specialist's load-bearing
  behavior (AP catches a duplicate and never pays; legal cites or marks
  unverified; HR refuses emotion inference; ops refuses an interlock override).
  A deterministic rubric scorer (include/exclude/refuse/cite) plus an injected
  runner; `--check` lints the suite against the roster (key-free CI gate) while
  `run_eval(cases, runner)` scores live when a provider key is present.
- **Specialist routing** (`domain_router.py`, wired into `list_specialists
  query=<task>`) — a pre-filter that ranks the whole 2,031-pack roster for a
  task so the orchestrator picks from a shortlist, not a haystack: lexical
  TF-IDF blended with sentence-transformer cosine when `fastembed` is installed
  (paraphrase-aware), graceful lexical-only fallback otherwise. A 25-case
  benchmark floors recall@10 ≥ 80% so a pack/persona edit can't silently degrade
  routing.
- **Hindsight engine** (`hindsight.py`, `maverick hindsight [--strict
  --ledger]`) — replays past goals against learned-state snapshots to detect
  when the forgetting loops silently cost coverage: gained / regressed /
  unchanged, deterministically, with no agent re-runs. `--strict` is a
  learning-regression CI gate; `--ledger` writes an aggregate local summary
  and a separate audit event. The summary itself is unsigned; audit signing
  depends on deployment settings. Incomplete recording exits non-zero and
  warns that the summary may already exist before a retry. Coverage changes
  alone do not demonstrate improved task outcomes.
- **Workforce value report** (`workforce_value.py`, `maverick proof
  [--fleet]`) — deliverables completed, agent cost vs human baseline →
  cost avoided + ROI, the capability improvement curve from the hindsight
  ledger, and governance evidence, per department (and per external vendor
  with `--fleet`). Read-only; the POC-closing artifact.
- **Intent-based work value and opportunities** (`intent_value/`, `/work-value`)
  — business-task grouping, provisional editable component benchmarks,
  audit-backed work, deduplicated cost/gross/net reporting, evidence/history
  drilldowns and scoped live Copilot answers. Existing-capability handoffs and
  optional native workflow drafts retain manual controls and require explicit
  publication/run. Linked outcomes inform later planning without adding forecasts
  to execution totals. See [the method, integration map and acceptance coverage](intent-work-value.md).
- **Assessment doc discovery** (`doc_discovery.py`, `POST /api/v1/docs/
  discover`, `POST /api/v1/goals/{id}/attachments/from-source`) — when
  someone is filling an assessment, searches the CONNECTED sources
  (Microsoft Graph/SharePoint/OneDrive, Slack files, Google Drive) for the
  subject's SOW/contract/DPA/security paperwork and attaches it as real
  goal evidence in one click. Creds resolve env-first then named sealed
  connections; fetched bytes pass the same validation as a direct upload
  (size cap, mime allowlist, executable deny). Fail-open per source;
  `[assessments] doc_discovery` + sources list; inert until a source is
  connected.
- **Assessment memory** (`assessment_memory.py`, `GET /api/v1/assessment-
  memory/similar`, agent tool `similar_assessments`) — the assessment flow
  learns from the org's own past assessments: similar-subject precedents
  with risk ratings, advisory per-question answer suggestions (majority
  vote with confidence + provenance; ties dropped), and semantic lessons
  via the knowledge plane (`assessments` collection, ingested on every
  `save_session`) when enabled. Advisory only — the human review gate is
  untouched. `[assessments] learn`.
- **Department workspaces** (dashboard `/privacy` + `/finance`, shared
  chassis partials) — one workspace pattern per department over the same
  assessment engine: worklist with the inherent→residual risk pair, aging,
  follow-ups, client-side filters, hero stats, precedent memory (rows open
  the full record in the review pop-out), and the framework catalog. Built
  for program volume: actionable rows first (open work + due re-reviews),
  capped table with an honest "showing X of N", stats always count
  everything. Operate floor — records carry answer bodies.
- **Assessment lifecycle** (`assessment.decide_assessment`, `POST /api/v1/
  assess/sessions/{id}/decide`) — reviewer decisions (approved/rejected,
  attributed, audited as `ASSESSMENT_DECIDED`) with a review cadence:
  approval schedules `next_review_at` (90d/180d/1yr/none from the shared
  pop-out) and the record comes due — "due for re-review" stat + filter +
  countdown column in both workspaces. Re-engagement is the existing
  follow-up loop (needs_more → answered → pending_review → re-decide).
- **Editable questionnaire templates** (`assessment.save_custom_template`,
  `GET/PUT/DELETE /api/v1/assess/templates/{type}`, catalog editor on the
  workspaces) — templates are data an operator edits, not code: a custom
  template (JSON under the tenant home, department-tagged privacy|finance)
  WINS over the built-in of the same type; deleting the override restores
  the built-in, which is never modified. Scoring identical; strict
  human-readable validation; saves audited (`TEMPLATE_SAVED`).
- **Privacy framework coverage** — built-in questionnaires span the
  assessments a program actually runs: PIA (lightweight screen) plus the
  formal **DPIA** (GDPR Art. 35, distinct and deeper), **LIA** (Art. 6(1)(f)
  three-part legitimate-interest test), **CCPA/CPRA** (California), the
  **TIA** (Schrems II), AIRA, vendor risk, HIPAA/SOC 2/PCI DSS.
- **Assessment lifecycle depth** — beyond approve/reject: **risk acceptance**
  (`accept_risk`, `POST /assess/sessions/{id}/accept-risk`) records a named
  owner, rationale, and expiry, and comes due again when it lapses;
  **re-review triggers** (`trigger_review` / `set_renewal`,
  `/trigger-review`) force a record due now for an external event (contract
  renewal, new sub-processor) or on a renewal date; the worklist's
  `review_due_reason` says why. **Vendor risk trend** (`risk_trend`,
  `/assess/trend`) shows residual risk moving up/down across successive
  reviews in the pop-out. **Bulk import** (`/assess/bulk-import`) queues a
  CSV of vendors as pending assessments. All revision-checked and audited
  (`RISK_ACCEPTED`, `REVIEW_TRIGGERED`, `RENEWAL_SET`,
  `ASSESSMENTS_BULK_IMPORTED`).
- **Program insights** on `/privacy` — a **DSAR SLA aging** heatmap
  (`/privacy/dsar/aging`: open requests bucketed by days to the statutory
  deadline, by kind) and a **cross-border transfer map**
  (`/privacy/transfer-map`: flows drawn from the Art. 30 register and TIAs
  with a Chapter V safeguard flag).
- **Audit binder** (`/audit/binder`, `GET /api/v1/audit/binder`,
  audit-gated) — the regulator-grade evidence pack assembled from the
  records themselves: per-day signed-chain verification over the audit log,
  the event summary, approvals with identity + quorum, the assessment
  register with CAS revisions and template digests, the privacy registers,
  and the acceptance-learning KPIs. Print-friendly; the product generates
  its own workpapers.
- **Partner fleet console** (`/partner`, `/api/v1/partner/*`) — the
  multi-tenant view for a partner operating client deployments: registry
  (admin-gated writes; tokens never echoed), live `/health` +
  `/value.json` probes per tenant, white-label theme per row, and fleet
  rollups of the agents' own counted value ledgers. Public endpoints are the
  default. Exact-IP loopback test estates additionally require both a global
  admin and an operator opt-in (`[partner] allow_test_estate_loopback = true`
  or `MAVERICK_PARTNER_ALLOW_TEST_ESTATE_LOOPBACK=1`); tenant configuration or
  request data cannot grant that exception.
- **Learning KPI** (`acceptance_metrics`, on the command center and the
  binder) — first-pass acceptance (approved with no follow-up thread = the
  reviewer took the agent's draft as-is), qualified-after-follow-ups,
  rejections, median days to decision, and the 12-month trend. The
  measurable learning loop: evidence the agent is getting better.
- **Question ROI** (`question_roi`, `GET /api/v1/assess/question-roi`,
  command-center panel) — per-question evidence across every saved
  assessment: fire rate, rating impact (re-rolled on the scorer's own
  rollup), and a verdict (load-bearing / informative / inert / unproven).
  The evidence-based questionnaire prune list.
- **DSAR Concierge** (`demo/dsar-concierge/`) — a
  standalone agent on the capability seam: subject-facing intake + a
  deterministic message detector, the emailed identity-verification loop,
  the statutory clock with SLA aging, access/portability packages built
  ONLY from operator-provided extracts, the deliberately non-destructive
  erasure handoff, `/value.json` for the fleet console, and a
  full deployment kit (Dockerfile, launcher, env reference). With
  Lightwork the same agent mirrors into the privacy workspace registers
  and the signed audit chain.
- **Privacy command center** (`/privacy/board`, `GET /api/v1/privacy/board`,
  operate-gated) — the whole program on one live executive board, every
  number from the operating record: KPI tiles with 30-day delta chips and
  sparklines; a residual-risk donut and per-framework bars that
  **cross-filter** the board on click (plus a 30d/90d/12m time slicer); the
  **risk burn-down** (inherent → residual — the risk the program removed);
  12 months of opened-vs-decided throughput; the DSAR SLA runway stacked by
  kind; transfer safeguard coverage; AI Act tiers; **posture gauges** that
  are real ratios out of the registers (DSAR SLA, review cadence, transfer
  safeguards, incident 72h clock, DPA clause coverage — never a synthetic
  score); and a drill-through of the records behind the numbers. One
  aggregate round trip; hand-rolled SVG (no chart deps); auto-refreshes
  every 60s; Present mode for a full-screen presentation. Estate rows drill
  through to the record behind them (`/privacy/vendors/{id}`,
  `/privacy/dsar/{id}`, operate-gated): a vendor's contracts with renewal
  state, questionnaires, linked specialist records and monitoring notes;
  a request's SLA clock, identity verification, collection sources, and
  delivery state with reads used against the cap. Neither page can render
  a questionnaire form token or a response-link token — tests assert it.
- **Privacy ops record types** (`privacy_ops.py`, `/api/v1/privacy/*`,
  tabs on `/privacy`; `[privacy_ops] enable`, wizard step) — the privacy
  operations data plane, every engine deterministic and explainable:
  - *DPA reviews* — clause-by-clause GDPR Art. 28(3) verdicts
    (present/unclear/missing) where every call quotes its matched excerpt;
    inherent risk from the document's declared exposure, residual falls as
    clauses are found. Reviews from pasted text, from CONNECTED sources
    (`/privacy/dpa-documents` search + review-in-place via doc discovery),
    or from digital PDFs (stdlib extractor: FlateDecode, Tj/TJ/hex
    operators; scanned PDFs refuse honestly).
  - *Vendor-paper review + tracked-changes redline*
    (`paper_review.py`, `docx_redline.py`, the **Vendor paper** tab on
    `/privacy` + `/api/v1/privacy/paper-reviews`, and the concierge's
    reviewer desk; `[paper_review] use_model`, wizard step) — when a vendor
    insists on THEIR paper: classify the instrument (GDPR DPA vs CCPA/CPRA privacy
    addendum, scored from the document and filename, ties resolving to the
    stronger instrument), compare it clause-by-clause against our standard
    positions, and emit two deliverables — an analysis memo and the vendor's
    own document marked up with real Word revisions (`w:ins`/`w:del`,
    authored and dated), filed onto the vendor's OneTrust record under the
    next sequential version for that vendor+instrument. The comparison goes
    beyond presence detection: adverse language ("may engage sub-processors
    at its sole discretion") is reported as *conflicting* and escalated to
    high severity, because a paper that bargains for the opposite of our
    position would otherwise score as satisfied. Gap findings are always
    deterministic — a model can neither create nor clear one; it only
    re-words OUR clause to match their drafting, and a draft that drops a
    load-bearing term is discarded for the template text. Redlines edit an
    uploaded `.docx` in place (every other package part preserved) or
    reconstruct from a digital PDF, saying so explicitly. Stdlib OOXML — no
    python-docx.
    **Setting it up:** the shipped clauses are *our* standard positions; a
    deployment's are its own. `maverick clause-playbook init` writes an
    editable playbook (`show` reports what is in force and what you have
    customised), `[paper_review] playbook_path` relocates it, and the
    **Your clause playbook** editor on the Vendor paper tab
    (`GET`/`POST /api/v1/privacy/clause-playbook`, admin to write) does the
    same without a terminal. Clauses left alone keep the shipped position, so
    a partial playbook is a valid one, and a missing or malformed one degrades
    to the shipped language rather than emitting a blank demand.
  - *Drafting OUR paper* (`paper_review.draft_our_paper`,
    `GET /api/v1/privacy/our-paper`, the **Draft our paper** button on the
    Vendor paper tab, `maverick clause-playbook draft <vendor>`;
    `[paper_review] org_name`, wizard question) — the other half of the
    paper-source question: when the vendor signs OUR paper, generate our
    template DPA or CCPA/CPRA addendum as a real `.docx` whose clause body is
    the operator's playbook and whose vendor-specific values (party names,
    effective date) are **rendered in red (`FF0000`)** and listed in a cover
    note, so counsel verifies exactly what the machine inserted. Entirely
    deterministic — no model touches it; a missing org name or date stays a
    red bracketed placeholder rather than a guess, and the generated draft
    carries zero fabricated tracked changes (`revision_count == (0, 0)`).
  - *The negotiation round-trip* — a renegotiated vendor draft (v2+ for the
    same vendor+instrument) is automatically diffed against the previous
    round's demands: the saved record and memo gain a **NEGOTIATION
    PROGRESS** section naming which demanded changes the counter-party
    accepted (`closed_from_previous`) and how many remain open, so a
    negotiation reads as converging (or not) instead of as unrelated
    reviews.
- **The entity graph** (`entity_graph.py`, `/api/v1/graph/*`, the **Lineage**
  tab on `/privacy`, `maverick graph rebuild|dossier|why|blast`;
  `[entity_graph] enable`, wizard step) — one resolved identity per vendor /
  system / person / document / clause across every record silo, connected by
  typed, **time-bounded** edges derived from the governed stores (assessments,
  DPA + vendor-paper reviews, security vendor reviews, AI registry, DSARs,
  incidents). Three rules make it trustworthy: it is an **index, never a
  source of truth** (rebuilt from records at any time, every edge cites the
  record id it derives from, so graph and records cannot disagree); linking is
  **exact-canonical only** ("Acme Corp." = "acme corp"), never fuzzy — a
  fabricated edge is worse than a missing one; and **every edge carries
  `valid_from`/`valid_to`**, with a superseded review's edge closed at its
  successor's birth. That buys the three questions a regulator actually asks,
  each answered with citable record ids: *why did we approve this vendor?*
  (`why()` walks decision → reviewer → reviews in force at decision time →
  clause findings → documents), *what did we know when we signed?*
  (`dossier(as_of=…)` reconstructs the point-in-time picture), and *this
  clause turned out bad — what relied on it?* (`blast_radius()` reverse
  reachability to records, vendors, and decisions). The **episodic plane**
  joins on exact keys only — episode→goal (foreign key), goal→agent
  (`goal.domain`), goal→owner — and the **procedural plane** joins through
  `source_goal_ids`, the goal ids the local distiller stamps into each
  learned skill's frontmatter. A goal's *title* is prose and is never matched
  against vendors or systems; a skill distilled before provenance stamping
  reads as provenance-unknown rather than guessed. Together they close the
  memory-integrity loop: *"this run turned out to be tainted — which learned
  skills depend on it?"* is `blast_radius("goal", id)`, the compliance
  version of a product recall applied to the platform's own memory.
- **Assessment assignment** (`assessment.assign_assessment`,
  `POST /api/v1/assess/sessions/{id}/assign`, the **owner** column plus
  *Mine* / *Unassigned* filters on every department worklist) — every other
  field on an assessment is post-hoc attribution (who decided, who answered);
  this is the only one that says whose job it is NEXT, so a reviewer can ask
  "what is on my desk?". Revision-guarded and audited like every other
  assessment mutation. Routing only: it never gates who may decide.
  - *AI systems registry* — EU AI Act tier screening
    (prohibited/high/limited/minimal) using the Act's own tests (Art. 5,
    Annex III, Art. 50) with matched signals + tier obligations; a
    completed AIRA registers its system (`/privacy/ai-systems/
    from-assessment/{id}`) and attestations ratchet the tier UPWARD only.
  - *RoPA / data inventory* — Art. 30(1) records; a completed PIA drafts
    an entry with provenance (`draft_ropa_from_assessment`), OneTrust's
    RoPA/Data-Mapping CSV export imports with `source="onetrust"`
    (tolerant of their column drift), `export.csv` produces the register
    an authority asks for.
  - *DSAR tracker* — statutory 30-day clock over the REAL machinery:
    access/portability run `dsar.export_subject_data`; erasure only ever
    prepares the exact `maverick erase` command (never destructive from
    the API). Intake from inbound messages: `detect_dsar` classifies the
    email a subject actually sent (Art. 15/17/20 phrasing), extracts the
    address, and keeps the matched phrases as provenance.
  - *Incident register* — Art. 33 72-hour clock from discovery ("past
    72h" badge while undecided); the notification call stays a documented
    HUMAN decision both ways (rationale required — Art. 33(5) covers the
    "no"), attributed and audited. The register never notifies anyone
    itself.
- **Security & GRC workspace** (`security_ops.py`, dashboard `/security` +
  print-friendly `/security/report`, `[security_ops] enable`) — a governed
  control-program data plane on the shared department chassis. Security
  questionnaires cover SOC 2, ISO/IEC 27001:2022, NIST CSF 2.0, NIST SP
  800-53 Rev. 5, CIS Controls v8.1 (pinned assessment specification snapshot),
  PCI DSS 4.0, the HIPAA Security Rule,
  CMMC 2.0 Level 2, and FedRAMP Rev. 5 Class C readiness (the 2026
  transition mapping for legacy Moderate authorizations) using the existing
  yes/no/na/unknown and inherent→residual scoring contract. Pinned granular
  catalogs provide 106 CSF subcategories, 287 NIST 800-53 Moderate selections,
  153 CIS safeguard IDs with minimum IG assignments, 110 CMMC L2 practices,
  and 322 current FedRAMP Class C selections; the CIS prompts omit licensed
  safeguard titles/text and require an authorized CIS copy for commercial use.
  Durable record
  types cover the control register / SoA, quoted-evidence verdicts, risk and
  expiring exceptions, POA&M, vendor posture, policy/attestation lifecycle,
  security incidents, and audit engagements. Mutations are revision-CAS and
  audit-outbox backed; program insights aggregate framework coverage, control
  status, open work, exception expiry, and crosswalk reuse. Framework prompts
  are readiness aids, not bundled licensed standards text or certification.
- **Agent Security Plane — agent-EDR: detect, contain, prove** (`agent_edr.py`,
  `maverick security posture|detections|contain|release|incident`) — the
  defense stack surfaced as one operator surface instead of six modules with
  six vocabularies. **Detect**: every security row on the signed audit chain
  (`shield_block`, `capability_denied`, `governance_denied`, `egress_blocked`,
  `agent_trust_denied`, `secret_redacted`) normalized into one `Detection`
  shape with an attack class and a severity **derived from the event, never
  self-declared** — an audit kind the table does not model produces no
  detection at all, because a plane that invents threats from rows it does not
  understand teaches its operator to ignore it. **Respond**: `contain()` seals
  the agent mid-run and revokes its capability subtree in one act, reporting
  each separately — a compartment seal is **run-scoped and in-memory**, a
  revocation is **durable**, and `contained` is True only when every requested
  action actually landed (a revocation is confirmed by re-reading the registry,
  never assumed). **Prove**: every containment lands on the signed chain and
  `incident_report()` renders the forensic timeline. Every command reports the
  deployment's **posture** alongside its findings: an empty detection list from
  a deployment with the shield off means "not watched", not "not attacked", and
  an unsigned chain is flagged as not tamper-evident rather than presented as
  evidence.
- **Internal platform threat hunter** (`platform_hunt/`, dashboard
  `/security/threats`, opt-in `[threat_hunt] enable`) — a deterministic,
  model-free detector whose production verdict authority is the verified signed
  audit chain plus the independently verified budget-receipt ledger. Mutable
  WorldModel approval/goal/episode snapshots cannot become finding evidence by
  being supplied beside an intact chain. Stable MITRE ATT&CK-tagged findings
  cover shield bypass, injection,
  novel tools, privilege/approval abuse, exfiltration-shaped sequences,
  unsanctioned self-modification, budget/rate and operator anomalies, quorum
  abuse, and goal anomalies; every verdict cites exact event references plus a
  normalized-event SHA-256 commitment. Audit-chain verification is a separate
  input and can raise a critical finding. Findings/investigations use revision
  CAS + a durable outbox; containment is proposal-only, never autonomous.
- **Customer-environment threat hunter** (`env_hunt/`, dashboard
  `/security/soc`, opt-in `[env_hunt] enable`) — read-only telemetry adapters,
  deterministic and customer-Sigma detections, exact-event evidence,
  bounded related-event pivots, allowlisted enrichment, an ATT&CK heatmap, and
  defensive response proposals. Raw events
  stay ephemeral; durable data is derived findings, investigations, proposals,
  and receipts. `[env_hunt] response_execution` is a separate default-off
  switch and does not bypass exact proposal-bound human approval or executor
  scope. The offline Ed25519 approval binds the exact queue row, decision
  identity, proposal digest, and executor; a durable one-shot claim blocks
  automatic retries after an ambiguous external outcome. Missing Shield keeps
  deterministic detection available but suppresses pivots, enrichment,
  automatic proposals, and execution as reduced-autonomy mode.
  The read-only `ConnectorRegistry` is the ingestion extension seam; the
  mutating `ResponseExecutorRegistry` ships empty and requires explicit client
  registration. The reduced standalone's generic JSON ingestion is the
  compatibility floor for a client source without a named adapter.
- **Model Risk & AI Assurance Officer** (`model_risk_assurance.py`, dashboard
  `/security/assurance`, opt-in `[model_risk_assurance] enable`) - governed
  inventory, declarations, review-gated evidence, deterministic findings,
  incidents, time-bounded risk acceptance, exact DGM promotion authority,
  deployment lineage, and signed assurance packs. The required opt-in
  `[evidence_graph] enable` projects approved evidence without treating raw
  collection as proof. Framework and legal mappings are advisory; applicability
  and every consequential decision remain human-owned. See
  [`MODEL_RISK_ASSURANCE.md`](./MODEL_RISK_ASSURANCE.md).
- **External AI estate discovery** (`ai_inventory.py`, the assurance API and
  cockpit, opt-in `[ai_inventory] enable`) — tenant-scoped, read-only inventory
  synchronization for customer-owned AWS Bedrock, Amazon SageMaker, Azure AI
  Foundry, Google Vertex AI, Databricks Unity Catalog, Microsoft Copilot
  Studio, MLflow tracking-server, Hugging Face Hub organization, Snowflake
  Model Registry (one fixed read-only `SHOW MODELS IN ACCOUNT` statement;
  asynchronous execution refused), Salesforce Agentforce / Einstein Bot
  definition estates (one fixed SOQL read over `BotDefinition`), OpenAI
  platform organizations (`GET /v1/models`, fine-tunes flagged by
  `owned_by`), and Replicate account deployments (account-scoped listing;
  each `current_release` binds an immutable provider version). The hardened
  stock contracts additionally cover SageMaker, Snowflake Cortex, Salesforce
  Agentforce and Hugging Face under their exact provider/source bindings.
  Connectors use fixed list operations, bounded pagination/retries/record caps,
  provider revision bindings, missing-asset grace runs, and explicit safe read
  projections. Credentials resolve from the standard provider chain or named
  environment references and are never written to discovery records. A sync is
  global-admin initiated or run by the bounded per-tenant inventory scheduler;
  reads require an explicitly selected tenant. Recurring sweeps also run
  through `maverick ai-inventory sync` (cron-able, with
  per-connector failure isolation) and `maverick ai-inventory status` shows
  each connector's last outcome. These registry adapters do not discover
  browser use, network egress, OAuth grants, or arbitrary shadow AI.
- **AI system hierarchy and portfolio risk** (`model_risk_assurance.py`,
  `portfolio_risk.py`, opt-in `[portfolio_risk] enable`) — declarations can
  bind components to governed parent systems with cycle/depth checks and
  ancestor-drift invalidation. The cockpit renders a transparent bounded risk
  roll-up and revision-CAS quarterly snapshots; the score is decision support,
  not a compliance or legal verdict.
- **Governed model drift monitoring** (`drift_monitoring.py`, opt-in
  `[drift_monitoring] enable`) — tenant-scoped aggregate baselines and bounded
  evaluations for the full statistical battery — feature and prediction
  PSI/KL, Jensen-Shannon divergence, a two-sample chi-squared homogeneity
  test, and a binned Kolmogorov-Smirnov test with exact-tail p-values
  computed in-tree (formula v2) — plus prediction drift, embedding-centroid cosine
  distance, and delayed-ground-truth performance decay. Raw feature rows,
  predictions, labels, and embeddings remain transient. Threshold breaches emit
  exact-artifact `drift_monitoring` evidence, a signed aggregate alert, and the
  assurance officer's ordinary `drift_detected` finding. Metrics are operational
  decision support and require deployment-specific calibration.
- **Agent dependency and MCP governance** (`agent_topology.py`, opt-in
  `[agent_topology] enable`) — an on-demand transitive view over enabled domain
  capabilities, configured MCP servers, and the existing operational entity
  graph. Every tool, server, endpoint, host, filesystem path, knowledge source,
  and model edge names its trust boundary and authority; reverse blast-radius
  queries identify affected agents. MCP servers synchronize into the model-risk
  inventory as governed `tool` assets with safe manifest digests, pin posture,
  transport, and referencing agents. Tokens, header/environment values, URL
  paths, queries, and raw launch arguments are neither projected nor persisted.
- **EU AI Act serious-incident reporting** (`ai_incident_reporting.py`,
  opt-in `[ai_incident_reporting] enable`, requires the assurance officer) —
  classifies an existing assurance incident under Art. 3(49) (death, serious
  health harm, irreversible critical-infrastructure disruption, fundamental-
  rights infringement, property/environment harm; Art. 3(61) widespread flag)
  and starts the Art. 73 tiered clock from *awareness*: 15 days by default
  (73(2)), 2 days for widespread/critical-infrastructure (73(3)), 10 days for
  death (73(4)); the strictest applicable window binds and the GDPR Art. 33
  72-hour clock is deliberately not reused. Declarations, initial/complete
  submissions (73(5)) and withdrawals are human assertions with named actors
  on CAS-governed records; the module routes to the operator-named market
  surveillance authority of an EU-27 Member State (73(1)), renders a bounded
  report draft with citations, and never transmits anything itself. Citations
  carry the consolidated basis (2026-07-27) as versioned metadata.
- **AI regulatory-change impact bridge** (`ai_regulatory_feed.py`, opt-in
  `[ai_regulatory_feed] enable`, requires finance operations and the AI
  evidence gateway; `maverick regulatory-feed`) — runs reviewed alerts from
  the finance regulatory-change engine through explicit operator-configured
  impact rules to create `ai-regulatory-impact.v1` records for human review,
  tenant-bound staleness records naming the exact evidence affected, and
  idempotent customer notices deliverable through the configured notification
  backends with CAS retry semantics. Only bounded alert metadata and
  before/after values are retained; full source documents, notification
  credentials, and delivery receipts are never persisted. Decision support
  requiring human review — never a legal applicability opinion.
- **EU conformity workflows** (`eu_conformity.py`, opt-in `[eu_conformity]
  enable`, `maverick eu-conformity`) — three human-gated registers: the
  Art. 27 fundamental-rights impact assessment as six named element
  assertions with completion, the Art. 27(2) outdate-and-reassess
  transition, and a recorded (never transmitted) Art. 27(3) authority
  notification; the Art. 11(1)/Annex IV technical-documentation checklist
  with per-item references and a cited skeleton render; and the Art. 43
  conformity-assessment route where forbidden combinations are refused at
  the boundary (point 1 without harmonised standards or common
  specifications cannot self-assess; points 2-8 never involve a notified
  body) and a substantial modification reopens the assessment while
  provider pre-determined documented changes do not. Plus three market-
  obligation registers: the Art. 72 post-market monitoring plan (where the
  documented plan lives, with bounded review history; the plan follows the
  Commission's Art. 72(3) template), the Art. 49 registration record where
  a basis in the wrong registry is refused with its citation (49(1)-(3) EU
  database; Annex III point 2 national, 49(5)), and the Art. 13(3)
  instructions-for-use content checklist (six cited items, reference-only).
  Drafting and tracking
  assistance — never a conformity assessment, CE marking, or legal advice.
- **AI-literacy register** (`ai_literacy.py`, opt-in `[ai_literacy] enable`,
  `maverick ai-literacy`) — the EU AI Act Art. 4 obligation (applicable since
  2025-02-02) made inspectable: named humans set per-role training
  requirements with validity windows, assign people, and record completions
  with evidence references and bounded history; `gaps` derives who is
  missing or expired and `export` emits one bounded JSON evidence snapshot.
  Person identifiers are operator-chosen tokens in a tenant-scoped governed
  store. Decision support for the obligation — never a certification of
  competence or training sufficiency.
- **Outbound GRC synchronization** (`grc_sync.py`, opt-in `[grc_sync] enable`,
  `maverick grc-sync`) — idempotently mirrors model-risk findings, accepted
  risks, and incidents into a customer's ServiceNow IRM, Archer, or other
  REST GRC system through the same SSRF-safe, enterprise-egress-guarded
  request path every governed connector uses. Each (record, target) pair owns
  one outbound ledger entry: unchanged sources send nothing, a changed source
  updates the same remote record, and a create whose response yields no
  remote id becomes terminal `delivered_unconfirmed` rather than a blind
  duplicate. The payload is a bounded governed pointer — id, type, severity,
  summary, content digest, `correlation_id` round-trip link, optional
  backlink URL; evidence bodies and detail payloads never leave the platform.
  The dashboard can compare a held delivery with the external record using
  read-only requests. A named global administrator can confirm one exact
  match after a fresh second comparison, or retain the hold with a review
  note. Reconciliation preserves the attempted content and destination,
  rejects stale revisions, and never resends the delivery. Legacy records
  without a stored attempt require an unchanged, digest-matching source;
  their original endpoint cannot be proven retrospectively. Provider-side
  acceptance is not established by the local synthetic tests.
- **Governance workspace** (dashboard `/security/governance` +
  `/api/v1/security/governance`, `governance_api.py`/`governance_schemas.py`,
  rides the `[eu_conformity]`/`[ai_literacy]`/`[ai_incident_reporting]`/
  `[grc_sync]` knobs — no knob of its own) — the plain-language surface for
  legal, privacy/DPO, compliance, and HR over the governed registers: the
  Art. 27 FRIA as six answered questions with citations, the Annex IV
  reference checklist, the Art. 43 route decision and substantial-modification
  marking, Art. 4 literacy requirements/assignments/completions with gap
  chips and a downloadable evidence file, Art. 73 declare/file/withdraw with
  deadline-aware category picking, and GRC delivery status and recovery.
  Inventory-backed pickers replace raw record ids; every mutation is
  operate-floor, CSRF-checked, CAS-guarded, and recorded under the caller's
  name. The page opens with the needs-attention digest, adds the Art. 72/49/13
  market-obligation panels, and can download a per-asset audit bundle — one
  JSON file with every governance record and rendered draft for a system.
  FRIA answer bodies stay operate-floor: the view-floor listing carries
  assertion state only. GRC dispatch explicitly requires a named global
  administrator's confirmation before sending records to the configured
  external system. GRC recovery contacts that system only to read and compare.
- **Model-agnostic explainability** (`explainability.py`, opt-in
  `[explainability] enable`, `maverick explainability`) — dependency-free
  implementations of the technical-evaluation battery: seeded permutation
  importance (model reliance; accuracy-drop with labels) and partial
  dependence for any caller-supplied scoring callable, Spearman global
  sensitivity over logged feature/score pairs, and standardized-deviation
  reason codes for single decisions (the adverse-action shape regulated
  verticals expect). Reports record as digest-scoped `explainability`
  evidence against a governed asset. Attribution for the operator's own
  review — never a fairness certification, causal claim, or legal advice.
- **Governed LLM gateway** (`llm_gateway.py`, dashboard
  `/gateway/v1/chat/completions` and `/gateway/v1/messages`, opt-in
  `[llm_gateway]`, `maverick gateway`) — estate coverage for agents that
  never enroll: point an OpenAI-compatible or native Anthropic-compatible
  client at Lightwork and every non-streaming call crosses a governed
  checkpoint — a team-bound gateway bearer, optional model allowlist,
  optional deterministic prompt screen, secret/PII redaction in both
  directions, bounded bodies, durable team call/input/output reservations,
  and the SSRF-pinned enterprise-egress-guarded fixed upstream path. The
  shadow-caller ledger retains only opaque caller/team digests, models,
  counts, token usage, redaction counts, and content digests; it never stores
  bodies or relays upstream error bodies. OpenAI Responses, streaming, live
  provider-contract acceptance, and traffic that bypasses the gateway remain
  out of scope.
- **Agent identity federation** — a trust-registry entry's `jwks_file` may
  be an `https://` JWKS endpoint (Microsoft Entra ID, Okta, any OIDC
  IdP), fetched with a bounded timeout and cached keys, so platform-issued
  agent tokens verify without exporting key files; authorization never
  federates — the agent must still hold an active, inbound-permitted
  registry entry, and the verified subject must equal the agent id exactly.
- **Signed content provenance** (`content_provenance.py`, opt-in
  `[content_provenance] enable`, `maverick content-provenance`) — the
  Art. 50(2) machine-readable marking obligation (applicable 2026-12-02)
  made verifiable: bounded sidecar manifests bind exact content bytes to
  the generating asset, modality, and optional delivery receipt,
  Ed25519-signed through a dedicated hash-chained attestation ledger
  (domain-separated from audit rows and assurance packs) and verified
  against an EXTERNAL key registry with full row-hash and key-id
  derivation checks. Media-container embedding (C2PA JUMBF) is out of
  scope and stated so. Never a content-authenticity certification.
- **Underwriting evidence pack** (`underwriting_pack.py`,
  `maverick underwriting-pack export`) — governance as premium input: a
  bounded underwriter-oriented posture summary (evidence coverage by kind
  and freshness, incident and Art. 73 discipline, EU AI Act register
  completeness, literacy posture, framework metadata) wrapped around the
  signed, externally verifiable assurance pack and bound to it by digest.
  Rides enabled modules; absent ones degrade to `enabled: false`. Never an
  insurance application, rating, or representation to any insurer.
- **GPAI provider obligations register** (in `eu_conformity`,
  `maverick eu-conformity gpai`, `/governance/gpai`) — Art. 53(1)(a)-(d)
  evidence tracking per general-purpose model, the Art. 55(1)(a)-(d)
  additions for systemic-risk models, and the Art. 53(2) open-source
  exemption applied only where the law allows (never to systemic risk,
  never to the copyright policy or training-content summary).
- **Independent FRIA review (four-eyes)** — a completed FRIA accepts a
  concur/objections review only from a reviewer other than the assessor;
  objections are recorded and the Art. 27(2) reopen path stays the only
  way content changes.
- **Asset dependency graph** (`model_risk_assurance.dependency_graph`,
  `GET /assurance/model-risk/dependency-graph`) — nodes and dependency
  edges over the governed inventory, whole-estate or scoped to one asset's
  direct neighbourhood.
- **California ADMT & risk-assessment readiness template** (in
  `assessment.py`) — the finalized CPPA CCPA regulations (OAL-approved
  2025-09-23): the ADMT significant-decision inventory, the enumerated
  pre-use notice, the opt-out and its two exceptions, plain-language
  access responses, the five risk-assessment triggers (including
  TRAINING ADMT/biometric technologies, required since 2026-01-01), the
  April 1 CPPA submission calendar, and the staggered cybersecurity-audit
  certifications. Regulation text verified before drafting.
- **Governance workspace panels for the per-model registers** — the GPAI
  (Art. 53/55) and deployer (Art. 26) registers have screens on
  `/security/governance`: open a register, record evidence per duty, and
  assign named human oversight (the page renders UNASSIGNED in red until
  people are named). The `/privacy` workspace gains contracts & renewals
  (with overdue/due-soon badges), privacy-notice publishing with the
  coverage badge, the one-click site scan, and an Estate worksheet
  button on every DSAR row.
- **OSCAL assessment-results export** (`assessment_exports.py`,
  `maverick exports oscal`) — any saved assessment as an OSCAL 1.1.2
  ``assessment-results`` JSON document: one observation per answered
  question, findings with honest satisfied/not-satisfied targets, and a
  deterministic rendering for an unchanged record. A minimal,
  self-assessment OSCAL profile — stated, and never a certification.
- **Statement of Applicability generator** (`maverick exports soa`) —
  control-style assessments (ISO 42001/27001, SOC 2, ...) render as the
  SoA a certification audit starts from: per-control applicability
  (``na`` answers become justified exclusions), implementation status,
  and the assessor's notes, as markdown or JSON.
- **CycloneDX ML-BOM export** (`ai_bom.py`, `maverick exports ai-bom`) —
  the governed inventory as a CycloneDX 1.6 bill of materials: model
  components typed ``machine-learning-model`` with full SHA-256 version
  digests, datasets typed ``data``, dependency edges resolved back to
  governed asset ids, and a deterministic serial number for an unchanged
  estate.
- **Gateway prompt screening** (`[llm_gateway] screen_prompts`) — the
  in-kernel deny-wins detector ensemble (injection, exfiltration, PII)
  screens chat-completion messages before they leave: a firing
  detector blocks with named reason codes and ledgers as
  ``screened_blocked``; the screen itself fails open if it errors, and
  never stores content.
- **OpenTelemetry GenAI ingestion** (`POST /gateway/v1/otel`) — point
  any OTel collector at the gateway (same bearer): spans carrying the
  GenAI semantic conventions (``gen_ai.system``, ``gen_ai.request.model``,
  token usage) aggregate into the shadow-caller ledger per service and
  model. Any agent framework's standard traces become governed telemetry
  without an SDK; prompts and completions are never read.
- **Art. 26 deployer-obligations register** (in `eu_conformity`,
  `maverick eu-conformity deployer`, `/governance/deployer`) — the EU AI
  Act's deployer side made trackable: the always-applicable duties
  (use-per-IFU 26(1), monitoring and incident escalation 26(5), the
  ≥6-month log-retention duty 26(6), informing affected persons 26(11),
  authority cooperation 26(12)) plus flag-conditional duties
  (input-data control 26(4), workplace worker-information 26(7),
  public-authority registration checks 26(8), the DPIA information duty
  26(9)). Art. 26(2) human oversight is deliberately un-assertable with
  a bare reference — it must name natural persons. The 26(10)
  law-enforcement biometric regime is out of scope and stated so.
- **US AI-law and multi-state privacy templates** (in `assessment.py`) —
  Colorado's replacement ADMT Act (SB 26-189, eff. 2027-01-01: developer
  documentation, pre-decision and 30-day adverse-decision disclosures,
  correction and human-review rights, 3-year records), NYC Local Law 144
  (annual independent bias audit, published impact ratios, 10-business-day
  notices), Texas TRAIGA (intent-based prohibited practices,
  government-context disclosure), Illinois HB 3773 (discriminatory-effect
  testing, the zip-code proxy ban, IDHR notice), and a 20-state US
  privacy applicability/readiness questionnaire. Statute status verified
  against live sources before drafting (including SB 24-205's repeal).
- **ISO/IEC 42001 AIMS readiness template** (in `assessment.py`,
  security department) — the clause 4-10 management loop and Annex A
  control themes as original outcome paraphrases; no standards text
  reproduced.
- **Vendor questionnaire auto-scoring and the public questionnaire page**
  — hosted-form submissions score deterministically against the
  template's risk answers (per-question findings, worst-severity rating,
  "clear" when everything answered came back safe), and the minted
  `/form/{token}` link renders a public questionnaire page the vendor
  answers in the browser; questionnaire tokens stay answerable even when
  automation events are off.
- **Vendor contract renewal tracking** (`maverick vendor contract`,
  `/api/v1/vendors/{id}/contracts`) — one current contract per kind
  (DPA/MSA/SLA/addendum) with its renewal date; the governance-alerts
  digest, CLI, and workspace chips surface contracts past renewal
  and renewing soon, alongside new data-map attention chips for flagged
  assets not yet linked to a governing record.
- **Privacy notice register** (in `consent_registry`, `maverick consent
  notice`, `/api/v1/consent/notices`) — immutable, digest-bound notice
  versions that consent receipts' `policy_version` resolves to, with a
  coverage check that names any receipt version the register cannot
  produce.
- **First-party site scan** (`maverick consent scan-site`,
  `/api/v1/consent/site-scan`) — one bounded, SSRF-pinned,
  egress-guarded fetch of the operator's own page reporting Set-Cookie
  attributes, third-party script/iframe/img hosts, and well-known
  trackers. Header- and markup-level on a single page — not a crawler,
  not a browser, never a CMP.
- **DSAR estate worksheet** (`maverick dsar worksheet`,
  `GET /api/v1/privacy/dsar/{id}/estate-worksheet`) — the human search
  plan beyond the platform's own holdings: platform export counts, the
  data-map assets whose flagged columns identify people, active vendors
  as processors to contact, and a bounded connected-source document
  search; absent modules degrade to `enabled: false`.
- **Fairness metrics as governed evidence** (`maverick explainability
  fairness`, `record_fairness_evidence`) — the existing four-fifths /
  demographic-parity / equal-opportunity monitor records
  digest-scoped `fairness` evidence against a governed asset, honestly:
  a failing report records as FAILED evidence, never suppressed. A
  screening record, not a fairness certification.
- **LGPD and PIPEDA assessment templates** (in `assessment.py`) — Brazil's
  LGPD (legal bases Arts. 7/11, subject rights Art. 18, security/incident
  Arts. 46/48, DPO Art. 41, transfers Art. 33) and Canada's PIPEDA (fair
  information principles, valid-consent s.6.1, breach-of-safeguards
  s.10.1) join the questionnaire chassis; both surface in the dashboard's
  privacy department. Structured self-assessment, never legal advice.
- **ISO/IEC 27701 PIMS readiness template** (`iso27701` in
  `assessment.py`) — privacy-information-management readiness on top of
  an ISO 27001 ISMS: scope and controller/processor roles, PII
  inventory, legal basis and consent, data-subject requests, processor
  contracts, transfers, privacy by design, breach response, retention,
  awareness, the management-system loop, and the SoA. Original
  paraphrases; completing it is not certification.
- **Third-party vendor register** (`vendor_management.py`, opt-in
  `[vendor_management] enable`, `maverick vendor`, `/api/v1/vendors`) —
  governed vendor records with criticality tiers and lifecycle status,
  hosted-form questionnaire campaigns over the public `/form/{token}`
  endpoint (any registered assessment template, responses read back
  in-place), monitoring notes, links to DPA/paper reviews and
  assessments, a posture rollup, and a OneTrust third-party CSV importer
  that never overwrites a vendor already registered here. A register and
  audit trail, never a vendor risk rating service.
- **Indexed vendor questionnaire lookup** (`governed_record_lookup.py`,
  `governed_record_lookup_pg.py`) — maintained token-digest projections with
  current canonical revision/association checks, bounded resumable backfill,
  atomic Postgres updates and local crash recovery. Existing vendor feature
  admission applies. See [migration and recovery](vendor-questionnaire-index.md).
- **Consent receipts and preferences registry** (`consent_registry.py`,
  opt-in `[consent_registry] enable` + `subject_salt`, `maverick
  consent`, `/api/v1/consent/*`) — per-subject, per-purpose consent
  events (status, policy version, channel) with salted one-way subject
  digests, self-checking per-event receipt hashes, a current-preference
  projection, bounded audit export, a OneTrust consent CSV importer, and
  a signed consent WEBHOOK (`POST /consent/webhook`, opt-in
  `webhook_enable` + an HMAC secret from the environment variable named
  by `webhook_secret_env`) so any CMP can push events into the durable
  record — backdated pushes can never flip a newer withdrawal. The
  governed record behind a consent front end — never a cookie banner,
  IAB TCF CMP, or preference-center UI, and stated so.
- **Data map and discovery** (`data_map.py`, opt-in `[data_map] enable`,
  `maverick data-map`, `/api/v1/data-map/*`) — a governed register of
  data assets with a pure-Python column-name classifier (email, phone,
  national id, date of birth, health, financial, credentials, and more;
  health marks the asset special-category), a warehouse
  `information_schema.columns` CSV importer (stock Snowflake/BigQuery/
  Redshift/Postgres exports), a bounded SharePoint site census via
  Microsoft Graph (`Sites.Read.All`, SSRF-pinned, egress-guarded), links
  from assets to the RoPA/assessment/vendor records that govern them,
  and an unlinked-flagged-assets posture signal. On top of the
  name-based triage, a deterministic CONTENT classifier
  (`content_classifier.py`, `maverick data-map classify-content`,
  `POST /api/v1/data-map/assets/{id}/classify-content`) verifies real
  data samples with recomputable checks — Luhn for payment cards, mod-97
  for IBANs, SSA structural rules for SSNs, octet-validated IPs,
  context-gated DOB/ICD-10 — recording `content_categories` beside the
  name-suggested ones (an auditor can recompute every finding; no ML
  scores). A Snowflake masking-policy DDL exporter (`maverick data-map
  masking-sql`, `GET /api/v1/data-map/masking-sql`) turns flagged
  columns into reviewable `CREATE MASKING POLICY`/`ALTER TABLE` SQL —
  emitted, never executed. Live file scanning closes the sample-only
  gap: `maverick data-map scan-sharepoint-files` lists a site's document
  library through Graph (`Files.Read.All`) and runs the classifier over
  bounded samples of the formats the platform reads **with the stdlib
  alone** — plain text plus docx/xlsx/pptx OOXML parts and untrusted PDF
  content streams — recording EVIDENCE (per-category counts and which
  file NAMES were flagged), never a byte of content. Item ids that could
  smuggle path segments are refused, and an unreadable container (a
  scanned PDF, an encrypted or bomb-shaped archive) counts as SKIPPED so
  the record never implies coverage the scan did not have. Sampling and
  emission, never a crawler.
- **Deterministic text redaction** (`redaction.py`) — replaces the
  content classifier's validated findings with typed placeholders
  (`[REDACTED:email]`); span-exact, idempotent on its own output, text
  only by design (no OCR — a dependency decision, not a drive-by). Used
  by the DSAR response path to scrub third-party identifiers.
- **Legal holds and matter export** (`ediscovery.py`, `ediscovery_export.py`,
  opt-in `[ediscovery] enable`, `/api/v1/ediscovery/matters`; the Legal holds section
  on Compliance) — tenant-scoped matters over custodians, dates and record types.
  While one is active, bulk deletion pauses for the workspace and in-scope erasure is
  refused with a plain message. Export is a streamed ZIP with per-type JSONL, a signed
  manifest and offline verification. See `docs/EDISCOVERY_LEGAL_HOLDS.md`.
- **Breach-notification planner** (`breach_notification.py`, opt-in
  `[breach_notification] enable`, `maverick breach`,
  `POST /api/v1/breach/plan`,
  `GET /api/v1/privacy/incidents/{id}/notification-plan`) — fifteen
  regimes' verified who/when/whether rules (GDPR/UK 72h; HIPAA 60d with
  the 500 split; CA/TX/CO/FL/NY state clocks; LGPD 3 business days per
  ANPD Res. 15/2024; PIPEDA RROSH; Quebec Law 25; Australia NDB 30-day assessment;
  Singapore 3-day post-determination; Japan two-stage 30/60d; Korea 72h)
  turned into per-incident obligations with computed due timestamps,
  threshold notes, and citations. Weekend-aware business-day math
  (holidays excluded, stated); unverified regimes are absent by design,
  named in the refusal. Four regimes also carry the statutory element
  list a notice must CONTAIN, each with its citation (GDPR Art. 33(3),
  HIPAA 164.404(c)(1), Cal. Civ. Code 1798.82(d) including the required
  "Notice of Data Breach" headings). Time-sensitive legal content is
  ratcheted: `python -m maverick.deprecations --ci` fails the build once
  a `VERIFIED_AT` stamp passes 270 days, so an encoded deadline cannot
  quietly rot. Decision support for counsel, never legal advice;
  nothing is transmitted.
- **DSAR fulfillment pipeline** (`dsar_fulfillment.py`, opt-in
  `[dsar_fulfillment] enable`, `maverick dsar-fulfill`,
  `/api/v1/privacy/dsar/*/fulfillment*`, public
  `GET /dsar/response/{token}`) — executes a subject request as a
  governed pipeline: a named human records HOW identity was verified
  (fixed method vocabulary), collection sources are logged toward a
  completeness record, and the response ships through a token-gated link
  (token stored only as a SHA-256 digest, with expiry) assembled at
  delivery time from the live stores — no second copy of personal data
  is persisted — with third-party identifiers scrubbed by the
  deterministic redactor, the subject's own reference preserved.
  Slim Microsoft 365 collection (`maverick dsar-fulfill collect-graph`)
  counts the subject's mailbox and drive footprint (`$select=id`,
  `Mail.ReadBasic.All` + `Files.Read.All`) and logs each probe as a
  collection source while moving NO content; a subject that is not a
  userPrincipalName is refused rather than guessed at, and a missing
  mailbox is recorded as a finding, not a crash.
- **Governance needs-attention digest** (`governance_alerts.py`,
  `maverick governance-alerts due`, `GET /api/v1/security/governance/alerts`)
  — one bounded read-side digest of what compliance must act on: Art. 73
  clocks overdue or due soon, Art. 4 literacy gaps (missing, expired,
  expiring soon), Art. 27(2) outdated FRIAs, and Art. 43(4) routes flagged
  for reassessment. No knob of its own — each section rides its source
  module's opt-in and degrades to ``enabled: false``. The CLI exits non-zero
  when anything needs attention, so an operator cron can wrap it with their
  own delivery channel; the platform itself transmits nothing.
- **Signed AI policy packs** (`policy_packs.py`, opt-in `[policy_packs]
  enable`) — bounded NIST AI RMF and EU AI Act starter mappings plus
  Ed25519-verified external updates, anti-rollback staging, explicit global
  admin activation, tenant-local subscriptions, exact evidence attestations,
  requirement diffs, and stale/missing/current counts. Catalog/channel reads
  expose metadata-only projections; subscription operations fail without an
  active tenant. Packs are advisory control mappings, not certification,
  conformity assessment, standards-text redistribution, or legal advice.
- **Operational AI policy management** (`ai_policy_management.py`, assurance
  API/cockpit, opt-in `[ai_policy_management] enable`) — tenant-scoped,
  immutable policy versions with human CAS activation; exact applicability
  over risk, jurisdiction, data, deployment, asset and use-case context;
  strictest-wins allow/review/restrict/prohibit decisions; four-eyes scoped
  exceptions pinned to an exact policy version/digest; expiry and explicit
  closeout; and evaluation attestations that become visibly stale when policy
  or exception authority changes. No-match defaults to human review. This is
  operational decision support, not certification or legal advice.
- **Explainable dynamic AI risk** (`ai_dynamic_risk.py`, assurance API/cockpit,
  opt-in `[ai_dynamic_risk] enable`) — exact Model Risk asset/version-bound
  quality, safety, drift, performance, policy, privacy and security signals;
  freshness and CAS resolution/supersession; deterministic category weights
  plus strict business/regulatory context floors; attributable score/tier
  changes; exclusions; stale-snapshot detection; and bounded trend history.
  The store admits normalized metadata and evidence digests, never raw prompt,
  output, feature-row, or provider telemetry payloads. Production calibration
  and live telemetry coverage remain deployment responsibilities.
- **Runtime AI policy enforcement** (`ai_runtime_guardrails.py`, authenticated
  external evaluate/execute routes, opt-in `[ai_runtime_guardrails] enable`) —
  composes operational policy, Shield, secret/PII inspection and exact approved
  asset context into allow/review/restrict/block decisions. Raw prompt and
  output content stays transient; durable receipts are digest-only and feed
  normalized violations into dynamic risk. The dashboard tests exercise the
  authenticated evaluate and execute routes for allow/deny, preview and
  enforced no-change, human approval, exactly-once commit, indeterminate
  after-effect outages and separately approved compensation against a local
  connector; a live third-party gateway, agent, MCP or Copilot deployment is
  not tested.
- **AI explanation review** (`ai_explainability.py`, assurance API/cockpit,
  opt-in `[ai_explainability] enable`) — admits closed native, SHAP, LIME,
  Captum, Alibi and counterfactual explanation receipts with exact model/input
  provenance, safe feature projections, revision-CAS review and independent
  approval. Provider adapters and adverse-action or legal acceptance are not
  implied.
- **AI vendor diligence and response portal** (`ai_vendor_risk.py`,
  `ai_vendor_portal.py`, assurance and external APIs/cockpit, opt-in
  `[ai_vendor_risk] enable` plus `portal_enable`) — AI-specific questionnaires,
  bounded cited document extraction, approved-prior and vendor-attested answer
  precedence, deterministic scoring, independent review and approved evidence
  projection. The tenant-scoped portal returns an opaque invitation credential
  once, stores only its hash, supports expiry/revocation and idempotent response,
  binds the exact questionnaire, requires explicit vendor attestation and
  imports submissions as pending human review. Raw documents are not persisted.
  Live document/vendor and ecosystem acceptance do not ship.
- **AI regulatory-impact bridge and Article 73 incidents**
  (`ai_regulatory_feed.py`, `eu_ai_incidents.py`, assurance API/cockpit,
  opt-in feature sections) — maps reviewed regulatory changes to exact affected
  assets and stale evidence, and provides human-owned serious-incident triage,
  2/10/15-day clocks, four-eyes report approval and receipt recording. Current
  licensed feeds, legal determinations, authority directories and filing
  transmitters remain external.
- **Business AI intake and literacy register** (`ai_business_intake.py`,
  `ai_literacy.py`, assurance API/cockpit, opt-in feature sections) — short
  intake creates or links governed inventory, declarations and review work;
  role requirements, pseudonymous assignments, completion receipts, waivers,
  gaps and evidence exports make literacy status auditable. Fresh-user timing,
  HRIS and LMS acceptance remain deployment work.
- **EU conformity-readiness workspace** (`ai_conformity_workflow.py`, assurance
  API/cockpit, opt-in `[ai_conformity_workflow] enable`) — governed FRIA,
  Annex IV, Article 43 route, post-market, declaration and CE-readiness
  checklist/evidence lifecycle. It does not make legal determinations, certify
  a system, sign a declaration or affix a CE mark.
- **Governed GRC outbound synchronization** (`grc_outbound_sync.py`,
  `grc_vendor_transports.py`, assurance API/cockpit, opt-in `[grc_outbound_sync]
  enable`) — semantic, idempotent ServiceNow IRM and Archer preview/execute,
  exact payload and source bindings, conflict handling and durable receipts.
  Live vendor-sandbox acceptance and additional GRC targets remain external.
- **Enterprise AI cost and assumption-labelled ROI** (`ai_cost_collectors.py`,
  `ai_cost_openai.py`, `ai_cost_roi.py`, `ai_cost_scheduler.py`, assurance
  API/cockpit, opt-in feature sections) — bounded AWS, Azure, GCP and OpenAI
  organization-cost collection, citations, allocation/correction history and
  owner/department reporting. Live billing credentials were not exercised;
  model-level OpenAI cost allocation is not invented from the Costs contract.
- **Bounded provider-contract acceptance harness**
  (`packages/maverick-dashboard/maverick_dashboard/provider_contract_acceptance.py`,
  `scripts/acceptance/run_ai_provider_contracts.py`) — a closed-schema,
  consent-gated runner for one Hugging Face namespace, one Entra tenant, one
  deterministic ServiceNow finding write plus exact replay, and one bounded
  OpenAI organization-Costs window. ServiceNow mutation requires an exact match
  against a closed `write_origin_allowlist`; hostname markers and the declared
  test/dev/sandbox environment cannot grant write authority. Readiness-only mode
  performs no provider I/O; secret values and response bodies are excluded from
  evidence. The working-tree readiness run is blocked on four unavailable
  credentials and therefore proves fail-closed wiring, not any live provider
  contract.
- **AI insurability evidence packets** (`ai_insurability.py`, assurance
  API/cockpit, opt-in `[ai_insurability] enable`) — exact-evidence profile
  versions, measurements, limitations, verifier guidance and four-eyes export.
  Coverage, underwriting, pricing and insurer acceptance are external outcomes.
- **Media provenance control plane** (`ai_media_provenance.py`,
  `ai_media_provenance_c2pa.py`, assurance API/cockpit, opt-in
  `[ai_media_provenance] enable`) — typed C2PA interfaces plus a concrete
  optional verifier/signer backed by the official `c2patool` CLI, with bounded
  process I/O, protected transient workspaces, strict report normalization,
  digest-only receipts, exact asset/deployment/context bindings and four-eyes
  release. `verification_adapter = "c2patool"` explicitly selects the verifier
  only when `c2patool_executable_sha256` supplies the independently reviewed
  executable digest. The tool must be a bounded regular non-symlink file; its
  identity and digest are revalidated after version admission and immediately
  before every verify or sign launch. The acceptance script has been exercised
  against separately installed `c2patool` 0.27.16 with public development
  fixtures. The production
  `C2PAToolExternalSigner` delegates claim signing to a fixed KMS/HSM signer
  subprocess so Lightwork never holds the private key. That signer executable
  has its own independent SHA-256 and identity pin; neither pin substitutes for
  deployment ownership, ACL and parent-directory controls. Development-fixture
  interoperability is not production custody or relying-party acceptance; see
  `docs/security/c2pa-signing-custody.md`.
- **Voluntary benchmark exchange** (`ai_benchmark_exchange.py`,
  `ai_benchmark_exchange_transport.py`, assurance API/cockpit, opt-in
  `[ai_benchmark_exchange] enable`) — aggregate-only, pseudonymous contribution
  packages, exact methodology/revision binding, four-eyes export, versioned
  Ed25519 report-trust roots with rotation/revocation, and an explicitly enabled
  fixed-origin HTTPS coordinator client with bounded transport, idempotent
  submission and literal manual consent. The default remains local
  and durable mutations are copy-on-write under a separately bounded state-file
  ceiling. No live cross-tenant network, anonymity/DP guarantee, privacy-budget
  accounting or participant acceptance is implied.
- **Discovery sensor control plane and signed ingress**
  (`ai_discovery_sensors.py`, `ai_discovery_sensor_clients.py`,
  `ai_discovery_sensor_agents.py`, assurance and external APIs/cockpit, opt-in
  `[ai_discovery_sensors] enable`) — registers,
  approves, configures and revokes browser-extension, network-egress,
  OAuth-grant, SaaS-posture, identity-directory and data-catalog sensors and
  accepts bounded normalized observations. The external route admits only
  tenant-scoped Ed25519 machine envelopes with exact sensor/configuration
  binding and durable replay protection. Deployable consent-gated JSONL agents
  for network-egress, browser-extension and OAuth audit events use fixed-origin
  delivery, hot key reload, a private normalized-only SQLite spool, bounded
  retries and recovery. A consenting local estate exercises rotation,
  revocation, privacy checks, ambiguous delivery, concurrency and 1,000-event
  scale while explicitly reporting incomplete coverage. Production source
  adapters, the other three sensor classes and enterprise completeness/privacy/
  scale acceptance are not included.
- **Identity and data-governance discovery adapters**
  (`ai_identity_governance_connectors.py`, `identity_governance_runtime.py`,
  `identity_governance_scheduler.py`, assurance API/cockpit, opt-in
  `[ai_identity_governance_connectors] enable`) — bounded, read-only Entra,
  Okta and Purview collection through pinned-host, redirect-disabled enterprise
  egress, with pseudonymous normalized snapshots. The separately opt-in
  scheduler uses per-provider CAS leases, bounded retry/backoff, digest-only
  history, bounded hash deltas and safe callbacks. Separately default-off
  controls add replay-safe risk/alert fanout, pseudonymous Entra/Okta
  agent-principal federation contracts backed by an independently injected
  enrolled subject-binding resolver (caller-supplied subject pseudonyms are
  exact-match assertions only), identity-to-capability mapping, fresh
  conditional-access decisions and Purview compare-and-swap writeback with
  compensation/recovery. These controls are configurable in the installer but
  remain unverified against live test tenants; live identity-provider policy,
  scheduler and ecosystem acceptance remain deployment work.
- **Regulated-industry decision-support packages**
  (`ai_regulated_verticals.py`, assurance API/cockpit, opt-in
  `[ai_regulated_verticals] enable`) — governed credit-reason, aggregate
  fair-lending interval, NYC Local Law 144 readiness and NAIC mapping packages.
  They do not issue individual decisions, legal conclusions, audits, filings,
  certifications or regulator approvals.
- **Bank model-risk package** (`ai_bank_mrm.py`, assurance API/cockpit, opt-in
  `[ai_bank_mrm] enable`) — nine closed review sections with explicit
  missing/unverified states, exact evidence, revision-CAS lifecycle and
  four-eyes package-integrity approval. It does not approve a model or establish
  bank, examiner or regulator acceptance.
- **Governed external red-team campaigns** (`red_team_assurance.py`, external
  gateway + assurance cockpit, opt-in `[red_team_assurance] enable`) — an
  actively enrolled inbound agent pulls deterministic synthetic probes for an
  operator-attested isolated non-production target. Each campaign binds the
  observed target digest, current deterministic evaluator implementation and
  suite, agent credential version, rules of engagement, and a
  campaign/case/tenant-domain-separated keyed response-commitment scheme.
  Raw responses, tool arguments, and tool names stay transient; any declared
  tool call fails and an unavailable trace is inconclusive. Finalization is a
  recoverable CAS transition that emits review-pending Model Risk evidence;
  approval requires a different human from the producer, and the cockpit has
  explicit finalize, force-incomplete, and stop-new-work controls. The
  installer provisions `MAVERICK_RED_TEAM_COMMITMENT_KEY` in its private
  `.env`; non-wizard deployments must supply a secret of at least 32 bytes.
  This is bounded lexical assurance with a runner-attested target digest, not a
  certification. Governed schedules, due-slot leases, per-case leases,
  cancellation, dispatcher recovery, matched-pair synthetic bias probes,
  refusal floors, and bounded remediation recommendations are included. A live
  enrolled-agent end-to-end and proof against hidden target-runtime side
  effects remain deployment acceptance work.
- **AI Evidence-Ready Gateway** (`ai_evidence_gateway.py`, the existing
  `/security/assurance` cockpit, opt-in `[evidence_gateway] enable`) -
  deterministic text-delivery disclosures, machine-readable markings,
  idempotent hash-only interaction receipts, policy/model/context bindings,
  cited regulatory-impact review, and exact signed JSON assurance packets.
  It stores no raw prompt or generated response in its receipt ledger and makes
  no certification claim. Packet issuance is a bounded, admin-only mutation
  with a completeness manifest and source-snapshot recheck. The synthetic
  dashboard seed performs no network access, requires an empty/dedicated demo
  tenant, and forces a visible readiness gap. See
  [`AI_EVIDENCE_GATEWAY.md`](./AI_EVIDENCE_GATEWAY.md) and the
  [governance benchmark report](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/benchmarks/GOVERNANCE_FRONTIER_RESULTS.md).
  Runtime delivery consumers use the `maverick.ai_evidence.delivery` boundary;
  the `maverick.ai_evidence_gateway` import remains supported.
- **Four reduced standalone security agents** (`demo/grc-concierge/`,
  `demo/platform-threat-hunter/`, `demo/environment-threat-hunter/`,
  `demo/model-risk-ai-assurance-officer/`) — each has
  an explicit standalone capability layer, backend seam, vendored
  engine that imports no `maverick` code in forced mode, launcher, accessible
  UI, `/about` capability matrix, and focused isolation tests. GRC keeps a
  local unsigned starter catalog/risk/POA&M store; both hunters persist derived
  records only; Model Risk keeps declared metadata, local human decisions, and
  non-executing DGM readiness reports. They do not claim the platform's signed
  audit, governed
  approvals, managed connectors, or cross-run learning. Both hunters are
  proposal-only; response execution is exclusive to the integrated platform's
  exact approval-bound, explicitly enabled executor seam.
- **Savings dashboard** (`savings.py`, `maverick savings`, dashboard
  `/savings` + `/api/v1/savings`) — money saved vs the typical human cost,
  from real completed work and the CLIENT's own inputs: fully-loaded human
  hourly rate × human hours per task (global + per-department overrides,
  `[value]` in config), editable right on the page and persisted via the
  dashboard overlay. Savings = human cost − actual agent spend, plus ROI
  and hours given back. Read-only over the same episode ledger as Spend;
  zeros (never invented numbers) until goals have run.
- **Outcome and delivered-cost evidence** (`outcome_accounting.py`,
  `outcome_value_reporting.py`, dashboard `/outcome-pilots` +
  `/api/v1/outcome-accounting`) — keeps every admitted pilot case in the
  accepted, rejected, failed, cancelled, or unresolved denominator and exposes
  its outcome, timestamps, provider attempts, review/setup/support/rework and
  exception costs, allocation assumptions, corrections, and evidence basis in
  the app and a bounded JSON export. Baseline cost and human-time evidence stay
  visibly observed, estimated, or unknown; net savings and ROI are withheld
  when the comparison is incomplete. Renewal and expansion evidence remains
  separate from operating savings. Operator-recorded evidence is identified as
  such until customer qualification supplies measured baseline and effort.
- **Autonomous Shoring** (`shoring.py`, dashboard `/shoring` +
  `/api/v1/shoring`; `[shoring] enable`, `MAVERICK_SHORING`) — the engagement
  tooling for moving a whole business function onto the workforce: a tenant-
  scoped **Book of Work** (each function mapped to an operating department,
  with a scope, an owner, target service levels, and a lifecycle in
  {scoping, demonstrating, running, proving}), an **SLA view** measuring
  target-vs-actual (throughput/day, exception rate %) from real completed work
  in the Operating Record with a met/at-risk/breached indicator, and an
  **exception desk** — the pending human sign-offs filtered to each function's
  department, the same queue behind `/approvals` seen through the shoring lens.
  The Shoring P&L is the Savings report above. Read-only over existing stores;
  the book is a small governed JSON store, not a world-model migration.
  SQLite/Postgres measurements aggregate all department goals without sampling.
  Turnaround uses the recorded completion time and remains stable after later
  edits; historical goals without that timestamp remain explicitly unmeasured.
  Exception attribution uses the approval's originating goal/department, with
  unattributed approvals shown as a shared queue rather than guessed from text.
  Book edits are serialized across processes; capacity (500 functions) and
  corrupt records cause an explicit refusal, preserving the saved book.
- **2,031-agent specialist portfolio across 54 suites** — the original 8
  business suites plus customer experience, marketing, procurement,
  data & analytics, security ops, executive office, facilities/EHS, tax
  preparation, commerce (shopper + merchant agents), and 30+ industry
  verticals (healthcare, insurance, banking,
  retail, manufacturing, construction, logistics, professional services,
  government contracting, education/nonprofit), with jurisdiction packs
  (country employment law, GDPR/CCPA/PIPL/EU-AI-Act regimes, indirect-tax
  regimes). Quality gate: `maverick domains-lint [--ci]` — every pack has
  a bounded persona, least-privilege allow list, explicit deny list, and
  risk ceiling; 0 errors, 0 warnings across all 2,031.
- **Tax preparation pipeline** (`tax_prep.py`, `maverick tax prepare
  <docs-dir>`; the 19-pack `tax_` suite) — a CPA firm's docs-to-draft
  workflow: uploaded client documents are classified and extracted
  deterministically (W-2 / the 1099 family incl. R/B/G/SSA / K-1 /
  1098/-T/-E / prior returns), assembled into a standardized workpaper, and
  computed into a first-pass TY2025 draft 1040 **plus the resident-state
  return** (auto-detected from W-2 box 15; no-tax and flat-rate states
  computed, graduated states explicitly handed to the preparer/tax engine)
  where **every line cites its source document** and everything out of
  computed scope (Schedule C/D/E, itemizing, benefit taxability) is an
  explicit OPEN ITEM. Agents do the unstructured labor (chasing,
  extraction, client comms — all drafts); the module does the provable
  math; the credentialed preparer reviews, completes, and signs in the
  firm's professional tax engine — reachable via the **CCH Axcess and
  Thomson Reuters GoSystem connectors** (write seats confirm-gated and
  high-risk; GET-only low-risk read seats wired into the status packs).
  Never files anything.
- **Signed tax-constants channel** (`tax_constants.py`, `maverick tax
  update [--file|--status|--rollback]`; `[tax]` config) — new tax law
  ships as a **content release, not a code release**: Ed25519-signed
  constants bundles verified fail-closed against `[tax]
  trusted_constants_pubkeys` (no TOFU), sanity-validated before they can
  replace the tables (rates in range, ascending brackets, real state
  codes), downgrade-protected, applied atomically with the previous
  bundle kept for `--rollback`, and audited. With `auto_update` +
  `update_url` configured, `maverick tax prepare` picks up a published
  law change automatically (throttled); air-gapped firms apply the same
  bundle from a file. Every review package states the constants revision
  that computed it, and the `tax_law_watch` pack (web access, NO
  client-data access — the inverse seal of the rest of the suite)
  monitors IRS/state guidance and alerts the firm; agents never edit
  constants directly.
- **Commerce suite — governed shopper and merchant agents** (`commerce.py`,
  `tools/commerce_tools.py`; the `com_` suite: `com_shop_*` search & compare,
  cart builder, product Q&A, order tracking & returns, preference memory;
  `com_merch_*` analytics, inventory, pricing, promotions, listing quality,
  order ops; opt-in `[commerce] enable` / `MAVERICK_COMMERCE`, wizard step)
  — the design of Anthropic's Apache-2.0 `commerce-agents` reference brought
  under Lightwork governance. `StorefrontBackend` (search / product / cart
  add-remove-view / cart link / own orders / return policy) and
  `MerchantBackend` (catalog / inventory / pricing / orders / analytics /
  campaigns reads + one `apply_change` for APPROVED changes) are abstract
  interfaces with an in-memory `DemoBackend`; a real storefront plugs in via
  `register_backend`. The safety rules live in the module, not the prompts:
  **per-session caps** (cart subtotal, per-line quantity, cart size — a
  refused add is final), a **provenance gate** (every product fact carries
  `source` + `fetched_at` or is rejected), **staged writes** (a price /
  inventory / listing / campaign / order-resolution / return proposal is
  recorded in a ledger and applied only with the human-path approval token,
  never by the proposing agent, and never by an `agent:` principal), and a
  **checkout handoff** that returns an opaque cart reference plus a
  scheme-host-path cart link — query strings, fragments, and anything naming
  the checkout/payment step are stripped or refused, so the agent never sees
  a card, an address, or the checkout URL. Shopper packs are fenced to the
  storefront (web search and browser denied); every `com_` pack is STRICT
  autonomy and carries the commerce refusals (no payment handling, no store
  writes, no unsourced product claims).
- **Institutional Memory attestation — is it really compounding, and really
  yours?** (`memory_plane.py`, `maverick memory-plane compounding|export|verify`)
  — the `attest` half of the fleet-memory ingest/recall/attest API, using the
  **same signed bundle format as the attestation bundle** (`attestation.py`;
  one implementation of the
  crypto, the out-of-band trust anchor, and the
  HOLDS/FAILS/INDETERMINATE/NOT_APPLICABLE vocabulary). Three claims:
  **cross_vendor** — how many vendors actually deposited through the governed
  plane, graded `NOT_APPLICABLE` below two because one vendor has demonstrated
  nothing, and `FAILS` outright if any ingest cannot be attributed to a
  `vendor:agent_id`; **compounding** — the cold-vs-warm cost and reliability
  curve *per department* (`compounding_by_department`), `INDETERMINATE` below
  the run floor because a short curve is noise, and an honest `FAILS` when the
  plane is running and has not yet paid off; **tenant_isolation** — deliberately
  `NOT_APPLICABLE`, because every record in a bundle is under that tenant's root
  by construction, so isolation is established by comparing two tenants' bundles
  rather than by reading one. Activity counts come from the **signed audit
  chain**, not the inbox directory: `ingest` routes a lesson into the reflexion
  store and only success/failure records into the inbox, so an inbox count would
  miss exactly the cross-vendor lessons the plane exists for.
- **Fleet memory — the Learning System of Record** (`fleet_memory.py`,
  opt-in `[fleet_memory] enable`; MCP tools `maverick_fleet_ingest` /
  `maverick_fleet_recall`; CLI `maverick fleet-memory`) — ANY external agent
  (Agentforce, Copilot, custom, OSS runtimes) deposits experience into and
  recalls from Lightwork's governed memory: roster-gated (fail-closed),
  Shield-scanned, provenance-tagged (`vendor:agent_id`), tenant-isolated,
  every read audited. Successes/failures consolidate through the dream
  cycle; `maverick proof --fleet` breaks value out per vendor.
- **Current-rights Knowledge** (`knowledge_access.py`,
  `knowledge_content_projection.py`, dashboard `/knowledge-access`, default-on
  `[knowledge_access] enable` / `MAVERICK_KNOWLEDGE_ACCESS`) — a named-user,
  tenant-scoped search/detail/export and source-rights workflow over exact
  research dataset versions. Human display is a distinct `read` use: export or analysis
  authority may imply that narrower read, while training-only authority never
  does. Every direct read and cache hit re-resolves current purpose, requested
  action, approval, checksum, license/usage constraints, freshness, consent,
  and every parent with the same action. Search filters assigned
  sources before bounded lexical ranking, exposes incomplete/unavailable states,
  and supports revalidated continuation in the UI and agent tool. Agent evidence
  preserves claim state, dates, provenance and exact source versions. Exports carry
  a deterministic binding of the user authorization and exact source evidence.
  Correction, exclusion,
  and deletion requests preserve what reviewers saw, re-walk derivative state
  on every response, and expose crash recovery for an interrupted approval.
  Raw deletion is never described as erasing learned-weight influence. The
  production projector currently supports exact approved evidence-graph nodes
  and immutable fleet-memory inbox records; unsupported or mismatched stores
  fail closed. The purpose picker walks every authorized registry page and
  distinguishes unavailable from empty with retry. Operators can submit an
  exact visible source/version for independent administrator review and inspect
  their own limited status receipts; this grants no approval, deletion, hold or
  training authority. See [Governed Knowledge](knowledge-access.md).
- **Cortex — the company brain** (`cortex.py`, default-on `[cortex] enable`
  / `MAVERICK_CORTEX`; CLI `maverick cortex status|recall|deposit`; dashboard
  compatibility page `/cortex`; audit kinds `cortex_recall` / `cortex_deposit`) — ONE
  governed recall/deposit surface over the five memories the workforce
  already has: **knowledge** (the tenant's documents, with citations),
  **skills**, **self-harness lessons**, **the Operating Record** and
  **fleet memory**. Dashboard document recall is composed through Current-rights
  Knowledge and never falls back to the raw vector source; other Cortex clients
  must use the governed Knowledge API for documents. Each source keeps its own store, gates and semantics;
  Cortex adds what none of them had together: one query, one provenance
  envelope (source, kind, text, citation, score), one audit row per read
  across all of them and per write — who asked, which sources answered with
  how many hits, which were denied and why, a digest of the query and never
  the text — and the Agent Trust Plane applied uniformly, so an external
  caller is gated *before* any source is touched instead of only on the
  fleet path. Tenant-exact by construction (every read is floored to the
  active tenant and the result carries it); fail-open per source but never
  silently (a broken or disabled source is reported in `denied` with its
  reason); `status` reports what each source holds plus the encryption-at-
  rest and isolation posture an auditor asks about; `recall --context`
  renders the hits as the cited prompt block an agent receives. The tenant
  floor is enforced differently per store and is test-backed
  (`test_cortex_tenant_isolation.py`): the **Operating Record** rides the world
  model, so it is row-level-security-enforced on shared Postgres and a distinct
  per-tenant `world.db` on SQLite; **knowledge**, **skills** and the
  **self-harness lessons** file store scope by their `data_dir` directory (a
  different path per tenant); the opt-in shared-Postgres learning store
  (`[self_harness] store = "world"`) carries a `tenant_id` on every
  `harness_*` row and scopes every read/write to the active tenant, so a fleet
  of hosts can still learn as one *within* a tenant without pooling learning
  across tenants (`learning_store.py`, `test_learning_store_tenant_isolation.py`);
  **fleet memory** answers only enrolled external agents and is roster-gated.
- **The Operating Record** (`operating_record.py`, `maverick record
  stats|search|export|verify`) — the firm's decisions as a system of
  record: goals (with departments, outcomes, spend) + human approvals
  (with deciders) threaded into one queryable spine, exportable as an
  Ed25519-signed portable **capsule** (decision spine + learned state)
  verifiable offline; tampering fails verification. `maverick record verify`
  also requires the signing key to be trusted -- this installation's own audit
  keys by default, or the publisher's key via `--pubkey <hex>` /
  `--trusted-keys <file>` -- and rejects a capsule signed by any other key as
  "signed by an untrusted key" (printing that key's fingerprint), because the
  key embedded in a capsule proves nothing about who made it.
- **Portable attestation — provable to somebody who trusts nobody**
  (`attestation.py`, `attestation_verify.py`, `maverick attest
  key|export|verify|export-verifier`) — the capsule proves *integrity* but is
  self-certifying on its own: `verify_capsule_integrity` checks the signature
  with the public key stored inside the capsule, so it establishes that nobody
  edited the file and nothing about who signed it (`verify_capsule` adds the
  trusted-key requirement above). An attestation bundle goes further. It binds
  three claims to evidence a third party can re-derive — every recorded action
  stayed inside the declared governance envelope; self-improvement never widened
  its own authority; the decision history is intact and complete (per-day content
  digests, chain tips, the cross-file anchor ledger) — and **verification
  requires the publisher's key obtained out of band**, failing closed without
  one. Each claim reports `HOLDS` / `FAILS` / `INDETERMINATE` /
  `NOT_APPLICABLE`, and the last two are never softened into the first: an empty
  governance policy forbids nothing, so "no violations" is reported as
  inapplicable rather than as a pass, and a sealed-at-rest day-file is
  `INDETERMINATE` because nobody outside the tenant can walk its chain. Two
  depths: *signed* (authentic, claims as the issuer recorded them) and
  *corroborated* (`--evidence <audit-dir>`, claims re-derived from the raw
  files). A day-file still open at issuance is committed as a **prefix**, so
  ordinary later activity does not invalidate a bundle while an edit to the
  attested rows still does. `maverick attest export-verifier` writes the
  verifier out as a standalone program that imports nothing from maverick and
  needs only Python plus `cryptography` — the "hand a regulator a USB stick"
  path.
- **Trust receipts — bearer-verifiable evidence for one decision**
  (`trust_receipt.py`, `trust_receipt_verify.py`, `maverick attest receipt
  mint|verify|export-verifier`, dashboard **Audit → Trust Receipts** at
  `/audit/receipts`: pick a signed row, mint and download its receipt,
  optionally anchoring it through a checkpoint, download the standalone
  verifier, and verify a receipt against the deployment's keys or a pasted
  one — audit-gated end to end) — the unit below an attestation bundle: a
  portable artifact for a single signed audit row ("`wire_transfer` was denied
  under `deny_actions` for `agent:finance-1` at T", "`read_file` ran") that an
  auditor, regulator or a customer's customer verifies offline with a public key
  obtained out of band. An executed/failed tool claim is available only when a
  signed call and terminal-result row carry the same recomputed commitment;
  `execution_unknown` dispositions remain unknown even with a matching pair.
  The verifier rejects a v2 receipt that labels such a row as executed or
  failed; regenerate that receipt from the original signed rows.
  A call row on its own proves only a recorded dispatch attempt. The call row and
  its input summary are omitted by default and require the explicit bounded
  `--include-execution-pair` disclosure. The receipt always embeds the claim
  row; `--include-chain` additionally embeds every following row up to the tip,
  while the default signed-only receipt reports chain linkage indeterminate
  instead of implying that omitted evidence was checked. With
  `--checkpoint-dir`, the receipt can also carry the signed checkpoint that
  committed that tip. Verification re-derives all included evidence: the envelope
  signature, the row's own hash and signature, the **claim recomputed from the
  row** (a stated claim that drifts from the row FAILS, however validly it was
  re-signed), the hash links to the tip, and the checkpoint's agreement with
  it. Three depths that are not synonyms: *signed* (a genuine row), *chained*
  (provably linked to an issuer-committed tip), *anchored* (that commitment
  matched a digest the verifier retained OUTSIDE the receipt and supplies with
  `--anchor-digest` — the only depth at which history could not have been
  quietly re-committed afterwards). `--checkpoint-dir` checks byte agreement
  with the issuer's mutable checkpoint directory, but does not independently
  anchor history. The minter refuses a broken chain, never mutates the audit
  files, publishes through a byte-exact exclusive two-phase protocol, and stamps
  `issuer.key_custody` to distinguish key sources. The historical `offhost`
  value means externally supplied: injected and KMS-unwrapped private keys
  remain available to the local signing process. It does not establish isolated
  signing or resistance to an actor able to use that key. The verifier accepts
  role-scoped trust inputs for the receipt
  envelope, historical audit rows, checkpoints, and the anchor ledger without
  claiming that a deployment uses physically distinct keys. Envelope and
  checkpoint key windows are evaluated at verification time; historical row and
  anchor-ledger windows use issuer-signed event timestamps, not an independent
  time authority, and the report discloses that limit. Point-in-time by design:
  a later lawful erasure re-signs the day, and the verifier says so.
- **Agent Control Plane — one console over currently resolvable principals**
  (`agent_control_plane.py`, dashboard `/agent-control-plane`,
  `maverick control-plane status|list|ledger|suspend|resume|contain|release|
  attenuate|halt|clear-halt`, opt-in `[control_plane] enable` /
  `MAVERICK_CONTROL_PLANE=1`) — a bounded roster of WorldModel `active` or
  revoked native principals currently visible in the goal/revocation stores plus
  enrolled external agents (`agent:<id>`) from the trust registry, and one set
  of operator verbs whose effects are the stores the runtime already consults
  on its next tool call: **suspend/resume** land in the capability revocation
  registry (a native subtree's next tool call is denied; an external agent's
  trust entry is flipped to revoked as well so every surface refuses it),
  **contain/release** drive the security plane's containment and the
  bring-your-own-agent gateway's, **attenuate** narrows an external agent's
  deny-tools / risk / budget / wall ceiling in the trust registry and refuses
  any change that would widen it, and **halt/clear-halt** arm and disarm the
  local deployment killswitch every kernel checks at its tool boundary. Native
  goal execution atomically binds an ownerless `Goal.owner` to the exact root
  capability/runtime principal and refuses a different non-empty owner before
  status, audit, episode, model, or tool effects. OIDC/SAML subjects remain
  opaque (including Unicode, spaces, `|`, and `/`) and the dashboard's current
  control endpoints carry them in request bodies/query values rather than path
  components; restricted legacy path routes remain for simple ids. No new
  enforcement is added; each verb reports what it *confirmed* landed (a
  revocation that did not persist is a failure, not a success with a
  footnote). Each verb also attempts a `control_plane_action` audit row carrying
  the verb, the principal, the actor and the outcome; the response reports
  whether audit emission succeeded instead of claiming that enforced state and
  durable audit evidence are the same thing. Bounded roster, status, and
  principal-timeline reads remain available while the verb gate is off, expose
  signing/completeness posture instead of assuming a signed chain, and fail
  closed when a required authority is unreadable.
- **Memory Guard — governed reads/writes (OWASP ASI06)** (`memory_guard.py`,
  opt-in `[memory_guard] enable` / `MAVERICK_MEMORY_GUARD`) — the screen
  between an agent and its memory store. Every fact write is stamped with
  **provenance** (`source` + a `TrustTier`: first-party / learned / tool /
  external + a sensitivity label) and low-trust writes are run through an
  **injection/poisoning tripwire** (and the Shield, fail-open) so smuggled
  instructions are quarantined, not stored. **Trust-aware retrieval**
  (`filter_facts`) keeps memory below `[memory_guard] min_recall_trust` out of
  the agent's standing brief, with a stricter gate available for memory
  consulted right before an irreversible action (`filter_facts(high_risk=True)`,
  which requires at least learned-loop trust). Every decision lands in the
  signed audit chain (`EventKind.MEMORY_GUARD`). Provenance columns are recorded
  even when the guard is off, so turning it on governs existing memory
  immediately.
- **Temporal memory — non-destructive fact evolution** (`fact_history` in
  `world_model.py`, opt-in `[memory] temporal` / `MAVERICK_TEMPORAL_MEMORY`) —
  a changed fact does not overwrite the old value; the prior value is kept
  with the validity window it was believed in (`valid_from`..`valid_to`), so
  `world.get_fact(key, as_of=t)` and `world.fact_history(key)` answer "what did
  we believe on date X, and why" for the Operating Record. Bitemporal metadata
  is plaintext (queryable) while the value stays sealed at rest; sqlite-first.
- **Federated insight exchange** (`insight_exchange.py`,
  `maverick insights-export` / `insights-import`) — consolidated lessons
  (never raw trajectories) cross instance boundaries as Ed25519-signed
  bundles; imports are fail-closed against `[dreaming]
  trusted_insight_pubkeys`, Shield-scanned, provenance-tagged, and merged
  through the normal dedup gate. Import checks the operator HALT again at the
  write boundary and requires a learning audit preparation record before any
  lesson becomes usable. A separate completion record distinguishes a clean
  import from a published one whose final activity record is missing.
  Transport is deliberately operator-managed
  (a file), never a network call. **Fleet aggregation:** a central
  `maverick dream --donations-dir` replays the whole fleet's donated
  trajectory records through the same consolidation.
- **Vector-store cross-run memory** — opt-in `[memory] backend` routes
  cross-run recall through a persistent **Chroma / Qdrant / Weaviate** store
  (`vector_store/`, `semantic_recall.py`) so similarity search is indexed and
  incremental instead of a linear re-embed scan; fail-open and
  dependency-injectable — the kernel never *requires* a vector store. The
  **Weaviate** adapter (`weaviate_store.py`, `[weaviate]` extra) targets a
  local or cloud v4 cluster with a server-side vectorizer (`near_text`). The
  **pgvector** adapter (`pgvector_store.py`, `[postgres]` extra) keeps vectors
  in the same Postgres database as the world-model backend (cosine `<=>`
  search); it takes an injected embedder rather than embedding itself, so
  recall reuses the local fastembed model.
- **Cognitive Data Engine — outcome-pattern discovery** (`data_engine.py`
  + `flywheel.py`, `maverick flywheel`, default-on `[data_engine] enable` /
  `MAVERICK_DATA_ENGINE`) — the Tesla-style data engine for a governed
  workforce: production failures are triaged by observed outcome differences
  within recorded context groups. These are hypotheses for review, not proof of
  cause. Candidate guardrails (`negative_knowledge.py`) need controlled
  evidence before automatic promotion,
  beneficial actions consolidate into **habits** (`procedural_memory.py`, a
  reinforce/forget curve), and the whole loop composes in one pass. It reads the
  trajectory store and can be disabled independently. Observable
  read-only at `GET /api/v1/flywheel` (mined guardrails + consolidated habits).
- **Outcome-comparison estimators** (`promotion_effect.py`,
  `counterfactual_rollout.py`) — a stratified difference and a learned-model
  rollout help rank hypotheses. The statistical gate uses sample variance and
  compares the observed statistic with shuffled assignments; the average of
  shuffles is not a refutation. Neither method alone establishes causation from
  observational logs, and those logs cannot clear the promotion gate.
- **Operations Scientist — propose a process change for a controlled trial**
  (`operations_scientist.py`, default-on `[operations_scientist] enable` /
  `MAVERICK_OPERATIONS_SCIENTIST`) — pairs a harmful-looking action pattern with
  a candidate replacement ("stop A; do B"), simulates the swap in the learned
  model, and prioritizes candidates for a real trial. The simulated lift is a
  forecast, not a measured causal gain; it can be disabled independently.
- **Consequence Engine — reality is the reward** (`consequence.py`, `maverick
  record-outcome`, dashboard `POST /api/v1/outcomes`, default-on `[consequence]
  enable` / `MAVERICK_CONSEQUENCE`) — when a real downstream result lands (an
  invoice paid, a ticket reopened), it **overrides the verifier's self-graded
  proxy** so the flywheel learns from what actually happened, not from a model
  grading its own work. Newest outcome wins, clamped to [0,1]; when disabled the
  verifier proxy passes through unchanged. The HTTP entry point a CRM/ERP/ticketing
  connector calls once reality reports back.
- **Earned Autonomy — prediction evidence** (`earned_autonomy.py`,
  `maverick earned-autonomy`, opt-in `[earned_autonomy] enable`) records and
  scores action-level consequence predictions. Qualification is advisory: it
  does not grant standing consent or authorize a specific operation. Shadow
  execution continues to require a human decision and uses compensating steps.
  Existing unscoped standing consent grants must be explicitly reauthorized;
  scoped grants retain their prior binding.
- **Connector consequence adapters — reversibility that is earned, not
  asserted** (`connector_previews.py`, `maverick connectors plan`, gated by
  `[governed_connectors] restore_points` / `MAVERICK_GOVERNED_RESTORE_POINTS`)
  — the governed REST connectors' `preview_write` returns a *sentence*
  ("would PATCH salesforce/… with fields ['Amount']"); Shadow Mode needs the
  dollars, the entities, and above all a real `undo`. `plan_write` supplies
  them, and enforces one rule: **an action is reversible only when we are
  holding the thing that inverts it.** A PATCH earns its undo by capturing the
  record's prior values for exactly the fields being changed; a POST earns its
  undo from the id the create response returns — but only when the path
  addresses a collection the dialect actually models, because the same verb
  drives RPC endpoints (`/actions/standard/emailSimple`) that no DELETE
  recalls, and appending an id to an unmodelled path guesses at another
  vendor's URL grammar. A full-replace PUT and a DELETE earn nothing, because
  replaying system fields fails and a recreated record has a new id and
  dangling references; a write path carrying a **query string** earns nothing
  either — for any verb, creates included, since a parameter like
  `sysparm_input_display_value` changes how the service reads the values being
  submitted (so replaying a raw prior writes something other than what was
  captured) and parameters like `sysparm_fields` reshape what the write
  *answers* with, which is the create's only evidence. Every gap fails closed to
  `undo=None`, which makes `run_saga` refuse **before any effect** and routes
  the action to a human. Per-service knowledge lives in a `RestDialect`
  (`SalesforceDialect`, `ServiceNowDialect`; an unknown connector gets a
  deliberately incapable generic one that earns nothing): which fields carry
  money, how a path names a record, which paths are create-into collections
  (matched **anchored**, since a suffix match would claim any prefix at all as
  this vendor's and earn a compensation aimed at a URL the dialect never
  modelled), what a record id must look like before the response's id is
  concatenated into a compensating DELETE address, and three facts that decide
  whether a restore can actually
  restore — **system-managed fields** (audit stamps, auto-numbers, formulas,
  roll-ups) whose priors read back perfectly and then silently fail to apply,
  so touching one forfeits the inverse; the **optimistic-concurrency token**
  (`LastModifiedDate` / `sys_mod_count`), which guards *both* windows a
  stranger's edit can land in — re-read immediately before the write, so an
  edit made while the card sat in front of a human aborts with no effect at
  all rather than being quietly reverted later, and re-read again before
  restoring, so an undo refuses rather than overwriting somebody else's edit.
  The token is necessary but not sufficient — Salesforce stamps
  `LastModifiedDate` only to the second, so a colleague saving inside the same
  second as our own write carries an identical token forever — so the undo
  also compares the **values** it is about to overwrite against the ones our
  write left behind. Third: the **raw-value capture** ServiceNow requires
  (display values are not writable back). The post-write snapshot that becomes the undo's reference is
  adopted only if it still carries the values we just wrote, field by field —
  a fallback GET can otherwise hand us a stranger's state and license the undo
  to overwrite it, while a stranger touching some *other* field is no reason
  to refuse, because the undo only ever replays ours. That comparison has to
  survive two shapes of the same value: the capture GET is *narrowed* (raw,
  dereferenced) but a write's echo is whatever the service volunteers, so a
  ServiceNow reference field is bare from the read and
  `{"link": …, "value": …}` from the echo — the dialect normalizes it, and an
  echo that still does not corroborate is treated as no echo at all rather than
  silently forfeiting the undo. The comparison is deliberately *not* lossy in
  the other direction: `"USD;100"` and `"EUR;100"` are different values, and
  reading them as equal would let the undo destroy an edit while reporting the
  field untouched. The approved params are
  snapshotted at planning time, so a caller mutating its dict while the card
  awaits approval cannot change the write that executes. Exposure is the
  *delta* where a prior was captured ($100k → $120k risks $20k) and the whole
  figure where it was not — overstating keeps a human in the loop,
  understating would not. `preview_write` keeps its no-network guarantee; the
  read-only GETs that earn and re-confirm the undo live in this separate seam
  and are operator-gated.
- **Emergent Substrate — an auditable coordination shorthand** (`emergent_protocol.py`
  + `emergent_tokens.py`, `maverick codebook` / `codec-learn` / `codec-probe`,
  opt-in `[emergent_protocol]` / `[emergent_codec]` / `MAVERICK_EMERGENT_CODEC`) —
  swarms coordinate in English, most of which is boilerplate they repeat. The
  codec learns short codes for that boilerplate from the swarm's *actual*
  messages, and — unlike opaque emergent languages — **every code decodes
  EXACTLY back to English** (`decode(encode(x)) == x`, fuzz-tested against
  adversarial content), so the Shield and a human always read plain text while
  agents move the compressed form. `maverick codec-probe` measures the real
  token (not just byte) savings with the target tokenizer; the token-aware codec
  measures **~28% token savings** on realistic coordination in benchmark. OFF by
  default and currently **measure-only** when wired into the live blackboard
  (`GET /api/v1/codec` reports what it would save on real traffic) — agents
  reading the codes to *realize* the savings is a separate, gated step.

- **Ekko — client-controlled work discovery** (`work_discovery.py`,
  `work_discovery_store.py`, `work_discovery_planning.py`, `work_discovery_factory.py`,
  `ekko_daemon.py`, `maverick ekko`, independently
  gated by default-off `[ekko]` / `MAVERICK_EKKO`) — turns repeated application
  transitions into automation candidates with separate-occurrence evidence,
  actionable discovery progress and an owner review of the task, inputs, output
  and approval. App switches do not imply task timing or tool access. Reviewed
  Agent Factory + Flow drafts are unsaved, with initial and final human approval
  in the workflow proposal; stale evidence requires another review. Copilot
  opens the same protected review without receiving recorded activity.
  Opt-in private opportunity plans retain reviewed task descriptions, benefit
  assumptions and shortlist/pilot/parked stages with scoped encryption and
  expiry. Estimates include setup and remaining human work; pilot scorecards
  count rejected outputs and rework as losses. Assumptions and owner-reported
  results remain distinct from verified savings. Reporting, reconciliation and
  document review tailor the unsaved draft's instructions. Revision checks and
  pilot retry references protect against stale edits and duplicate counts.
  **Find and build for me** separately opts in to discovering repeated owned
  business requests, current reviewed plans or guided task steps and customer-specified
  tasks, then saving native agent workflows in bounded batches. Existing drafts
  and customer exclusions are preserved. The UI and reviewed Copilot operation
  share the build service, source/context checks and recovery behavior. Building
  makes no provider calls and never publishes, schedules or runs workflows.
  External connections receive readiness checks, not content crawling.
  Enrollment is owner/device scoped, observation uses a
  positive application allowlist with a winning sensitive-app blocklist, and
  raw local events expire after at most 30 days. The bundled foreground daemon
  accepts an explicitly supplied observer; it never chooses an ambient OS
  monitor, requests endpoint permissions, starts a login service, or captures
  screen/window/clipboard/keystroke/document content. Pausing, revoking,
  erasing, saving a draft, and activating automation remain distinct
  human-controlled actions. Provider
  egress is reserved and unsupported; it must remain false.
  See
  [`ekko-work-discovery.md`](./ekko-work-discovery.md).

- **Bounded learned pure operators** (opt-in `[flows] learned_operators`) —
  reviewed scalar examples retain the complete matching expression set from a
  fixed grammar; an attached agent node uses a learned value only on in-domain
  agreement, otherwise retaining its original agent fallback. File-only
  `maverick flow operator` commands learn, refine, inspect, attach and remove
  draft artifacts; agreement is not verified correctness or action authority.
  Bounded distinguishing questions expose ambiguity for reviewed labels;
  `[flows] learned_operator_questions` separately enables authenticated,
  tenant-owned review records and unpublished refinement drafts with audit
  recovery. Exhausted search does not imply equivalent candidates.
  `learn-composed` infers bounded multi-operation scalar expressions from
  reviewed end-to-end examples, retaining all matching expression trees in a
  packed graph. The same refinement, question and draft paths handle both
  artifact schemas. Composed execution also requires `[flows] composed_operators`;
  incomplete prediction or disagreement preserves the original agent fallback.
  See [usage and limits](./learned-operators.md).

- **Learned action dataflow** (`maverick.flow.action_recipe`,
  `[flows] action_recipes`) — infer all matching typed input, earlier-result and
  constant argument bindings from reviewed straight-line action episodes.
  `maverick flow recipe learn/refine/draft` produces reviewable native flows with
  an approval before each action. Fresh runtime IDs remain data dependencies;
  disagreement stops the sequence without repeating completed work.
  Explicit `learn --transforms --domain ...` learns bounded arithmetic/text/
  conditional argument expressions with all consistent candidates retained,
  up to six eligible source fields per step and eight total argument leaves.
  Default-off `[flows] action_recipe_transforms` additionally gates v2 execution;
  native action approvals and authority remain required. Float/null values keep
  copy-only semantics. Explicit `learn --choices --domain ...` learns a Boolean
  guard and argument relationships for one shared action followed by one of two
  demonstrated terminal tools, from at least four episodes with two per outcome.
  All consistent guards remain; the default mode stops on disagreement after
  the shared action without replay. Default-off `[flows] action_recipe_choices` requires both
  recipe and transform opt-ins. Verified learning also accepts `--choices`;
  existing refinement and draft paths preserve the choice artifact. This bounded
  topology does not learn arbitrary tool order, nested branches or loops.
  Separate `learn-workflow-verified` learns next actions and completion from
  signed reviewed histories with varied counts and repeated tools, within an
  explicit last-tool/latest-results representation. The strict default-off
  `[flows] action_workflow_learning` also requires recipe, transform and lineage
  opt-ins and an actual governed reference. The authenticated
  `/flows/recipe-lineage/learn-workflow-verified` route learns and admits using
  current source/owner authority; CLI output remains unadmitted. Bounds include
  eight executed actions, eight tools, 32 episodes/states, 12 source leaves per
  state and two operations per expression. All consistent alternatives remain;
  uncertainty stops work. This is not hidden-policy inference, unrestricted
  loops, cost-optimal evidence acquisition or proof of business correctness.
  Workflow execution requires strictly persisted signed receipts, separately
  from source-bundle verification. Unavailable signing or persistence refuses
  further execution; receipt failure after an effect quarantines the run without
  replaying that effect. Enabling workflow learning does not configure global
  audit signing or install its dependencies. This does not make every product
  audit event signed or local storage immutable.
  Separate `learn-memory-verified` and the matching authenticated
  `/flows/recipe-lineage/learn-memory-verified` route infer a bounded integer
  history accumulator alongside those next-action and argument expressions.
  The complete family includes no memory, zero/input initialization and one
  fixed retain/replace/add/subtract/min/max update program over one selected
  tool result field. All consistent models and their own expression alternatives
  remain; every interpretation must agree before execution. The strict default-off
  `[flows] action_workflow_memory_learning` additionally requires the workflow
  opt-in and its dependencies, including the same mandatory signed execution
  receipts. Shared search/history budgets and integer overflow
  cause refusal; they never select an incomplete set of alternatives. This is
  one bounded integer cell, not arbitrary hidden-state or business-policy inference.
  Explicit `draft`/`draft-verified --teach-choices` and the governed draft API's
  strict `teaching: true` option add human continuation review on a real completed
  prefix. Both branches' arguments must agree; the chosen terminal still needs
  separate native approval. Default-off `[flows] action_recipe_teaching` requires
  the recipe/transform/choice/lineage flags and an actual governed reference,
  including when general require-lineage policy is off. Inspection markers grant
  no execution authority and never reopen indeterminate runs. Optional
  in-memory capture admits only successful native governed action observations,
  with source-run/definition/call provenance and explicit local review export.
  Separate `[flows] action_episode_capture` enrollment retains encrypted native
  evidence across ordinary approval pauses, with declared data bounds, expiry
  and authenticated human review before export. Learning consent is separate
  from execution approval. Ordinary capture requires straight-line source flows;
  a separate teaching family admits only the exact human-choice topology and
  binds its actual prefix, authenticated selection and native terminal. An
  agreement-only teaching run cannot supply a new human label. Complete teaching
  bundles still need separate suitability review, copied-data grant and signed
  export before verified refinement; no automatic publication follows. This does not
  learn agent policies. Raw `learn/refine` files remain operator assertions. The separate
  default-off `[flows] action_recipe_lineage` path signs authenticated reviewed
  bundles, verifies them against independent issuer/tenant key trust and retains
  complete training lineage in a package. Authenticated governed admission and
  draft export bind that package to native decision receipts; current source,
  review, key and grant eligibility are checked before each proposed action and
  dispatch. `[flows] require_action_recipe_lineage` can require this path for all
  learned recipes. Grants expire no later than the original capture deadline
  (at most seven days); no renewal route is included. Service signatures are not
  personal reviewer signatures or proof of business correctness. Offline
  verification reports live status as unchecked, and expiry does not erase
  downloaded or derived Flow copies. Preserve complete packages and bundles.
  The run page's **Learning example** card lets an authorized human stop future
  governed use with an ordinary reason and confirmation form. Restricted
  withdrawal preparation and withdrawal remain available while execution or
  learning is disabled, retaining current ownership, source, retention, revision
  and audit checks. Pending recording is not success; withdrawal does not undo
  business work or erase exported copies. See
  [usage, controls and limits](./learned-action-recipes.md). Apart from that
  withdrawal control, these capabilities are operated through the engine, CLI
  and API; the dashboard and Copilot do not provide a complete setup, teaching,
  consent, use and recovery journey for them.

- **Flow engine & visual automation** (`maverick.flow.*`, gated on `[flows]`) — a
  deterministic graph of typed nodes (`ir.py`: agent / action / branch / switch /
  foreach / while / parallel / approval / delay / wait_event / scope (try-catch) /
  subflow / setvar) run by a pure interpreter (`runner.py`)
  with [complete private checkpoints](./flow-checkpoint-storage.md) for pause,
  restart and retry (bounded API previews never replace execution data),
  tenant-scoped indexed metadata history and cursor-paged due-run recovery,
  with data threading, safe expression rendering (`{{fn(...)}}` incl. arithmetic,
  list ops, `and`/`or` conditions with numeric-or-lexical ordering so date/string
  comparisons work; legacy `secret(...)` action expressions are refused before
  effects, while authorized native connectors resolve their scoped accounts
  internally; see [credential migration](./flow-credential-migration.md)), a whole-flow wall-clock deadline
  (`Flow.max_seconds`), a per-run **aggregate agent-spend ceiling**
  (`Flow.max_dollars`, enforced in `execution.py` so a wide parallel / long
  foreach can't fan out unbounded cost), a per-flow **concurrency cap**
  (`Flow.max_concurrent`, a lock-guarded slot claim at dispatch that defers an
  overlapping run so a singleton "drain/sync" flow never double-fires its side
  effects), a per-flow **schedule timezone** (`Flow.timezone`, an IANA zone so
  `0 9 * * *` fires at 9am local and follows DST; `scheduler.next_run(tz=...)`),
  per-node retries with exponential **backoff** (`retry_backoff`, and a raising
  executor is retried too) / timeout / on-error routing, and **real intra-flow
  parallel concurrency** (parallel branches AND `foreach concurrent: true`
  iterations run on a bounded thread pool with per-branch cycle detection).
  `switch` routes n-way on a data key; `while` loops a body with a runaway cap;
  `setvar` computes flow-data keys from expressions (a loop counter, a composed
  field); `wait_event` pauses the run until an external event resumes it; `scope`
  is try/catch (a body failure routes to `on_error` with `{{_error}}` readable in
  the catch arm). A flow may declare **typed manual-run inputs** (`Flow.inputs`:
  `{key, type: text|number|bool|date, required, default}`) — the designer's Run
  button prompts for them and `POST /flows/{id}/run` validates + coerces them
  (`ir.coerce_inputs`, 400 on a missing-required or bad value), and that endpoint
  takes an optional `idempotency_key` so a double-submit dedups to one run.
  Reusable **sub-flows take mapped inputs** (`subflow_inputs`) to run isolated —
  the child sees only what's passed, can't clobber parent data, and returns via
  its `output` key. Approvals support **choice verdicts** beyond approve/reject
  (recorded to `output` for downstream routing) and an **expiry** (`timeout` — a
  lapsed approval resolves as rejected via the sweep, fail-closed). The live
  driver (`execution.py`) persists a resumable run (`store.py`) with per-node
  trace **including each work node's measured wall-clock seconds**, dry-run
  sandbox executors, and secret redaction (`redact.py`). A **self-rewrite loop**
  (`evolve.py` + `evolution_log.py`) swaps a node kind, measures grounded
  before/after outcomes, versions the definition, and autonomously reverts a
  regression. It grounds which tool a reliable agent node keeps calling
  (`node_tools.py`, sourced from the trajectory store) so a **hardening**
  proposal (agent → deterministic action) can name a candidate tool. The
  proposal is currently review-only because tool-name history does not prove
  the parameters or effects needed for a safe replay; `auto_apply` cannot
  activate it. The Learning page exposes the separate evolution controls,
  including automatic regression revert when enabled.
  `evolution_log.improvement_count()` reports the
  self-rewrites that stuck (reverted ones netted out) as the improvement count. A failed run records WHICH node failed (`FlowRun.cursor`) and can
  **resume from the failed step** with the data as of the failure
  (`execution.execute(from_failure=True)`, `POST /flows/runs/{id}/retry?from_failure=1`)
  — pre-failure side effects are never re-driven. The server-rendered **visual
  designer** (`flow_designer*.js`, pure logic in `flow_designer_core.js`) drafts
  a flow from natural language, edits nested foreach bodies / parallel branches
  on their own canvas, shows live run + measured-impact overlays (💡 badges mark
  nodes with learned self-rewrite proposals), and carries the editor
  fundamentals: undo/redo (Ctrl+Z/Y), duplicate (Ctrl+D), copy/paste
  (Ctrl+C/V), click-to-cut edges, insert-a-node-into-a-selected-edge, 16px
  grid snapping, zoom-to-fit, client-side structural validation before save
  (`FDCore.validateFlow`), and **data pills** — one-click `{{key}}` insertion
  from the outputs a node can actually see upstream (`FDCore.upstreamOutputs`).
  The action picker searches the FULL live tool registry
  (`GET /flows/tools?q=`) and groups its ~3,300 connectors into coarse,
  browsable **categories** (Communication, Dev & Code, CRM, Finance, … +
  Other — `tool_categories.py`, keyword-classified) so a user can filter to one
  area instead of scrolling a flat list; `?category=` narrows the registry and
  `?q=`+`?category=` intersect, a **⚡ Triggers panel** shows everything that starts
  the flow (cron / webhooks / event triggers) in one place, a **gallery**
  (`GET /flows/gallery`) loads curated starter graphs onto the canvas, flows
  export/import as JSON files, and `?from_template=` opens any saved template
  as its single-agent flow (the text-builder → designer bridge). Shift-drag
  **marquee multi-select** moves/deletes node groups together, a corner
  **minimap** gives click-to-jump orientation, and a failed run surfaces a
  one-click **🔧 Fix it** that opens the copilot pre-armed with a
  diagnose-and-patch turn grounded in that run's trace. Live status streams
  over **SSE** (`GET /flows/runs/{id}/events`, slot-capped like the goal
  stream) with automatic fallback to backoff polling. A dedicated
  **run viewer** (`/flows/{flow_id}/runs/{run_id}`) shows the node-by-node
  timeline with per-step durations, redacted run data, and the recovery
  actions.

- **Flow copilot (chat that builds the flow)** — a conversational assistant
  docked in the designer (`maverick.flow.chat` + `POST /api/v1/flows/chat`).
  It edits a populated canvas via small **validated patches**
  (`maverick.flow.patch`: add/remove node, set field, rewire — applied
  copy-on-write and `Flow.validate()`d, so the model can never leave the canvas
  broken), drafts a full graph only on an empty canvas, answers "what does this
  flow do?", and — grounded in a real run trace via `run_id` — diagnoses "why
  did it fail?" and proposes the fix. Budget-capped per turn like the drafter;
  every applied edit is one designer undo step and a normal flow version.

- **Triggers for flows** — a flow fires from a cron schedule (`Flow.schedule`, a
  per-flow `flow_cron` job), any polled event source (`automation_events.py`:
  `http_json` / `rss` / `oauth_http_json` / `github_issues` / `imap_email` /
  `file_dir` / `form`), an **inbound webhook** (`/webhook/run` with a
  flow-target trigger — the signed payload's `data` becomes the run data and the
  delivery `id` doubles as the idempotency key, so a re-delivered event never
  fires twice), or a manual/dry run. A run paused on a **wait_event** node
  resumes from the same webhook (`{"resume": "<run_id>", "data": {...}}` — the
  event payload merges into the flow data). A paused **approval** node can post
  signed Approve/Reject links to a channel (`approvals.py` — a stateless HMAC
  token; `POST /flow/approve` resumes) so a human clears it without a dashboard
  session. A hosted **form** submission (`form_store.py`, public `POST /form/{token}`)
  is accepted only for a registered form trigger with a current published flow
  release or bound template (or a live vendor questionnaire), and becomes flow
  data when the trigger polls. Its per-token queue is capped at
  5,000 submissions / 32 MiB; a full queue refuses new submissions with 507
  rather than accepting data that cannot be retained.

  OAuth event triggers refresh only through registered provider presets and
  send vaulted tokens only to approved API origins for that provider. Existing
  triggers with custom token endpoints, credential environment names, or
  unsupported resource origins must be reconfigured before polling resumes.
  Salesforce and custom provider domains are not currently in the approved
  origin list. Remove saved credential overrides and configure the preset's
  environment credentials for supported providers.
  An owner can replace a form link in Automations after every accepted
  submission has been checked. The old link stops accepting submissions, the
  new link starts with an empty queue, and the old submission file is retained.
  Replacement refuses pending or unreadable history. An owner can review an
  exact waiting submission and record a signed, reasoned decision that it must
  not run; that decision is checked again when the queue advances. Repairing a
  submission for a new target remains unavailable.

  The administrator's connected-automation settings show the effective signing
  configuration. Reviewed changes recheck current authority and settings,
  verify the incoming and outgoing resolvers separately, and restore the local
  configuration when a write cannot be confirmed. The ordinary form reports
  uncertain outcomes and clears a prior account's credential entry. External
  secret ownership transfer, independent outgoing-only rotation and durable
  settings audit history are not implemented.

  Polled batches are retained in the tenant world database before dispatch,
  using the configured at-rest encryption. A failed queue reservation or cursor
  write retries that retained batch even if the feed no longer contains it.
  Template events commit their goals and admission receipts together, and both
  manual polling and scheduled polling publish through the durable queue. Queue
  admission receipts survive completed-job cleanup. This prevents automatic
  duplicate admission; it does not make an external service's effects reversible.
  An unconfirmed non-idempotent callback remains held for reconciliation.

  Source cursors distinguish an initialized empty feed from a new trigger, so
  its first later item runs. Stored cursor-format metadata preserves legacy raw
  IDs, including IDs resembling the new envelope format. Flow admission uses
  the exact source identity rather than truncated display fields. During cursor
  migration, an existing legacy flow run is reused only when its retained fields
  establish the same identity; ambiguous truncated records require reconciliation.
  File batches drain timestamp ties, including new arrivals at the current
  boundary. A boundary holds at most 4,096 file identities; overflow is reported
  before advancing, and files arriving with timestamps older than an already
  advanced boundary remain historical. Legacy timestamps cannot reconstruct
  files previously skipped by an older installation. IMAP initialization reads
  the complete UID high-water without fetching historical message bodies;
  UIDVALIDITY changes establish a new baseline. Provider-wide OAuth vault
  authorizations and token rotations are serialized across local processes.

  The sender-check upgrade holds earlier, unstarted IMAP goals and workflow
  runs before execution. Older non-email goals continue only when their saved
  admission receipt proves the current owner and unchanged trigger generation;
  older non-email workflow runs require the same binding and a source ID that
  reproduces their generation-scoped reservation key. Missing, deleted, edited,
  and ambiguous legacy work stays held for review. A run reserved under the
  older protocol is not proof that its email sender was verified, even when it
  reached the queue. Owners should review held items and start fresh work from
  the current trigger after confirming the source. A pre-upgrade IMAP batch tied to an
  edited trigger configuration may remain retained but cannot be attributed to
  the new binding or automatically replayed. This requires explicit operator
  reconciliation; there is no in-product one-click repair for that historical
  batch. New IMAP work requires the receiving server to remove forged sender
  results before stamping its own aligned result; a successful mail sign-in
  test does not prove that server behavior.

- **Migration fidelity** (`automation_import.to_flow`) — a per-source
  `_STRUCTURAL_LOWERERS` registry (register a source in one line): n8n IF/Filter,
  Power Automate (WDL) `If` / `Foreach` / `Switch` / `Until` / `Scope`, Workato
  recipe `if` / `repeat`, UiPath exported activity trees
  (`Sequence` / `If` / `While` / `ForEach` / `TryCatch`), and Make (Integromat)
  `BasicRouter` routes are all captured **structurally** (branch/foreach/switch/
  while/scope nodes, arms wired to rejoin, bodies as nested flows, Until's exit
  condition negated, and a Make router lowered to parallel fan-out route flows
  guarded by its route filters); graphless sources approximate each step as an agent
  node that still runs. A UiPath Release/Schedule with no exposed activity tree
  stays a correct one-step *invocation* import — honestly reported
  `approximated` (the Orchestrator API returns no .xaml, so the process's
  internal control flow isn't visible), never a false `preserved`.
  `to_flow_with_report` returns the per-step fidelity log
  (`preserved` / `approximated` + why). Automations presents the full import
  review before saving instruction or visual drafts; the older unreviewed
  `POST /import/run` directs customers to those controls. Imported drafts are
  not automatically published or activated. Fidelity is shown per automation;
  an import never silently pretends to be lossless.
  Supported n8n `$json` references normalize to flow-data paths and every
  AND/OR clause is retained. WDL `If` preserves nested AND/OR/NOT as a branch
  graph, including literal types and nested trigger fields. Unsupported
  operators, unbound action-output references and dynamic right operands
  require manual repair; graph imports preflight the entire batch before
  creating templates, schedules or triggers. Agent fallback steps retain
  bounded, secret-redacted operational inputs without silent truncation.
  WDL `Until` remains an approximation because the generated loop checks its
  exit condition before each pass; compound exit expressions require repair.

- **Reviewed automation imports** use the existing automation-import and
  Connections switches. Customers choose an exported file or their own named
  n8n, Make, Workato or UiPath account in Automations; Power Automate uses an
  exported file. The current account, workspace, connection revision, complete
  bounded source, parameters and migration limits are reviewed before saving.
  Unsupported or oversized work is refused before saving any member of the
  batch. Lost replies read exact original outcomes without importing again.
  Visual conversion is optional, and instruction drafts keep supported
  nonsecret operational inputs instead of silently shortening them. Publishing
  and activation remain separate decisions. Activation reviews the current
  template, spending/time allowance, named timezone and next occurrences,
  then admits the native schedule once. Copilot opens these protected forms
  without receiving credentials or replacing an entered draft.

- **Protected report downloads** provide explicit, named controls for the
  SOC 2 snapshot, AI inventory, OSCAL assessment, statement of applicability
  and public consent-signing key. Ordinary download actions verify the current
  account and bounded native response before offering a file; interrupted
  sign-in, missing records and stale signing keys remain readable errors in
  the page. Copilot focuses the protected download control without fetching
  report bytes or delivering private content through its answer. Offering a
  file does not establish that the customer saved it.

- **Owned generated-tool stopping** shows current owned tools, disabled files
  awaiting cleanup and retained original decisions on Learned. Each removal
  reviews exact stopping and file consequences before consent and guarded
  native deletion. A withdrawn source allows only its owner's metadata-only
  stopping or cleanup; it does not reveal the old source or restore permission.
  An interrupted removal remains unknown. Any later cleanup requires its own
  explicit acknowledgment and current review, rather than replaying the old
  decision. Native library callers retain their existing defaults, while the
  older unreviewed dashboard delete opens the complete review.

- **Invitation expiry choices** let administrators choose one hour, one day,
  seven days or thirty days for installation and workspace invitations. The
  result and waiting list show the actual native expiration date. Creation
  rechecks the current administrator, people context, invitation switch and
  existing workspace MFA requirement at the physical write, and records the
  chosen lifetime and exact expiration in the creation audit. A lost one-time
  link cannot be recovered: review and cancel the waiting invitation before
  deliberately creating its replacement. Copilot opens the same protected
  people form while keeping entered email and expiration choices.

- **Truthful workflow retry waits** show supported no-wait, ten-second and
  thirty-second choices. Earlier saved requests remain intact until deliberately
  changed; the designer states their actual first wait and thirty-second cap.
  Later eligible waits double within that cap, and uncertain or unsafe actions
  retain the native refusal to repeat. Ordinary editing, Undo, draft recovery
  and the existing workflow Copilot share the native saved field.

- **Rich human tasks** — an `approval` node carries `choices` (verdicts beyond
  approve/reject, recorded to `output` for a downstream switch), an `assignee`,
  an `expires_after` expiry (its own field, not the execution `timeout`) that
  routes to an `on_expire` escalation lane on lapse (else fails closed), and a
  `form` of fields collected on sign-off (merged into flow data, filtered to the
  declared field names). The run viewer renders the choice buttons + form inputs;
  the expiry sweep resumes the run with an out-of-band `expired` flag (never a
  human-verdict string, so no resume caller can forge it) so expiry escalates via
  `on_expire` rather than only reject.

- **Data experience** — the `{{ }}` transform set spans text (`split` `join`
  `slice` `regex` …), data (`index` `keys` …), number (`abs` `int` …), and time
  (`now` `datefmt`). Real runs record per-output-key **schema hints** (types +
  field names, never values; `maverick.flow.schema_infer`, `GET /flows/{id}/schema`)
  so the designer's data pills offer nested keys (`order.total`). Branch/while
  conditions have a **structured builder** (key / op / value dropdowns over a
  data-key datalist) with a raw-text advanced mode for `and`/`or`.

- **Renewable named accounts** (`connection_oauth`, gated on Connections and the
  OAuth vault) — sealed workspace app registration managed by an installation
  administrator, with reviewed account consent by workspace administrators
  in Connections for Google Drive, Google Cloud Storage discovery and Jira
  Cloud. Server-held PKCE/state binds the current workspace, account, app and
  connection versions; renewal preserves the reviewed generation, while a lost
  rotating-token response requires reconnecting. Vendor/discovery adapters consume
  the actual named records. Existing personal registrations stay private. A
  same-browser connection detour retains the original vendor request; denial
  and uncertain renewal expose reconnect/return actions without resending work.
  The optional desktop return uses a signed, one-shot loopback broker to return
  from the system browser to the initiating Lightwork window. Saved status shows
  provider account identity, requested/provider-reported scopes, Lightwork owner
  and the selected Jira workspace; renewal refuses a changed provider subject.
  Customers use the installed provider registration and do not create provider
  applications or handle client secrets during normal setup.
  Authenticated disconnect requires the reviewed credential revision. Callback
  access logs and connection validation errors redact sensitive inputs.
  External provider registration/consent and live
  customer acceptance remain separate; see [account authorization](named-account-authorization.md).
- **Named connections** (`maverick.connections`, gated on `[connections]`) —
  store a connector's base URL + API token under a name, sealed at rest with
  the tenant KMS key like the OAuth vault; a connector resolves a saved
  connection as a fallback only when `<NAME>_TOKEN` is unset (env always wins).
  CRUD + a reachability `test` at `/api/v1/connections`; a Connections page
  wires a connector without shell access — the citizen-developer path.

- **Flow analytics** (`GET /flows/analytics`) — per-flow volume, success rate,
  failure count, duration p50/p95 (from per-node `seconds`), and top recent
  error messages, on a Flow Analytics page. The Workflows index unifies flow
  graphs alongside templates and playbooks (one surface, not two).

## Tools

Built-in tool modules. Highlights by group (all under `tools/`):

- **Code & files** — `fs`, `str_edit`, `ast_edit` (tree-sitter), `apply_patch`
  (atomic multi-file), `repo_map`, `dep_graph`, `test_impact` (coverage-guided),
  `reviewer` (diff review), `file_watcher`, `notebook_exec` (run a .ipynb's code
  cells in the sandbox), `html_to_app` (scaffold a starter app from an HTML
  mockup).
- **Data** — `sql_query` (read-only by default), `pandas_query`, `spreadsheet`
  (CSV/XLSX, write-capable), `compute` (SymPy), `embeddings`.
  Spreadsheet writes stage a complete file before replacement. Formula cells
  explicitly identify cached or uncalculated values. Optional XLSM cell edits
  preserve untouched ZIP/VBA parts. Optional native recalculation updates caches
  using an offline Calc worker; macros are never executed. CSV `info` identifies
  counts beyond its bounded sample as partial. PDF reads use the assigned
  workspace; enabled offline OCR handles scans, with `ocr=true` for mixed pages.
  Native text-table extraction requires `pdfplumber`. See
  [document processing](document-processing.md) for setup and format limits.
- **Web & research** — `web_search` (Tavily/Brave/DDG/SerpAPI), `http_fetch`
  (GET/HEAD directly; any other request, or one with a body, after a person
  approves it), `browser` (navigate/click/type/`fill_form`), `browser_device` (device-emulation
  presets), `browser_auth_vault` (Fernet-encrypted session store), `websocket`
  (ws/wss connect-send-recv), `dom_diff` (structural before/after HTML diff),
  `arxiv`, `semantic_scholar`, `wikipedia`, `hackernews`, `youtube`.
- **Media** — `view_image`, `view_video`, `pdf_reader`, `ocr`, `voice`
  (transcribe/speak — STT backends: OpenAI/Groq Whisper keys, local
  faster-whisper, and a **built-in offline path**: the pywhispercpp engine
  (whisper.cpp wheels, a maverick-dashboard dependency — dashboard installs
  transcribe out of the box) or a local whisper.cpp binary, both loading the
  checksum-pinned GGML model managed by `voice_models.py`
  (in-app Settings > Models setup with reviewed source/size, progress,
  cancellation, checksum verification and retry; optional
  `maverick voice setup|status|transcribe`; auto-fetch OFF unless explicitly
  enabled via `[voice] auto_fetch_model` or the installer;
  deployment-wide routing via `[voice]
  stt_backend`, where `local` keeps audio on-machine even with keys set) —
  with **voice persona presets** (`[voice.personas]`:
  named backend+voice bundles selected per call) and **multi-language voice**
  (`[voice.languages]`: per-language voice map, BCP-47 prefix match); explicit
  args always win, unknown presets degrade to defaults — `voice_personas.py`), `ffmpeg_tool`, `imagemagick_tool`, `pandoc_tool`,
  `office_convert` (LibreOffice headless: the binary office formats pandoc
  can't take — Word/Excel/PowerPoint/OpenDocument → PDF/text/HTML/CSV, all
  sandbox-mediated with workdir-confined paths),
  `replicate_tool` (image/video/audio gen), `latex` (math→MathML + document→PDF),
  `diagram` (Graphviz / Mermaid render).
- **Robotics & hardware** — `ros` (drive a ROS stack over **rosbridge** via
  `roslibpy`, `[ros]` extra): publish a command to a topic (e.g. `/cmd_vel`) or
  call a service; auth `ROS_BRIDGE_URL`, no native ROS in the agent process;
  disabled by default and only registered when `[capabilities].ros = true`.
  `serial` (embedded device over **UART**/serial via `pyserial`, `[serial]`
  extra): list_ports / write / read / query a microcontroller or board, with a
  device-path guard so it can't be turned into an arbitrary-file opener.
- **Knowledge** — `knowledge_search` (per-domain RAG over collected docs),
  `recall`, `kv_memory`.
- **Productivity & SaaS connectors (~47)** — GitHub Actions, GitLab,
  Bitbucket (issues / PRs / pipelines), Jira, Linear,
  Asana, Trello, ClickUp, Confluence, Notion, Obsidian, Slack, Discord, Gmail,
  Google Drive, Dropbox, Calendar, Salesforce, HubSpot, Stripe, Shopify, Plaid,
  TrueLayer (EU/UK open banking),
  Twilio, Zoom, S3, DynamoDB, MongoDB, Redis, Elasticsearch, Datadog, Sentry,
  PagerDuty, Mixpanel, PostHog, Plausible, GA4, Home Assistant, Cloudflare,
  Vercel, AWS Lambda/SES/SNS, Microsoft Graph, and more — plus a long-tail of
  2,877 write-capable token-authed REST/GraphQL connectors
  (`enterprise_connectors.py`, built on `make_rest_tool`) covering nearly
  every category of enterprise and SMB software: CRM, ERP, ITSM, HRIS,
  security, data/BI/CMS, automation/iPaaS platforms (Zapier, n8n, Power
  Automate, Make, Workato), e-commerce, healthcare, real estate, legal,
  insurance, manufacturing, education, nonprofit/government, hospitality,
  media, telecom, no-code/AI, fintech/crypto, and region-specific SaaS.
- **Primary-source data connectors (37, read-only, low-risk)** — authoritative
  government and public data APIs that ground the analyst-style packs in
  primary sources instead of model memory: SEC EDGAR, FRED, U.S. Treasury,
  World Bank, IMF, FDIC, BEA, Census, BLS, EIA, Alpha Vantage, Finnhub,
  Polygon, OpenFIGI (finance/markets); Federal Register, eCFR, Regulations.gov,
  CourtListener, GovInfo, USAspending, SAM.gov, Open States, PatentsView
  (legal/regulatory/gov); GLEIF, OpenCorporates, UK Companies House (entity
  registries); openFDA, NPPES/NPI, ClinicalTrials.gov, RxNorm, PubMed (health);
  NWS, NOAA Climate, OpenWeather, EPA Envirofacts, Climatiq, Carbon Interface
  (weather/energy/ESG). All GET-only and confirm-free — they read public
  reference data, mutate nothing, and carry no tenant secrets. Most are keyless
  (a fixed public host, zero config); the rest take a free API key from env,
  delivered as a header or query param (never from the prompt). Built on three
  new `make_rest_tool` auth modes: `keyless`, `query_auth`, `default_base_url`.
  **Auto-wired by suite** (`SUITE_DATA_CONNECTORS`): each analyst pack is granted
  its suite's relevant sources in `domain_capability` (e.g. FDIC/FRED → banking,
  openFDA/NPI → healthcare, USAspending/SAM.gov → gov-contracting, EIA/EPA →
  utilities, NWS/NOAA → insurance & agriculture), so the agent reaches for the
  right primary source by default. Additive and deferred (no context cost); a
  host-restricted pack's egress is never silently widened. On by default with a
  kill-switch — `[workforce] data_grounding = false` /
  `MAVERICK_WORKFORCE_DATA_GROUNDING=off` (installer wizard step).
- **System** — `shell` (sandbox-mediated), `wasm_run` (**WASM sandbox**:
  execute a WebAssembly/WASI module under wasmtime — capability-grant
  isolation where the module sees ONLY the preopened dirs/env/args given;
  workdir-confined paths, validated env keys, sandbox-mediated invocation),
  `git_advanced`, `compute`,
  `dns_lookup`, `openapi_runner`, `clipboard`, `notify`, `attachments`,
  `android` / `ios_sim`, `a11y`, `task_graph` (persistent dependency-DAG of
  tasks — add/status/ready/order/list plus **`critical`**: the longest
  dependency chain, weighted by optional per-task cost, that bounds completion
  no matter the parallelism — the tasks a critical-path-aware scheduler runs
  first), `workspace_snapshot` (snapshot/restore a working dir), **attachments
  of all kinds** (`attachments.py`: text, images, audio, video, PDFs, and
  Office/OpenDocument/epub files — document ZIP containers are structurally
  sniffed past the executable/archive magic-byte deny, which no setting
  bypasses; extend the mime allowlist with `[attachments]
  extra_mime_prefixes` or accept any declared type with `allow_any_mime`;
  images auto-embed as vision blocks and PDFs as native document blocks
  budgeted by the driving model's context window, `[attachments]
  embed_documents` to opt out), **attachment understanding**
  (`generate_companions`: incoming audio/video auto-transcribes via the
  kernel STT backends and Office/OpenDocument/RTF files auto-extract text
  via the knowledge parsers into `<name>.transcript.txt` /
  `<name>.extracted.txt` companion attachments, which embed as text blocks
  on the first message under a window-scaled budget — user text files stay
  tool-reachable only; off via `[attachments] transcribe_media` /
  `extract_text`), **channel inbound attachments** (files shared over
  email/Telegram/Slack download in the adapter — auth first — travel as
  `IncomingMessage.attachments`, and the server stores them as goal
  attachments under the same validation as a dashboard upload, then runs
  companion generation; attachment-only messages get a "Process the
  attached file(s)." brief), **attachments panel** (the goal page lists a
  goal's files with companion labels, uploads more via `POST
  /api/v1/goals/{id}/attachments`, and downloads each via `GET
  .../attachments/{aid}/download` — always `Content-Disposition:
  attachment` + `nosniff`, so a crafted HTML/SVG upload can't execute in
  the dashboard origin; the chat composer also takes drag-and-drop and
  pasted files), **S3-backed
  attachments** (`[attachments] s3_bucket`: mirror every stored attachment to
  any S3-compatible bucket + `s3_fetch` pulls it down on another worker host;
  local disk stays the source tools read, mirror is fail-open), `license_scan`
  (classify deps + flag copyleft), `self_capability` (report the run's capability
  grant), `oidc` (OIDC authorization-code client), `oauth_helper` (builds a PKCE authorization URL; token exchange and refresh
  are handled through the operator-facing connection flow rather than agent
  tool calls); the Automations page's **Connected
  accounts** panel lists each provider's token-free health (expiry, granted
  scope, auto-refresh) and a **Test** action that forces a live refresh through
  the preset's token endpoint so a stale connection surfaces before a flow hits
  it — `oauth_vault.status()` and `POST /oauth/{provider}/test`; `cost_curve` (per-provider cost
  model), `bench_track` (record benchmark scores + flag regressions), `teams`
  (Microsoft Teams webhook), `knowledge_graph` (extract/query/render
  subject-relation-object triples; no external graph DB), `cross_repo_deps`
  (cross-repo Python package import graph + cycle detection via `ast`),
  `citation_verifier` (check cited quotes against their source text), `anki`
  (flashcards via the local AnkiConnect add-on — decks/models/find/add_note/
  sync, writes gated by confirm, loopback-only by default), `test_gen`
  (generate a Hypothesis property-test scaffold from a function's signature),
  `semantic_code_search` (rank functions/classes by intent via ast + lexical
  scoring), `lsp_bridge` (cross-language code intelligence over the Language
  Server Protocol — symbols/definition/references/hover/diagnostics against
  host-installed servers: pyright/gopls/rust-analyzer/tsserver/clangd;
  one-shot session per call, deadline-gated stdio), `mutation_test` (plan source mutants a strong suite should catch),
  `constrained_output` (validate/coerce a value to a typed/enum/range/regex
  shape — the guard half of constrained generation), `model3d_inspect`
  (headless 3D-mesh stats — triangle/vertex counts + bounding box for STL/OBJ),
  `synthetic_data` (deterministic synthetic rows from a field spec, json/csv),
  `web_recorder` (generate a runnable Playwright script from a list of browser
  steps — deterministic codegen with escaped literals), `web_archive` (save a
  URL's content locally so research stays reproducible — SSRF-pinned per-hop
  redirect revalidation, 5 MiB cap, sha-dated snapshot ids, list/get over the
  archive), `github_search` (GitHub repos/code/issues search — explicit token
  only, clamped pages, readable rate-limit errors with Retry-After), `a11y_tree` (distill raw
  HTML into a compact accessibility tree — landmarks/headings/links/controls —
  for a 5-10x token cut), `cache_admin` (inspect/purge the
  tool-output cache — stats or targeted purge), `error_patterns` (cluster noisy
  error/log lines into ranked patterns by normalised signature), `container_build` (build a
  container image from a Dockerfile via sandbox-mediated `docker build`), `ai_act_classifier` (EU AI Act
  risk-tier screening for a described AI use-case — prohibited/high/limited/
  minimal + obligations; heuristic, not legal advice), `geofence` (region
  allow/deny policy check — ISO codes or groups EU/EEA/FIVE_EYES, deny-precedence), `two_person_rule` (validate
  dual-control sign-off — distinct approvers, separation of duties, optional roles), `differential_privacy` (Laplace
  mechanism for (epsilon)-DP noisy counts/sums on published stats), `watermark_detector` (find hidden
  text watermarks/steganography — zero-width, tag chars, variation selectors, homoglyphs), `privacy_budget` (stateless differential-privacy budget calculator — remaining epsilon +
  fit/deny estimate from trusted cumulative spend; not an enforcement ledger),
  `collusion_detector` (flag collusion between independent swarm agents —
  op=scan: echoed reasoning + rubber-stamping in messages; op=detect:
  voting-collusion blocs whose agreement defeats independent-quorum
  guarantees), `coordinated_disclosure` (run a CVD process offline —
  op=status over a record set flags EMBARGOED/DUE_SOON/OVERDUE/PATCHED/
  DISCLOSED per report with per-severity policy, or checks one report's
  OPEN/EXPIRED window; op=advisory renders the advisory block),
  `capability_delegation` (validate a
  delegation graph for privilege escalation — fixpoint from root capabilities),
  `capability_delegation_graph`
  (static analysis over capability delegations — cycles, privilege escalation,
  transitive holders), `agent_identity` (per-agent stable id + HMAC sign/verify),
  `risk_tier` (score an agent goal LOW/MEDIUM/HIGH from operational signals —
  shell/secrets/PII/spend/irreversibility — for gating), `bias_eval` (group-
  fairness metrics — four-fifths rule, demographic-parity and equal-opportunity
  differences from per-group outcome counts), `decision_explainer` (per-factor
  contribution breakdown for an additive/scorecard decision — right-to-explanation),
  `governance_explainer` (explain a governance ALLOW/DENY/REQUIRE_HUMAN decision —
  the rule that fired + plain reason + the counterfactual that would change it;
  GDPR Art. 22 / AI Act Art. 14, re-runs the real policy evaluator),
  `voice_command_grammar` (match a transcribed utterance to an intent + slots
  from a {slot}-template grammar — no model round-trip for high-frequency
  commands), `what_changed_digest` (added/removed/changed digest between two
  snapshots, optional signed numeric deltas), `gui_element_memory` (offline
  store of GUI element locators keyed by app/screen/name for computer-use),
  `adversarial_eval` (score a red-team batch — confusion matrix, recall/
  precision, and the missed-attack list that gates red-team CI),
  `trace_compare` (diff two replay traces step by step — first divergence,
  matched prefix, per-step field diffs), `latency_heatmap` (tool × latency-band
  shaded grid + p50/p95 per tool), `tool_call_inspector` (per-tool call count,
  error rate, avg/max latency, HIGH-ERROR flags from a tool-call log),
  `rectification` (validate/apply GDPR Art. 16 field corrections under a
  mutability policy — auditable diff + corrected record), `anomaly_scan` (flag
  cross-run metric outliers via the robust median/MAD modified z-score),
  `k_anonymity` (check a released dataset for k-anonymity + optional l-diversity
  — quasi-identifier group sizes and sensitive-value diversity), `retention_check`
  (audit records against a data-retention policy — flag over-retained and
  no-policy records by category/age; GDPR storage limitation), `redact`
  (**provable redaction**, `provable_redaction.py`: redact secrets/PII to a
  fixpoint then re-scan to *prove* the output carries none — composes the
  secret + PII detectors, and reports the residual gap instead of a false
  guarantee when a bound is hit), `breach_notification`
  (GDPR Art. 33/34 72h breach-notification timer — DUE/OVERDUE/ON_TIME/LATE +
  Art. 34 high-risk reminder), `data_minimization` (flag fields collected beyond
  a purpose's allowlist + missing required fields; GDPR Art. 5(1)(c)),
  `consent_check` (evaluate consent records for active validity — granted /
  withdrawn / expired per purpose, latest grant governs; GDPR Art. 7),
  `kv_cache_offload` (LRU KV-cache keep/offload plan under a memory budget),
  `otel_semconv` (map span attributes to OpenTelemetry semantic-convention
  keys), `payload_compress` (zlib compress/round-trip ratio helper),
  `compaction_classifier` (rule-based compaction-strategy picker),
  `capability_revocation` (transitive revocation over a delegation graph),
  `memory_safe_parse` (size/depth/item-bounded JSON/CSV parse that never raises
  on hostile input), `misuse_removal` (remove flagged leaderboard entries +
  tombstones), `consent_ergonomics` (minimal plain-language consent prompt +
  risk badge), `skill_distill_v2` (extract a reusable skill spec from a
  successful trace), `observation_channel` (merge multi-agent observations into
  a time-ordered feed), `marketplace_moderation` (APPROVE/REVIEW/REJECT listing
  scan), `channel_autoroute` (pick the best channel for a message by rules),
  `jwt_inspect` (decode + validate a JWT offline — claims, exp/nbf, and
  HS256/384/512 HMAC signature verification; flags alg=none), `rbac_check`
  (evaluate an RBAC authorization decision — role inheritance + '*'/'prefix:*'
  wildcards, ALLOW/DENY with the granting role), `cidr_check` (firewall-style
  ordered CIDR access-control for an IPv4/IPv6 address — first match wins),
  `semver_check` (does a semver version satisfy a constraint — comparator sets,
  caret/tilde ranges, prerelease ordering, and prerelease exclusion at
  final-release upper bounds unless explicitly named).
- **Extensibility** — `@tool` decorator (`tools/decorator.py`): turn a typed
  function into a registered Tool with a signature-derived JSON Schema, no
  boilerplate. **TypeScript plugin SDK** (`sdks/plugin-ts/`,
  `@maverick/plugin-sdk`): author a tool in TypeScript with
  `defineTool`/`servePlugin` over a versioned NDJSON stdio protocol
  (`maverick-plugin/1`: `--describe` manifest, `{id,tool,args}` →
  `{id,result|error}`); the host (`ts_plugin_host.py`, `[plugins] ts =
  [["node", "/path/plugin.js"]]`, wizard step included) loads the manifest
  into regular Tools with a persistent scrubbed-env child, per-call timeout,
  no automatic call replay, owned process cleanup, and the no-shadowing rule built-ins enjoy. A **gRPC
  plugin host** (`grpc_plugin_host.py`, proto `grpc_api/plugin_host.proto`,
  `[plugins] grpc = [{target, command}]`) carries the same contract over gRPC
  for any language: Describe → Tools, Call with a deadline, scrubbed-env spawn,
  owned process cleanup and typed unknown outcomes without call replay.
  **Governed qualification workbench** (`plugin_workbench.py`, `/plugins`) runs
  actual Python tool/channel/skill/persona, bundled Node and local gRPC contracts
  in a reviewed immutable no-network container. It records observed completion or
  interruption, rejects unknown/malformed versions, retains task/workflow pins,
  and offers explicit stopped-work migration. Settings and the installer control
  it and its shared native/Copilot review operations; no live-service acceptance
  is inferred from process startup.
  **Retrospective generators** — period reports the operator runs over a
  chosen window: `safety_report` (safety) and `benchmark_retrospective`
  (perf).
  **AI Act conformance package** (`ai_act_package.py`, `python -m
  maverick.ai_act_package [-o out.md]`): assembles the Art. 11 / Annex IV
  technical-documentation skeleton from the deployment's *recorded* posture —
  the Annex III risk self-assessment, Art. 14 oversight measures (consent
  mode, capability enforcement, delegation, killswitch), Art. 12 logging
  (audit signing, retention, day-files present), Art. 15 evidence (red-team
  gate, shield calibration, reliability cert when present), and the effective
  Art. 50 first-turn disclosure setting (including an explicit opt-out) —
  sections without evidence say so, and the items only a
  provider can complete (intended purpose, conformity route) are an explicit
  checklist, not fabricated prose.
  **Adversarial-prompt corpus release** (`maverick_shield/corpus_release.py`,
  `python -m maverick_shield.corpus_release`): turns the CI red-team corpus
  into a versioned, validated, integrity-pinned artifact — content-hash
  version, SHA-256 over canonical rows, license + intended-use ("NOT a
  training set for attack generation"), and a provenance gate that REFUSES a
  release containing secret-shaped content or identity PII (fixture IPs in
  attack samples are allowed and disclosed); writes corpus + MANIFEST +
  README.
  **Security backports + LTS machinery**
  ([`docs/security-backports.md`](security-backports.md) +
  `backport_tool.py`, `python -m maverick.backport_tool scan|plan|check`):
  the policy (what qualifies, the `lts/<v>` 2-year safety-fix branch, 7-day
  SLA) made executable — `scan` finds security-marked commits, `plan` lists
  the ones not yet on the LTS branch (patch-id matched, so a cherry-picked
  twin isn't re-flagged), and `check` exits non-zero when an eligible fix is
  past the SLA — read-only; cherry-picks/pushes stay maintainer acts.
  **Formal verification of the sandbox interface (TLA+)**
  ([`docs/specs/tla/`](specs/tla/README.md)): `SandboxInterface.tla`
  models the chokepoint as a state machine and TLC-verifies — for all
  interleavings — no silent downgrade to host exec under a container backend,
  scrubbed child env always, refused-never-ran, bounded execution budget, and
  every command eventually terminal (the liveness property assumes dispatch
  fairness, stated explicitly in the spec). Verified: 982
  states, no errors; reproduction steps in the README.
  **Sigstore keyless signing** (`sigstore_signing.py`, `[sigstore]` extra,
  `python -m maverick.sigstore_signing sign|verify`): sign skill/plugin
  artifacts with sigstore's keyless flow (OIDC identity) into a
  `.sigstore.json` bundle; verification pins the identity+issuer pair and
  fails CLOSED on a missing bundle, wrong identity, or absent install —
  identity-based signing alongside the key-based skill signing and the
  self-hosted plugin CA.
  **Federated shield rule updates** (`shield_updates.py`, opt-in `[shield]
  federated_updates` + `update_url`/`update_pubkey`, wizard step included):
  pull-based publisher-signed rules bundles (Ed25519 over canonical JSON);
  unsigned, mis-signed, tampered, downgraded, or un-anchored bundles are
  refused, and a verified bundle stages `shield_rules.json` (0600) atomically —
  the kernel never imports the shield itself (rule 1).
  **Shield decode/defang pre-pass** (`maverick_shield/deobfuscate.py`): on every
  scan surface — input, tool-call arguments, and tool output — the shield decodes
  base64/hex/percent encodings and folds Unicode homoglyphs (Cyrillic/Greek
  lookalikes NFKC leaves alone), then re-scans every de-obfuscated variant — so an
  encoded `rm -rf /` is blocked even though the literal surface form hid it.
  Monotonic (only upgrades an allowed verdict to a block), bounded against decode
  bombs, and fail-open; escape hatch `MAVERICK_SHIELD_NO_DECODE=1`.
  **Trained cheap-probe seam + offline trainer** (`probe_model.probe_features`
  n-gram extension + `maverick_shield/probe_train.py`, `python -m
  maverick_shield.probe_train --corpus … --out model.json`): `probe_features`
  additionally emits deterministic hashed char n-gram features (`ng:<bucket>`,
  blake2b — stable across processes) when `ngram_buckets > 0`, so a model can
  carry lexical content the 7 hand-named signals can't; `ngram_buckets = 0` keeps
  the original contract, so every existing artifact is byte-for-byte unaffected.
  The pure-stdlib trainer (no numpy/sklearn) fits an L2 logistic regression over
  the SAME extractor inference uses (train/serve parity), selects a threshold at a
  configurable benign false-positive ceiling (`--max-fp`, default 1%), and exports
  the `{bias, weights, threshold, ngram_buckets, ngram_sizes}` JSON the shield
  already loads. Still OFF by default and MAX-ensembled with the heuristic (can
  only raise recall). Datasets, licences and the enablement gate are in
  [training a probe model](security/shield-benchmark.md#training-a-probe-model).
  **Annual safety report generator** (`safety_report.py`, `python -m
  maverick.safety_report --since --until`): aggregates what the deployment
  actually recorded — shield blocks, capability denials, killswitch
  activations, consent decisions, erasure requests, red-team/calibration
  results when present — into a markdown report with explicit reporting-period
  and data-available sections; empty sections say so, nothing fabricated.
  **eBPF syscall monitor** (`ebpf_monitor.py`, opt-in `[ebpf_monitor] enable`,
  wizard step included, `python -m maverick.ebpf_monitor program|run`):
  generates a bpftrace program tracing execve/connect/openat for the agent's
  PID tree with a validated suspicious-syscall watchlist, supervises it via an
  injected runner, parses events, and alerts on watchlist hits — generator/
  parser/supervisor fully offline-tested; the live attach needs root +
  bpftrace and refuses politely otherwise.
  **Memory-safe parsing of untrusted bytes** (`parser_isolation.py`, opt-in
  `[security] isolate_parsers`): the parsers fed attacker-controllable bytes
  (PDF via pdfplumber/pypdf, images via Pillow) are C-extension-backed — a
  memory-safety bug there is an in-process foothold. The whitelisted-parser
  inventory (`PARSERS`, the policy in code) routes them through a
  secret-scrubbed child process: a segfault on hostile bytes kills the child,
  never the kernel, and an exploited child holds no provider keys; size caps
  enforced before the child sees data, hard timeout, and on child death the
  consumer REFUSES rather than re-parsing the same bytes in-process (wired
  into `read_pdf`). Off by default — in-process behavior unchanged.
  **Plugin signing CA** (`plugin_ca.py`): a self-hostable Ed25519 certificate
  authority for plugin/skill artifacts — the in-house counterpart to sigstore's
  keyless flow. An org runs its own root (`init_root`, keys 0600 under
  `keys/plugin_ca/`), issues publisher certs (`issue`, expiring, serial'd),
  maintains a CA-signed revocation list, and every install verifies the
  two-link chain offline (artifact sig → publisher key; publisher cert → root)
  **fail-closed**: tampered artifact/cert, wrong root, expired or revoked cert,
  or a missing piece all refuse; an unverifiable CRL never silently
  un-revokes.
  **Plugin compatibility matrix** (`plugin_matrix.py`, `python -m
  maverick.plugin_matrix [--ci]`, wired as a CI lint step): one table per
  installed entry point — dist, declared API major, loadable/deprecated/
  refused, allowlisted, permissions granted — with a CI gate that fails when
  any *enabled* plugin is API-incompatible, so an upgrade dropping an API
  major can't ship silently against plugins still pinned to it. Pure
  inspection (nothing imported or executed).
  **Plugin API v2 (released)** — `MAVERICK_API_VERSION = "2"` with
  `SUPPORTED_API_MAJORS = (1, 2)`: v1 plugins keep loading through a
  deprecation window (warned in manifest validation), declared v3+ is
  refused; release notes in [`docs/plugin-api-v2.md`](./plugin-api-v2.md)
  (structured channel `Reply`, enforced manifest permissions, lockfile,
  isolation, TS plugins).
  **Plugin sandboxing** — opt-in
  `[plugins] isolation = "subprocess" | "subinterpreter"`
  (`plugin_isolation.py`): discovered plugin tools keep their schema but their
  *calls* run in a fresh CPython subinterpreter (fault/state isolation — a
  plugin that pollutes globals or leaks can't touch the host) or a
  secret-scrubbed child process (stronger: separate address space, survives a
  segfaulting plugin, no host env secrets); values pass by baked literals,
  never argv. **Plugin telemetry (opt-in, local-only)** —
  `[plugins] telemetry = true` counts plugin-tool invocations to a local JSON
  tally (nothing leaves the machine); `maverick plugin stats` shows
  calls/last-used per tool for allowlist pruning; composes with isolation so
  isolated calls count too. **Plugin version-pinning lockfile** —
  `maverick plugin lock` records each plugin distribution's version to
  `plugins.lock.json`; discovery verifies against it per `[plugins]
  lock_policy = "off"|"warn"|"enforce"` (`plugin_lock.py`: enforce refuses a
  drifted or unpinned dist — that plugin only — warn logs once per dist;
  `maverick plugin verify` reports drift/missing/unpinned and exits 1 on
  failure). **Hot plugin reload** — `maverick plugin reload <dist>`
  (`plugins.reload_plugin`): drop a plugin distribution's modules from the
  import cache so the next discovery pass re-imports the current code on disk;
  the edit-reload-retry loop for plugin authors, same allowlist/permission
  gates on re-import.

## Channels

18 wired channels (`packages/maverick-channels/`): Telegram, Discord, Slack,
**Microsoft Teams** (`teams.py`: Azure Bot Framework webhook — Bot Connector JWT
verified fail-closed against Microsoft's OpenID keys, tenant + Entra object-id
allowlists, mention stripping in channels/group chats, replies through the
activity's service URL with a tenant-aware client-credentials token, and
**approvals in Teams**: Adaptive Cards with the dashboard card's content,
Approve/Reject/Ask-a-question, a second confirm card for high/critical risk,
decided through the dashboard's own `approval_decisions` path with `channel =
teams` in the audit, cards updated in place; Teams accounts are linked to
Lightwork users on the Channels page or by a one-time `link <code>` in chat —
see [docs/channels/teams.md](channels/teams.md)),
Signal, Email, Matrix, Mattermost, Bluesky, Mastodon, Voice (Twilio), WhatsApp (Twilio),
**WhatsApp Cloud API** (`whatsapp_cloud.py`: Meta's first-party Graph API —
GET verification handshake, constant-time `X-Hub-Signature-256` HMAC,
sender allowlist, atomic message-id dedup claim, chunked outbound; no Twilio
middleman), SMS, iMessage
(macOS), **IRC** (channels + DMs, TLS), **Threads** (`threads.py`: Meta's
Threads API — polling adapter by design since webhooks are partner-gated;
author allowlist, claim-first dedup that fails CLOSED because a polling
adapter re-sees replies, two-step publish with 500-char chunking),
**RCS** (`rcs.py`: Google RCS Business Messaging for approved RBM agents —
Pub/Sub or direct envelopes, constant-time clientToken verify, MSISDN
allowlist, service-account Bearer auth with cached refresh). Rich
formatting + dedup + per-channel authz. **Reply threading** — inbound messages
carry their platform `message_id` and adapters expose `send_threaded`
(Slack `thread_ts` behind opt-in `[channels.slack] thread_replies`; Telegram
`reply_to_message_id`; base falls back to a plain send) so long-running
answers land under the message that asked. Inbound IMAP/SMTP channel work and IMAP-triggered workflows
require a configured receiving-server identity, a matching From-aligned
sender-authentication result, and an explicit permitted-sender list before an
email can start work. The Channels and Automations pages provide those controls.
**KaTeX/Mermaid rich render** (`rich_render.py`, opt-in
`[channels] rich_render`): replies carrying display math or ```mermaid fences
are rendered into a standalone HTML page (KaTeX/Mermaid in-page, escaped
`<pre>` source as the no-JS fallback) that `channel_reply_results.prepare_reply`
attaches to the saved reply on chats that can send files (Slack, Telegram);
elsewhere the reply says a rendered copy cannot be attached, and plain
messages pass through byte-identical. **Channel SDK v2** (`base.py`): handlers may return a structured `Reply` (text + attachments +
thread_ref) instead of bare `str` — `as_reply` is the v1 shim (bare `str`
accepted through the deprecation window), `Channel.dispatch`/`dispatch_text`
normalize either contract, and all 18 wired adapters route through the
dispatch path so a v2 handler works everywhere unchanged.

## Sandboxes

8 run-to-completion backends (`sandbox/`): local subprocess, Docker, gVisor, SSH,
Podman, devcontainer, Kubernetes, and Modal cloud (below), plus an **experimental
Firecracker microVM scaffold** (the exec path does not mount the workspace).
Selected via `[sandbox] backend`.
**Modal sandbox backend** (`sandbox/modal_backend.py`, `[sandbox] backend =
"modal"`, `[modal]` extra): run agent shell in ephemeral Modal cloud sandboxes
(per-exec container, image/cpu/memory/timeout plumbed, torn down after the
command) — burstable remote compute without running a cluster; infra errors
surface as a failed command, never a kernel crash. There is no Cloudflare
Workers backend: Workers run JS/WASM request handlers, not processes, so the
self-hosted relay reference and `wasm_run` cover that use instead.
**Sandbox SDK v2** (`sandbox/sdk.py`, `SDK_VERSION = 2`): the formal backend
contract — a `runtime_checkable` `SandboxV2` protocol (`workdir` +
`exec(cmd, timeout=None)`), declared optional capabilities
(`capabilities()`), a static `conformance()` checker, and **entry-point
loading** (`[sandbox] backend = "ep:<name>"` resolves the
`maverick.sandboxes` group, instantiates with `[sandbox] options`, and
refuses a non-conformant backend rather than falling through to unsandboxed
local exec) — so third parties ship backends without forking. All in-tree
backends conform (the check surfaced and fixed a real gap: devcontainer
lacked `workdir`, crashing path-confined tools).
Backends whose execution workspace is not the host path declare
`workdir_is_local = False`. For such backends the registry omits workspace
tools that inspect or modify local paths; their remote workspace support
requires an explicit file-transfer interface. The SSH, Modal and Firecracker
backends declare this today. For compatibility, legacy third-party SDK v2
backends that omit this declaration retain the existing local-workspace
assumption; their authors should set it explicitly. This declaration does not
by itself establish complete remote sandbox isolation.
Dispatch never retries a backend because an invocation raised `TypeError`.
Legacy `exec(cmd)` backends can explicitly declare a backend-enforced finite
execution policy; admission rejects a caller deadline shorter than that fixed
cap before execution. See [legacy sandbox policy](operations/legacy-sandbox-policy.md).
Docker/Podman cleanup checks exit status, retains unresolved owned container
identities, and shares one total cleanup deadline; see
[runtime integrity and bounded work](operations/runtime-integrity.md).
**gVisor** is offered as a backend (`backend = "gvisor"`): Docker with the
`runsc` runtime (`--runtime=runsc`), interposing a userspace application kernel
between a possibly prompt-injected agent and the host — stronger isolation than
seccomp + dropped capabilities alone. It reuses every Docker knob (image,
network, memory/pids/cpu caps, non-root); `[sandbox] runtime` may select only
an approved runsc registration whose Docker metadata declares an exact runsc
`path`/`runtimeArgs` or the official `io.containerd.runsc.v1` runtime type.
Ambiguous aliases and literal `runc` fail closed in construction, health, and
diagnosis. This catches misconfiguration; it does not cryptographically attest
the runtime binary, so the Docker daemon administrator remains a trust boundary.
**Warm-container reuse** (`[sandbox] reuse_container`, default off): instead
of a fresh `docker run --rm` per command (a cold start each time), keep one
container alive and `docker exec` into it, so the 2nd..Nth command in a run
skip container startup; torn down on `close()`.

## LLM providers and routing

15 providers, routable per role (`llm.py`): Anthropic, OpenAI, OpenRouter,
Ollama, Gemini, DeepSeek, Bedrock, Vertex AI, Azure, xAI, Moonshot, TGI, vLLM, and
`openai_compatible` (a separate generic-gateway provider — any other
OpenAI-compatible server or proxy via a configurable `base_url`: LM Studio,
llama.cpp, Together, Groq, etc.), and **Codex CLI**
(`providers/codex_cli_provider.py`: ChatGPT/Codex *subscription* via a local
`codex exec` subprocess — auth from `CODEX_ACCESS_TOKEN` or `codex login`,
token fed on STDIN only; tool calls emulated via a fenced-JSON protocol;
spend is subscription-metered so `codex_cli:` ids price $0 while token /
wall-clock / tool-call budget caps still enforce). Cost-aware routing (`cost/router.py`) with **per-role
policies** (`[routing.roles.<role>]`: provider allow/deny, cost ceiling, tier
floor) and provider failover (`provider_failover.py`) with a **policy engine**
(`failover_policy.py`: error-class gating — auth fails fast, 429/timeout/5xx
fail over — plus per-model cooldowns), all opt-in. **Local-first routing**
prefers a reachable local model before remote (`provider_local_first.py`);
**energy-aware routing** downgrades to a cheaper model on low battery
(`energy_aware_router.py`); both opt-in and default-OFF. **Learned cost-aware
routing** (`cost/bandit.py`) layers a contextual **epsilon-greedy bandit** on
top of the cost router: it learns reward-per-dollar per coarse task class
(role + tier) and reorders *only within* the healthy/affordable arm set the
router already produced — never routing somewhere the router rejected, falling
back to the router's pick on a cold context. The
learned table persists atomically (`router_bandit.json`, 0600); opt-in via
`[routing] bandit` and default-OFF.

**Per-tenant BYOK provider keys** (`config.tenant_provider_api_key`, threaded
through `llm._provider_api_key` where the provider client is built; opt-in
`[providers] per_tenant_keys` / `MAVERICK_PER_TENANT_KEYS`, **default OFF**): an
active tenant that opted in (the tenant record's `byok` flag,
`tenant.registry.set_byok`) runs on ITS OWN provider API key instead of the
deployment-global one — resolved through the secret provider under a
tenant-scoped name (`MAVERICK_TENANT_<digest>_<PROVIDER>_API_KEY`, the digest
derived from the tenant's collision-safe namespace key so two tenants never
alias one name; `config.tenant_provider_key_env` reports the exact name). The
key bytes never touch config, the repo, the tenant record, or logs (the name
ends in `_API_KEY` so the GitHub Action sanitizer redacts it). Fail-safe: no
tenant, the knob off, the flag off, or a missing key all fall back to the
deployment-global key byte-for-byte — a BYOK misconfiguration never takes an
agent offline. BYOK only: no resale, metering, or markup lives here. Distinct
from per-tenant `[kms]` BYOK (envelope-encryption key custody).

**Installation performance diagnostics** (`GET /perf` + `GET /api/v1/perf` on
the dashboard, installation-admin-only): one page/JSON face for the perf story — the perf-SLA checks
measured live on the host (in a worker thread, against the published
thresholds), recorded benchmark history with short-window regression
verdicts, and the longitudinal era retrospective; sections with no recorded
data say so. **Longitudinal benchmark retrospective** (`benchmark_retrospective.py`,
`python -m maverick.benchmark_retrospective`): the multi-year companion to
continuous benchmarking — slices the FULL recorded score history into calendar-
quarter eras and reports per-era medians, era-over-era movement, best/worst
eras, net first→last change, and a least-squares trend verdict per benchmark;
the report states its actual coverage span (the intended cadence is the 3-year
mark, run over whatever the deployment recorded). **Public performance SLA** ([`docs/perf-sla.md`](./perf-sla.md) +
`perf_sla.py`, `python -m maverick.perf_sla --ci`): the published, measurable
performance properties each release certifies — tool-dispatch overhead,
compaction latency, world-model hot-path read/write p95 — measured against the
REAL code paths and compared to the published thresholds (changing a threshold
is changing the SLA); rows that need concurrency/fault drills delegate to the
reliability cert. **Reliability certification** (`reliability_cert.py`,
`python -m maverick.reliability_cert`): a reproducible, evidence-backed
self-certification composing the shipped drills — chaos game-day, the plugin
reliability drill, a 16-writer WAL contention probe — into a certificate JSON
(environment fingerprint + per-check verdicts), Ed25519-signed with the audit
key when available and only issued for a passing run.
**Deprecation registry + sunset gate** (`deprecations.py`, `python -m
maverick.deprecations [--ci]`, wired into CI): every deprecated path is
declared in one registry (target, replacement, deprecated_in, **remove_in**);
`warn_once` gives call sites a once-per-process DeprecationWarning,
`check_config` lints a loaded config for deprecated keys, and the **sunset
gate** fails CI once the package version reaches an entry's removal version
until the old path and its registry entry are deleted together — so
deprecations can't rot. Seeded with the two live windows (plugin API v1
manifests; bare-`str` channel handlers). **Critical-path-aware scheduling** (`task_graph.py`):
`remaining_critical_weight()` gives each task its heaviest tail of not-yet-done
work, and `ready_prioritized()` orders the runnable frontier longest-tail-first
(the standard critical-path heuristic — start the work bounding the finish
time before short-tail work); exposed as the `task_graph` tool's `schedule` op.
**JSON seam** (`fastjson.py`): stdlib `dumps`/`loads` with a compact serializer
for tool output and cache snapshots. It returns `str`, honors `sort_keys`, and
stringifies unsupported values. It uses the same backend regardless of whether
the legacy `[perf-fastjson]` extra is installed, preserving values such as
large integers and non-finite floats. **Self-tuning budget suggestions**
(`self_tuning_budget.py`, governed `[budget] self_tuning`): retains observed
spending and can suggest a cap for a caller that explicitly requests a *coarse
task class*
(e.g. the goal's leading verb) from how much past runs of that class actually
cost — a bounded reservoir per class, a high-quantile × margin suggestion
clamped to [floor, ceiling]. Wired as the **lowest-precedence** layer of
`budget_from_config` for such callers (an operator's configured `max_dollars`
wins) and fed by the orchestrator's per-run cost recording. It returns nothing
until a class has enough samples. Ordinary production tasks do not request a
learned class cap, and **Task limits Off** suppresses learned defaults as well
as configured ones. The advisory `maverick budget tune` command remains a
recommendation for an operator to review.

**Local-runtime launcher + autoscaler** (`local_runtime.py`, opt-in
`[local_runtime]`, `maverick local-runtime plan`): composes the correct
engine flags for **vLLM / TGI / llama.cpp** from config — continuous
batching (`max_concurrent`/`max_batch_tokens` → `--max-num-seqs` /
`--max-batch-total-tokens` / `--parallel --cont-batching`), **persistent
KV-cache** (`kv_cache = "persistent"` → `--enable-prefix-caching` /
`PREFIX_CACHING=1` / `--prompt-cache FILE --prompt-cache-all`), **KV offload
to disk** (`kv_offload_dir`; llama.cpp persists, vLLM gets `--swap-space`,
others warned honestly), and **mixed precision** (`precision =
fp16|bf16|int8|int4` → `--dtype`/`--quantization`/quant-GGUF guidance) — plus
a queue-depth **autoscaler** (min/max replicas, hysteresis, injectable
spawn/stop/probe/clock, round-robin `endpoints()` for the router). Default
OFF; the launcher refuses to start until `[local_runtime] enabled = true`
(wizard step included); no model is ever defaulted.

**Per-role reasoning effort** (`effort.py`) — the biggest cost/latency lever on
Opus 4.7/4.8: model-gated `output_config.effort` tiered by role (critical roles
`high`, bulk roles `medium`/`low`), opt-in via `[effort] enabled`.

**Prompt caching** (`providers/anthropic_provider.py`) — frozen system prompt +
name-sorted tool catalog (1h TTL) + a stable-history-prefix breakpoint (5m TTL,
with a secondary breakpoint on long turns for the 20-block lookback); billing
reads Anthropic's per-tier `cache_creation` split (5m vs 1h write surcharge)
when the response reports it, rather than pricing the whole write at one TTL.
Opt-in **cache pre-warming** (`max_tokens=0` prefill at orchestrator start)
and a `maverick_llm_cache_tokens_total` hit-rate metric.

## MCP and agent interop

- **MCP server** (`packages/maverick-mcp/`) — stdio JSON-RPC **and** Streamable
  HTTP transport; tool `outputSchema`, resource subscriptions.
- **Registry publishing** (`maverick_mcp.publish`, `python -m
  maverick_mcp.publish [--validate]`) — emit the reverse-DNS-namespaced
  `server.json` an operator submits to an MCP registry (name / version /
  source repo / pypi package + stdio transport), built from the server's own
  `SERVER_NAME`/`SERVER_VERSION` with a `validate` lint; tools stay
  runtime-discovered (`tools/list`), never frozen into the manifest.
- **Elicitation** — client inbound (policy + shield); server outbound **form
  mode** and **URL mode** (https-only, shield-screened prompt, action-only
  response so secrets never transit the model).
- **MCP Tasks (2025-11-25)** — task-augmented `tools/call` → `CreateTaskResult`,
  background worker, `tasks/get|result|cancel|list`, status notifications.
- **MCP execution ownership** (`maverick_mcp/execution.py`) — cooperative
  task/request cancellation with separate acknowledgment and worker-exit state,
  async result waits, bounded transport admission and single-reader stdio.
  [Execution operations](operations/mcp-execution.md) documents effects and
  disconnect/shutdown limits; cancelled workers remain counted until they exit.
- **MCP catalogs** (`mcp_catalog.py`) — shared bounded pagination and atomic,
  explicitly stale generations for stdio/HTTP; notices retire changed bindings
  without granting new tools to running agents. See
  [catalog synchronization](operations/mcp-catalogs.md) for refresh limits and
  the HTTP notification subscription boundary.
- **MCP client** (`mcp_client.py`) — consume remote HTTP servers; **OAuth 2.1
  client-credentials and authorization-code + PKCE** grants (`mcp_oauth.py`).
- **MCP registry** (`mcp_registry.py`) — `maverick mcp-registry browse/add/...`.
- **Federated marketplace indexes** — `[catalogs] indexes` takes any number of
  index base URLs; catalogs merge across them (earlier indexes win on name
  collision, malformed entries skipped per-entry) — run your own index next
  to the community one (`catalog.py`, pinned by test).
- **IDE protocol unification** — one MCP server (stdio + Streamable HTTP) is
  the editor protocol: any MCP-speaking editor (VS Code, JetBrains, Zed,
  Cursor) drives Lightwork through it; the editor-specific packages
  (`apps/vscode-extension`, `apps/emacs`, `apps/nvim`) are thin CLI fronts,
  not parallel protocols.
- **A2A** (`a2a.py`, `a2a_tasks.py`) — Agent Card discovery + delegation, with
  the **interop consuming half** (`validate_agent_card` spec-shape lint,
  `parse_remote_card` normalization that refuses a non-conformant card before
  anything delegates against it) proven both ways by interop tests: Lightwork's
  own card passes its own validator, and third-party-shaped fixture cards
  (rich + minimal) parse correctly. The mounted task engine claims every
  `messageId` in a tenant-and-principal-scoped durable ledger before execution,
  replays terminal results across workers/restarts, and refuses crash-left
  indeterminate claims rather than risking duplicate side effects. Local mode
  uses SQLite; the governed-record Postgres selection uses encrypted
  shared claims with forced RLS and atomic claim/lookup/quota/terminal indexes
  (`a2a_store.py`, `governed_record_batch.py`). A protected local authority receipt
  rejects accidental downgrade or a replaced shared namespace. Cached task reads
  also revalidate authority. Existing local ledgers are refused in shared mode;
  offline migration remains unfinished. The control plane still requires one
  active owner; shared A2A storage does not establish platform HA.
- **Swarm federation** (`federation.py` + `grpc_api/federation.proto`,
  protocol `maverick-federation/1`, opt-in `[federation] enabled` + `peers`):
  delegate goals across *sovereign* swarms (each with its own world DB —
  distinct from `RunGoal`'s shared-DB offload). `Hello` exchanges A2A agent
  cards (non-conformant peers refused), `DelegateGoal` carries a correlation
  id + required tools resolved **narrow-only** via capability boot negotiation
  (an ungrantable requirement refuses the delegation), auth is a constant-time
  shared token that *identifies* the caller from local config (wire names
  never trusted; fail-closed), and **both halves record matching audit rows**
  with the shared correlation id, so comparing the two nodes' signed logs shows
  a dropped half. The protocol layer runs over any `call(method, payload)`
  transport; the gRPC binding is a thin `[grpc]` adapter (live-smoked).
  New inbound requests atomically reserve one held goal and a sealed, pinned
  execution contract in the existing SQLite/PostgreSQL world admission ledger.
  The required audit acknowledgment precedes dispatch. Same-correlation retries
  repair pending audit/release phases; a claimed dispatch is never automatically
  repeated after a crash. Additive response fields distinguish pending, accepted,
  and unknown outcomes from refusal; acceptance does not prove completed work.
  Current policy can hold a previously pinned grant, but cannot broaden it.
  Recovery requires the peer to retry the same correlation; there is no automatic
  startup drain. Retained receipts, including erased-goal tombstones, count
  toward the existing 250,000-per-tenant / 50,000-per-peer capacity limits.
  These limits do not imply TTL eviction that could reopen old work.
- **Agent Trust Plane** (`agent_trust.py`, engaged by enterprise mode or
  `[agent_trust] enforce = true` / `MAVERICK_AGENT_TRUST=1`) — the *single*
  registry + decision point for talking to **external** agents, unifying what
  was scattered across `[federation] peers`, `[a2a]`, the fleet-memory roster,
  and the channel/marketplace pinned-key lists. One `[agent_trust] agents` list
  names each trusted outside agent by its **pinned Ed25519 public key** (reusing
  `federation_envelope`'s asymmetric identity), with a **direction**
  (inbound/outbound/both), a tool/risk **capability ceiling**, a dollar+wall
  **budget ceiling**, and **data_scopes** (which memory domains it may read).
  `decide_inbound` / `decide_outbound` / `decide_memory_access` are the gate
  every transport consults: **default-deny at the company boundary** when
  engaged (an unregistered agent is refused even with a valid shared token), a
  no default-deny admission when disengaged. Per-agent credentials still enforce
  their registered memory scopes. Entries carry a
  **key lifecycle** (`not_before` / `expires_at` / `revoked`, propagated onto
  the issued capability). Wired into federation (inbound + outbound + `hello` /
  `status`, registry ceiling intersected into capability boot, **wall-clock AND
  dollar budget clamped down**, and goal text **secret-redacted + shield-screened
  in BOTH directions**, fail-toward-gate); A2A (**default-deny admission** when
  engaged, plus ceiling tightening); and fleet memory (**both recall AND ingest**
  gated by `data_scopes`, with recall **hard-filtering** returned content to the
  declared scope — unscoped reads denied). Engagement + registry are read from a
  **single config snapshot** per operation; `maverick doctor` warns when the
  plane is engaged with an empty registry. Denials record an `agent_trust_denied`
  audit row. In-process peer messaging (`agent_bus`) is internal and never gated.
  **Signed-request identity** makes the pinned key *load-bearing* on federation
  delegation: the caller signs the canonical delegation envelope
  (`maverick-federation-delegate/1`) with its audit Ed25519 key and the receiver
  verifies it against the pinned key — so a leaked shared token alone can no
  longer impersonate a peer that has a pinned key. Freshness + a replay-nonce
  cache reject captured signatures; `[agent_trust] require_signed = true` refuses
  even shared-token-only peers (peers without a pinned key remain a documented
  migration path). **Per-caller A2A identity**: an `[agent_trust] a2a_token`
  resolves an A2A caller to principal `agent:<id>`, so the registry governs
  individual A2A callers (admission + per-caller tool ceiling) rather than one
  shared surface. **Org governance**: accepting a
  federation delegation routes through `governance.evaluate` when engaged —
  `DENY` refuses and `REQUIRE_HUMAN` refuses fail-closed (no silent
  auto-accept), a no-op without a `[governance]` policy. The **gRPC goal API**
  and **MCP server** are likewise gated: each accepts a per-caller
  `[agent_trust] grpc_token` / `mcp_token` (distinct per surface) resolving to
  `agent:<id>`, and when engaged a caller must be a permitted inbound agent
  (per-caller entry, or the surface-wide `"grpc"` / `"mcp"` entry for a
  shared-bearer caller) — so every external ingress (federation, A2A, fleet,
  channel, marketplace, gRPC, MCP) is default-denied at the boundary.
- **Bring-your-own-agent gateway** (`external_agents.py`, opt-in
  `[external_agents] enable` / `MAVERICK_EXTERNAL_AGENTS=1`) — agents built
  on *other* runtimes (Agentforce, Bedrock Agents, Copilot Studio, OpenAI,
  LangChain/LangGraph, custom) enroll into the governed workforce: they run on their runtime,
  governed on ours. Four verbs: **enroll** (one call writes the inbound Agent
  Trust entry — tool/risk/budget ceilings, expiry — plus the fleet-memory
  roster and platform/ownership provenance), **credential** (per-surface
  bearer tokens, rest/a2a/grpc/mcp, shown exactly once; rotate = re-mint,
  revoke everywhere at once), **screen** (pre-action admission: trust
  ceilings, cumulative budget cutoff, Shield input scan — a scanner error
  **denies** — and the `[actions] require_approval_at` floor, which parks a
  real dashboard approval the agent polls), and **account** (completed runs
  ingest as Operating Record goals owned by `agent:<id>` with step trails and
  costed episodes, so Overview/Spend/Workforce/Savings and the audit binder
  count foreign agents like native ones). Above screening sits **governed
  execution** (`[external_agents] connectors` / `MAVERICK_EXTERNAL_CONNECTORS`,
  empty = screen-only): Lightwork performs the action *itself* through the
  governed-REST connector path (SSRF host-pinning, enterprise egress
  allowlists, PREPARE/COMMIT lineage receipts) — reads run immediately, writes
  always park a digest-bound human approval that commits only on the
  byte-identical request (a mismatch voids the parked execution and counts
  toward containment; 24h TTL, 20-pending backlog cap) via
  `/api/v1/external/execute` + `/executions/{id}` + `/executions/{id}/commit`,
  audited as `external_action_executed`. Fail-closed at the boundary: text
  hygiene rejects poisoned ingest, over-budget agents are refused further
  actions, and the registry binds here even with the global trust plane
  disengaged. Agent-facing HTTP surface `/api/v1/external/runs|screen|
  approvals` + an importable `/api/v1/external/openapi.json` (drops into
  Agentforce External Services / Bedrock action groups); audit kinds
  `external_agent_enrolled` / `external_credential_minted` /
  `external_run_ingested` / `external_action_screened`. **Platform-native
  identity** (`external_identity.py`) layers on the minted bearers: a trust
  entry can pin a connected-app JWT (`jwt_issuer` / `jwt_audience` /
  `jwks_file`, verified offline against a local PEM/JWKS with `sub` = agent
  id), a webhook-format HMAC secret *reference* (`hmac_secret_ref`, resolved
  through the secret provider at verify time), and/or Ed25519 signed requests
  against the entry's `pubkey` (domain-separated `lightwork-external-request-v1`
  message, single-use nonce, fail-closed replay defence). `[external_agents]
  require_signed` then refuses the bearer for agents holding a strong
  credential, and `mint_approval` step-up gates every credential mint behind
  a one-shot, dual-control dashboard approval. See
  `docs/external-agents.md`.
- **gRPC API v1 — stable** (`grpc_api/maverick.proto`, package `maverick.v1`;
  contract gate `grpc_api/contract.py` + committed golden
  `maverick_v1_contract.json`, wired into CI): additive changes pass; removing/
  renaming a service/rpc/message/field, renumbering or retyping a field,
  changing an rpc's streaming shape, or reusing a removed field number fails
  the gate — a breaking change requires a `maverick.v2` package. The gate is a
  dependency-free proto parser, so it runs in CI without grpcio.
- **gRPC dispatch** (`grpc_dispatcher.py`, opt-in `[grpc_dispatch] target`)
  — execute goals on a remote Lightwork worker over gRPC: a `RunGoal` RPC runs
  an existing goal row to completion (API and worker share the Postgres world
  DB, same contract as the arq queue), and `GrpcDispatcher` plugs into the
  runner's Dispatcher seam with no caller changes; queue backend wins when
  both are configured; unreachable worker degrades to could-not-start, never
  an exception.
- **gRPC API** (`grpc_api/`) — typed, streaming surface for driving the runtime
  from any language: `StartGoal` / `StreamEpisode` (server-stream of episode
  events) / `Cancel` / `GetStatus`. Behaviour lives in a transport-agnostic
  `GoalService`; the gRPC shim compiles stubs on demand from the bundled
  `maverick.proto`. Behind the `[grpc]` extra; run via `python -m maverick.grpc_api`.
- **Cross-language quickstarts** — TypeScript, Go, Rust, C#, Java (`docs/clients/`).
- **LangChain / LangGraph interop** (`langchain_adapter.py`, `[langchain]` extra)
  — expose the Lightwork swarm as a LangChain `StructuredTool`, and wrap any
  LangChain `BaseTool` as a Lightwork tool. **AutoGen + CrewAI adapters**
  (`agent_framework_adapters.py`): the same two directions for both frameworks
  — Lightwork as an AutoGen `FunctionTool` (or a dependency-free typed
  callable) and as a CrewAI `BaseTool`; `wrap_autogen_tool` /
  `wrap_crewai_tool` adapt their tools into Lightwork `Tool`s (duck-typed,
  lazy imports, actionable install hints).
- **MCP-client language analytics** (`mcp_analytics.py`) — opt-in, consent-gated
  local tally of client language (from the User-Agent), read with
  `client_language_counts()` and `non_python_share()`; off by default, consent step in the
  installer wizard (`maverick init` → Analytics).

## Safety and security

- **Consumer Consent & Preferences authority**
  (`consent_preferences.py`, `[consent_preferences] enable = true`) — an
  explicit-opt-in, tenant-scoped data plane separate from the agent-action
  consent ledger. It stores immutable policy-version-bound receipts for
  purpose/channel/vendor grants, denials, withdrawals, and revocations; links
  pseudonymous known and anonymous profiles; records asserted GPC/DNT signals;
  governs registered web trackers and mobile SDKs; returns fail-closed
  enforcement decisions; and exposes bounded export/access-log, retention,
  replayable outbox, REST, installer, and operator-console paths. Inputs are
  opaque identifiers and SHA-256 digests rather than raw consumer identity.
  This authority is distinct from the agent-action consent ledger and fails
  closed when the tenant, profile, policy version, tracker, or current grant is
  absent.
- **Consent experience publishing** (`consent_publishing.py`,
  `[consent_preferences.publishing] enable = true`) — tenant-scoped exact
  web-origin and mobile bundle enrollment; immutable versioned purposes,
  topics, custom preferences, notices, plain-text translations, closed
  templates, contrast-checked six-hex-color/plain-copy theme tokens, and
  jurisdiction/locale rule groups; pinned bundle preview;
  compare-and-swap publication; immutable history; rollback-as-a-new-
  publication; and admin-confirmed withdrawal as a content-free immutable
  tombstone that makes public configuration resolution fail closed while
  retaining prior bundles only in audit history. The admin REST surface and
  `/consent/publishing` workspace cover
  the complete local authoring/promotion lifecycle. Executable HTML, script,
  arbitrary CSS, URLs/assets, wildcard origins, credential-
  bearing URLs, and unpinned resource heads are outside the contract. Published
  theme versions resolve localized display copy and exact colors into the public
  configuration, are covered by the publication digest, and roll back with the
  rest of the immutable bundle.
- **Privacy-bounded consent scanner runtime** (`consent_scanner.py`,
  `[consent_preferences.scanner] enable = true`) — a deployable Playwright
  collector visits only enrolled public HTTPS origins in a fresh browser
  context, blocks private-network and off-property navigation, supports an
  explicitly consented credential-state resolver, and retains hashes and
  cookie/storage/network metadata rather than page content, cookie values,
  storage values, or raw page URLs. Every discovery starts `unknown`; failures,
  event/page limits, and unavailable browser dependencies make the report
  explicitly incomplete rather than falsely clean. The separate
  `consent_scan_inventory.py` authority adds exact-origin property enrollment,
  compare-and-swap schedules, durable jobs and digest-only leases, recovery,
  bounded retry/dead letters/replay, immutable reports and diffs, versioned
  four-eyes classification, exact forward-cursor discovery pagination,
  retention, and an approved-only bridge into the
  tracker registry. Its REST and `/consent/scan-inventory` surfaces preserve
  incompleteness and never treat absence of a finding as proof of cleanliness.
  A separately gated dashboard-lifespan supervisor drives enrolled schedules
  across bounded active tenants, renews digest-only leases, recovers stale work,
  stops acquiring leases during shutdown, and publishes sanitized health
  metrics; all three consent, scanner, and scheduler gates must be exactly true.
  Authenticated estate custody, broad live-estate completeness, and automated
  notice population still require deployment acceptance.
- **Reviewed scan-to-disclosure proposals**
  (`consent_scan_notice_proposals.py`,
  `[consent_preferences.scanner.notice_proposals] enable = true`) — an
  independently gated tenant-local authority converts an exact, fresh
  inventory report into digest-only structured disclosure proposals.
  Its constructor-bound inventory adapter re-reads the enrolled property,
  immutable report, discoveries and independently reviewed classifications;
  rejects unknown, stale, retired, revoked or drifting authority; and rejects
  incomplete/truncated reports by default unless an exact property/report-
  bound, current independently reviewed exception is installed. Any exception
  preserves the explicit incomplete/truncated label. The adapter pins the
  property/report/inventory/review/classification digests and follows the public
  discovery cursor up to an explicit 10,000-item ceiling. Proposal
  creator, approver and local acceptor must be three distinct principals, and
  desired/no-change, reconcile, rollback, approval revocation, retention,
  signed export and integrity paths are explicit. This module never generates
  legal prose, updates a notice, publishes to a site/app/provider, or treats a
  local baseline as live-estate completeness or customer/legal acceptance.
- **Self-authenticating public consent boundary and web SDK**
  (`consent_public_api.py`, `static/lightwork-consent-sdk.js`) — one-time
  admin-minted public-client credentials resolve the exact tenant, property,
  current publication, and policy server-side; separate opaque profile
  capabilities scope anonymous consumers. Exact-origin CORS, request/response
  bounds, rate limits, GPC/DNT capture, publication/policy binding, credential
  rotation/revocation, and a static browser client are locally tested. The
  public routes accept no tenant/property selectors and expose no enrollment,
  linking, administrative, or bulk-export authority; consumer-scoped profile
  and Trust Center exports remain capability-bound. Native mobile/OTT SDKs,
  production IdP/JWKS and subject-digest-key custody, localization/usability
  acceptance, and live web property deployment remain external work.
- **Signed consent publishing and visitor sessions**
  (`consent_publication_signing.py`, `consent_publication_signing_api.py`,
  `[consent_preferences.publishing] require_signed_publications`,
  `[consent_preferences.public_api] token_ttl_seconds`) — with signing on,
  every publish, restore and withdrawal is Ed25519-signed in its own
  transaction with a per-workspace key derived from one installation root
  (generated and replaced on the Banner and Preference Center page by a global
  admin, sealed in the dashboard overlay, audited, never shown; the public key
  is shown by fingerprint and downloadable; `MAVERICK_CONSENT_PUBLICATION_SIGNING_KEY`
  wins). Publishing without a key is refused; `/configuration` adds a
  signature over the served configuration, publication and policy digests
  only for publications whose publish-time signature verifies, and the web
  SDK's `publicationKeys` option refuses anything else. `token_ttl_seconds`
  (60-86400 s, unset = off) requires a short-lived, origin-bound visitor
  session (`X-Lightwork-Consent-Session`, digest-only storage, renewable
  before expiry, rate-limited like every public call) next to the site key;
  the served SDK starts and renews sessions by itself.
- **Verified consumer identity federation and one-time domain/device pairing**
  (`consent_identity_federation.py`,
  `consent_identity_federation_api.py`,
  `[consent_preferences.identity] enable = true`) — an independently gated
  public flow verifies an OIDC token through a server-injected verifier or
  exact-JWKS-origin/`kid` signing-key resolver; enforces exact issuer, single
  audience, `iat`/`nbf`/`exp`, nonce and token-digest contracts; and persists
  neither the raw token nor raw subject. A short-lived one-time capability and
  digest-only PKCE challenge bind exact source and target client, property,
  profile/CAS revision, publication, configuration, policy and browser-origin
  or service-client authority. Successful browser, mobile-service or TV-service
  pairings call the existing `ConsentPreferenceStore.link_profiles()` CAS path,
  so linked-profile receipt ordering and latest-negative decisions remain in
  the existing consent ledger. Replay, expiry, revocation, partial-operation
  recovery, authority drift and cross-tenant attempts fail closed; pairing
  audit is immutable and integrity checked. The consumer API/SDK accepts no
  tenant, property or profile selectors. Production JWKS retrieval is not
  bundled: a deployment must inject key and subject-digest custody, then obtain
  live IdP, native-client, recovery, concurrency, scale and customer/privacy
  acceptance.
- **Capability-gated consumer Trust Center** (`consumer_trust_center.py`,
  `consumer_trust_center_authority.py`,
  `[consent_preferences.trust_center] enable = true`) — a bounded read model
  joins the current active publication, consent receipt history, volunteered
  profile data and explicitly authorized privacy-rights summaries without
  accepting tenant, property, profile or case selectors from the consumer.
  The persisted authority stores digest-only context, capability-grant and
  rights-case bindings; requires a requester plus two independent approvers;
  supports revision, revocation, retention, integrity and signed metadata
  export; and produces a zero-argument reauthenticating context resolver. Its
  authenticated mounted authority API/workbench binds tenant/principal server-
  side and covers context, approval, revocation, history, integrity, retention,
  signed-export creation, persisted read and verification without accepting
  browser-selected identity or keys. The public exact-origin routes and safe SDK
  renderer expose only granted sections and a signed consumer export. A pinned
  localized theme can apply only contrast-checked colors and plain copy across
  the CMP and Trust Center. The separately gated
  `[consent_preferences.trust_center.branding]` authority adds tenant-private,
  AES-GCM-sealed and immutable-versioned PNG/JPEG logo/icon custody; bounded
  structural media/dimension/digest validation; independent review,
  activation, key-reference rotation, revocation and ciphertext retention;
  exact DNS/TLS challenge, reverify, revoke and recovery contracts through an
  injected deployment authority; and an exact enrolled-client/property/
  publication/host/digest-bound public asset route. It accepts no SVG, HTML,
  CSS, URL, raw storage path, tenant selector or raw key, and Host never selects
  a tenant. Live DNS/TLS issuance, CDN/custom-domain routing, accessibility,
  brand/customer acceptance, DSR intake, native/cross-channel delivery and
  live identity acceptance are not claimed.
- **Consent change delivery** (`consent_delivery.py`,
  `consent_delivery_bridge.py`, `consent_delivery_runtime.py`,
  `consent_delivery_destinations.py`,
  `consent_delivery_destinations_composition.py`,
  `[consent_preferences.delivery] enable = true`) — bridges immutable consent
  receipts into a durable ordered destination outbox with exact destination
  enrollment/revocation, compare-and-swap authority, bounded retry/backoff,
  dead letters/replay, retention, external HMAC signing custody, and a
  DNS-pinned exact-HTTPS dispatcher. The API and `/consent/delivery` workspace
  expose operations without accepting raw signing keys. A separately gated
  named-adapter composition translates only server-authorized envelopes into
  closed Salesforce external-ID upserts, Marketo custom-object upserts, Adobe
  Experience Platform streaming records, or parameter-bound Snowflake SQL API
  merges. Each binding pins the tenant, destination, public provider origin,
  credential revision and provider schema; credentials remain deployment-held,
  redirects are refused, DNS is pinned, completed requests are local no-change,
  and ambiguous outcomes require an independently injected provider-read
  authority before replay. The liquid-glass operator surface exposes minimized
  readiness, operation, ambiguity, reconciliation and integrity views without
  accepting provider URLs, credentials, raw provider bodies or caller-declared
  reconciliation outcomes. Provider-specific independent readback adapters,
  live OAuth/tenant interoperability, schema provisioning, permissions,
  recovery/scale exercises and recipient/customer acceptance are not claimed.
- **Cohort-suppressed consent analytics** (`consent_analytics.py`,
  `[consent_preferences.analytics] enable = true`) — read-only aggregate event
  trends over immutable receipts with allow-listed dimensions, unique-profile
  thresholds, whole-result suppression below the threshold, bounded source and
  row reads, exact snapshot digests, explicit partial-result limitations, a
  strict audit API, and operator UI. It deliberately reports event history,
  not a fabricated current-preference KPI.
- **Governed consent experiments** (`consent_experiments.py`,
  `[consent_preferences.experiments] enable = true`) — immutable control,
  holdout, template, language, and layout variants; independent definition-
  digest approval; keyed sticky targeting; legal-signal, accessibility,
  required-purpose, choice-parity, schedule, traffic, and exposure precedence;
  aggregate-only deduplicated exposure/outcome analytics; sequential alpha-
  spent analysis; pause, resume, kill, and rollback; and verified audit export.
  It retains no raw subject identity or profile context and cannot declare a
  winner before the configured evidence floor. Live web/app traffic, legal and
  privacy approval, causal-validity review, distributed scale, and external
  rendering enforcement remain operational acceptance work.
- **Governed volunteered profile data and progressive journeys**
  (`consent_profile_data.py`, `[consent_preferences] enable = true` plus
  `[consent_preferences.profile_data] enable = true`) — exact-tenant,
  independently approved boolean/single/multi-select definitions; publication/
  policy-bound values, history, export, unset/revoke, retention and integrity;
  independently approved purpose-signal-targeted journeys with closed
  conditions, required-first prompts, cooldown/frequency caps, kill/rollback
  and aggregate interactions. The mounted strict admin adapter and operator
  workbench, their dedicated behavioral tests, and the focused-test-covered
  public API derive tenant and principal/profile authority server-side.
  The public SDK supports capability-bound view, history, export, set, unset
  and revoke plus safe progressive rendering that
  retains assignment before DOM insertion and records terminal completion only
  after successful saves. Raw capabilities, free-text PII, protected-trait
  inference, live traffic, native runtimes, and customer/accessibility/privacy
  acceptance are not implemented or claimed.
- **Provider-neutral Data Use Governance** (`data_use_governance.py`,
  `data_use_policy_compiler.py`, `[data_use_governance] enable = true`) — a
  tenant-explicit system of record for catalog assets/fields/lineage, four
  independently sourced and freshness-bound decision contexts, reviewed
  versioned machine labels, draft/active/retired policies, expiring reviewed
  exceptions, project data-use requests, immutable fail-closed decisions, and
  deterministic control IR. Policies use a closed vocabulary of allow, deny,
  mask, row-filter, and review controls; row filters are bounded ASTs and never
  raw SQL. The REST surface and `/data-use` workspace bind author/reviewer and
  requester/authorizer identities server-side and enforce four eyes. Native
  Snowflake and Databricks adapters translate server-recompiled control IR into
  closed native masking/row-filter operations with idempotency, compare-and-
  swap bindings, revocation, reconciliation, rollback, retry, no-change and
  ambiguous-outcome handling. `data_use_provider_runtime.py` attaches those
  adapters to secret-provider custody and DNS-pinned exact-HTTPS transport;
  the admin API and `/data-use/providers` workspace never accept arbitrary SQL,
  client-supplied control IR, credentials, or origins. Provider writes remain
  separately opt-in and no live Snowflake/Databricks acceptance is claimed.
  The independently gated provider-audit plane pins an exact completed/no-
  change operation, provider binding, compiled IR, expected changes,
  independently issued read authority and credential revision. Its durable
  digest-only authority outbox is staged before provider I/O and finalized from
  exact adapter evidence; registration either commits or is returned honestly
  as `recovery_pending` for exact retry/scheduler recovery without repeating
  the provider mutation. Revision/integrity CAS, revocation reasons, fair
  persistent recovery cursors, audit-first retention, a credential bridge,
  bounded scheduler, operator routes and default app wiring are included.
  Snowflake and Databricks mutations carry canonical query tags, Snowflake
  retries use its documented retry flag, and provider statement handles are
  retained only as digests. Normalization distinguishes Snowflake
  `QUERY_HISTORY`/`ACCESS_HISTORY`, Databricks `system.query.history` primary
  statement evidence and supplemental `system.access.audit` request evidence;
  mixed references fail closed. The plane persists explicit matched/missing/
  extra/drift/ambiguity outcomes, leases, retry/dead-letter/replay and integrity
  without raw SQL, principals, addresses, credentials, statement IDs or
  provider payloads. It does not claim provider-log completeness or live
  interoperability. The dashboard supplies built-in DNS-pinned, redirect-
  disabled, byte/time-bounded Snowflake and Databricks audit transports.
  Snowflake reads and corroborates `QUERY_HISTORY` plus `ACCESS_HISTORY`,
  validates result metadata/partitions/counts, follows subsecond keyset
  pagination, and applies the documented source-retention and ingestion-delay
  boundaries. Databricks validates inline/chunked Statement Execution results,
  reads `system.query.history` plus supplemental `system.access.audit`, and
  requires an independently accepted delivery watermark before completeness can
  be asserted. Missing or stale authority yields incomplete/no-op evidence, not
  an invented match. Live tenant permission, latency, retention, continuous-
  operation, recovery, completeness, scale and customer acceptance remain
  required before this local path is production-proven; Databricks query tags
  remain a preview dependency.
- **Reviewed privacy-discovery to Data Use bridge**
  (`privacy_discovery_data_use_bridge.py`) — a default-off, tenant-bound bridge
  re-reads exact source, report, finding, independent review, asset and current
  context authority, then proposes and reconciles digest-only desired/no-change
  updates into only the `observed_classification` context. Revision/digest CAS,
  idempotency, interrupted-write recovery, immutable history, rollback,
  retention, hash-chained audit and SQLite index/payload integrity checks are
  explicit. Business-purpose, regulatory and consent contexts remain separate
  and are never inferred; the bridge performs no provider/network write and has
  not been composed or accepted in a live estate.
- **Privacy Automation data discovery** (`privacy_data_discovery.py`,
  `[privacy_automation.data_discovery] enable = true`) — a tenant-private,
  default-off coordinator for exact structured and unstructured source
  enrollments, credential/evidence-key references, schedules, bounded jobs,
  leases, recovery, retries, dead letters/replay, immutable completeness-
  explicit reports, keyed digest-only locations, deterministic personal-data
  detectors, inventory/diff, four-eyes classifications, audit and retention.
  Only fresh approved classifications can enter the separately composed
  `privacy_data_discovery_remediation.py` outbox. That digest-only authority
  double-reads source/report/finding/review pins and supplies leases, retry,
  dead-letter/replay, revocation/cancellation, ambiguity reconciliation,
  retention, audit/integrity and a network-free-by-default injected worker.
  The separately opt-in nested `remediation.scheduler` owns bounded active-
  tenant cycles, tenant/principal-derived worker identity, exact built-in target
  reconciliation before retry, durable interrupted-cycle recovery, interval/
  jitter/backoff, and process plus cross-process exclusion. Its API/UI status is
  tenant-gated and content-free. The scheduler never executes provider scans or
  provider writes. Live source acceptance, proprietary/binary document formats,
  estate completeness, continuously operated deployment, recovery/scale drills
  and customer acceptance remain separate.
- **Privacy regulatory intelligence**
  (`privacy_regulatory_intelligence.py`,
  `[privacy_automation.regulatory_intelligence] enable = true`) — an exact-
  tenant, licensed-source authority with independent source-rights approval,
  revocation, immutable/versioned legal documents and provenance, purpose-
  specific use controls, citation-grounded search/research and jurisdiction
  comparison, evidence-floor abstention, ACL collections, revocable scoped
  shares, saved-query trackers, deterministic alerts, a leased retryable
  delivery outbox, an explicit opaque-destination-to-SMTP worker with
  at-least-once/acknowledgement-ambiguity evidence, exportable evidence
  reports, retention, and retained-state integrity verification. The REST surface and
  `/privacy/regulatory-intelligence` console never claim bundled DataGuidance
  content or legal advice. Licensed feeds, proprietary content, delivery
  transports, legal-content acceptance, and multi-node operation remain
  external dependencies.
- **Privacy-rights request orchestration**
  (`privacy_rights_orchestration.py`, `[privacy_automation] enable = true`
  plus `[privacy_automation.rights_orchestration] enable = true`) — an exact-
  tenant local control plane for reference-only source enrollment, raw-to-HMAC
  case intake, externally evidenced identity status, legal holds and retention
  gates, rights-derived source tasks, independent destructive-work approval,
  leased callback intent, evidence receipts, completeness-explicit manifests,
  encrypted response-package metadata, four-eyes closure, exports, retention,
  and integrity verification. The strict REST surface and
  `/privacy/rights-orchestration` workbench bind tenant and a stable opaque
  principal digest server-side. This orchestration module performs no network
  I/O, provider write, actual identity verification or response delivery and
  retains no raw subject. The separate delivery path below does not turn local
  callback intent into live-provider or estate-completeness acceptance.
- **Stock privacy-rights source runtime**
  (`privacy_rights_source_worker.py`, `privacy_rights_source_adapters.py`, and
  `privacy_rights_source_composition.py`; additionally gated by
  `[privacy_automation.rights_orchestration.source_adapters] enable = true`) —
  opt-in Microsoft Graph, Google Workspace, Salesforce and ServiceNow source
  contracts resolve raw subjects and credentials only through deployment-owned
  request-time authorities. Mutations use a read-only unique-ID preparation,
  encrypted exact-target custody and a `BEGIN IMMEDIATE` one-time dispatch
  reservation that becomes reconciliation-only before provider I/O. Source
  revision/integrity, adapter and credential references, adapter authority,
  provider contract, operation digest and target binding remain in immutable
  evidence. Active-record 404 responses do not prove erasure: Graph deleted
  items and Salesforce `queryAll` distinguish soft deletion from purge, while
  providers without a hard-purge contract remain retention-unknown. Retrievals
  enter the encrypted governed-document vault through an operation-idempotent
  receipt index. Claims are restricted to configured source IDs, empty polls
  are not persisted, claim history is minimized and retention-bounded, and
  runtime batch/lease/retry values are capped by server configuration. Status
  reports configuration preflight separately from credential-checked
  executable readiness. Local adversarial tests cover duplicate dispatch,
  process exit, lease overlap, hold/source drift, identifier reuse, soft-delete
  retention and post-ingest recovery; live provider/customer acceptance and
  whole-estate completeness remain external.
- **OTT/CTV consumer-rights bridge** (`privacy_rights_ott_ctv.py`,
  `privacy_rights_ott_ctv_api.py`,
  `[privacy_automation.ott_ctv_rights] enable = true`) — a selector-free
  public service-client path requires a fresh, exact redeemed OIDC/device
  pairing and revalidates the linked profile, current publication/policy,
  Trust Center `rights_cases` context/grant and service-client authority before
  creating idempotent access or deletion cases in the existing rights
  orchestrator. Effective authority expires at the earliest identity, pairing,
  Trust Center or client expiry. Pairing, account transition, grant or client
  revocation fails closed; interrupted planning recovers; signed status and
  persistence are digest-only; and controlled expiry/purge is explicit.
  Deletion still requires the orchestration store's independent destructive
  approval and remains blocked by legal hold. This is a focused-test-covered
  local control-plane bridge, not a native TV/mobile SDK, household/device sync
  product, built-in provider retrieval/deletion adapter, retrieved-data
  delivery path, or live device/provider/customer acceptance result.
- **One-time privacy-rights consumer delivery**
  (`privacy_rights_consumer_delivery.py`,
  `[privacy_automation.rights_consumer_delivery] enable = true`) — a default-off
  authority double-reads exact closed-case, identity, completeness, redaction,
  callback and response-package evidence; mints a raw consumer capability once
  while persisting only its digest; binds subject, reauthentication, case,
  package revision/digest, expiry, retry limits and request context; atomically
  redeems without selectors; and immediately converts the capability into an
  opaque one-time server grant. Revocation, retention, immutable audit,
  integrity and signed metadata export are explicit. The authenticated operator
  API/workbench exposes status, one-time mint, digest-only lookup, revoke,
  export, purge and integrity but no capability list/readback, redeem, grant,
  object-byte, credential or provider-write route. The public consent API and
  SDK accept reauthentication only in a dedicated header, claim the server
  grant immediately, and return bounded package bytes only after an injected
  adapter's content hash matches the pinned package digest. The production
  composition lazily opens tenant/principal-bound stores, pins digest,
  export-signing and package-encryption key references, re-resolves the exact
  orchestration case/package, and adapts the stock encrypted governed-document
  vault populated by privacy-rights retrieval. Vault document authority,
  record type, object reference, package digest, revocation state and package
  metadata are checked before vault grant issue, again before consumption and
  again before response bytes are returned. Public subject binding comes only
  from the independently reauthenticated public profile, while a strict
  deployment-owned identity verifier must attest the reauthentication receipt.
  Operator mint remains fail-closed until a production IdP-backed
  operator-to-consumer mapping is injected; the case/package authority is never
  accepted as identity proof. Live IdP, KMS/HSM, browser/customer, recovery/load
  and external object-store acceptance remain separate operational evidence;
  durable replay after a process failure between one-time server-grant claim
  and HTTP response completion still requires a separately reviewed protocol.
- **Privacy-notice governance** (`privacy_notice_governance.py`,
  `[privacy_automation] enable = true` plus
  `[privacy_automation.notice_governance] enable = true`) — an exact-tenant,
  content-free authority for role/quorum/TTL approval policies, independently
  reviewed digest-bound notice releases, approval revocation, scheduling,
  leased retry/dead-letter publication intents, rollback and withdrawal,
  cited regulatory-update proposals, effective-version resolution, signed
  exports, retention, and integrity verification. The strict REST surface and
  `/privacy/notice-governance` workbench derive tenant and principal
  server-side and expose a live lease token only from an explicit claim. The
  companion `privacy_notice_publication_bridge.py` consumes exact claimed
  publish/rollback/withdraw intents through constructor-bound tenant and target
  authority, pins release/rule/notice/bundle digests, and drives the local
  `consent_publishing.py` compare-and-swap lifecycle, including fail-closed
  withdrawal tombstones and exact lost-response recovery. The opt-in dashboard
  production composition adds named exact tenant/property/consent-reference/
  rule-group-version/notice-resource-version bindings, tenant-private store
  factories, independent authority re-reads, exact-digest rollback resolution,
  and a bounded app-lifespan scheduler with durable recovery/retry status plus
  in-process and cross-process cycle exclusion. Authenticated status and
  run-once routes and the liquid-glass operator card never accept a tenant or
  target from the request. See `PRIVACY_NOTICE_PUBLICATION_RUNTIME.md`. Both
  stores remain non-atomically committed. The modules accept no raw notice content or
  signing-key value and perform no network transport, consent-provider write,
  SDK deployment, site/app/native mutation, legal applicability decision, or
  live acceptance.
- **Third-party intelligence and due diligence**
  (`third_party_intelligence.py`,
  `[third_party_management.intelligence] enable = true`) — provider-neutral,
  independently approved source enrollment and revision-bound snapshots;
  encrypted-profile references and vendor relationships; sanctions, PEP,
  watchlist, adverse-media, cyber-posture, breach, compliance, and performance
  screening with cited evidence and independent match disposition; immutable
  approved risk-policy versions; explainable decisions; guarded low-risk
  autoapproval, override, and rollback; EDD cases, tasks, evidence, escalation,
  and decisions; continuous-monitor change detection with a leased retryable
  outbox and explicit opaque-destination-to-SMTP worker with at-least-once and
  acknowledgement-ambiguity evidence; and explicit-consent,
  inclusion/privacy-reviewed, revocable risk-
  exchange contributions with lineage and purpose/audience controls. The six
  mandatory screening kinds must all be complete and fresh before any policy
  may autoapprove. The strict REST surface and
  `/third-party/intelligence` workspace bind tenant and principal server-side;
  outbound delivery is a confirmed operator action that fails closed without
  an injected opaque destination resolver. No commercial corpus, provider
  credential value, live feed, proven anonymity, production provider
  acceptance, operated notification transport, or ecosystem scale is bundled
  or inferred.
- **Named third-party provider-feed runtime and scheduler**
  (`third_party_intelligence_providers.py`,
  `third_party_intelligence_runtime.py`, and
  `third_party_intelligence_provider_composition.py` plus
  `third_party_intelligence_scheduler.py`; additionally gated by
  `[third_party_management.intelligence.providers] enable = true` and
  `[third_party_management.intelligence.providers.scheduler] enable = true`)
  — closed normalized reference-feed contracts cover the RiskRecon,
  SecurityScorecard, HackNotice, SupplyWisdom and ISS Corporate Solutions
  concepts plus one deployment-approved generic provider. SupplyWisdom and ISS
  require exact deployment-enrolled bare hostnames; no package default guesses
  a customer-specific licensed authority. Each adapter fixes the HTTPS host,
  GET method, path and response schema; binds tenant, provider, source
  revision/digest, monitoring capability and credential-key ID; bounds pages,
  cursors, bytes, records, and elapsed time; and rejects redirects, drift,
  cycles, duplicates, malformed schemas and any explicit incompleteness. The
  bundled production composition uses the project DNS-pinned egress policy,
  deployment-held secret references and current approved source revisions. It
  is attached to dashboard startup/shutdown, exposes side-effect-free status
  plus an admin-only source credential check, and drives the default-off cross-
  tenant scheduler. The durable tenant-local runtime adds deterministic jobs,
  leases, retry/backoff, dead-letter/replay, no-change handling, revocation,
  idempotency, minimized receipts, immutable retained history/audit, integrity
  checks and acknowledgement-boundary recovery while writing observations only
  through the existing source-snapshot and monitor/alert/outbox authority.
  These are normalized reference contracts, not accepted vendor-native
  integrations. No raw credential or provider page is persisted, no provider
  write or automatic vendor/risk conclusion occurs, and no licensed/live feed,
  vendor-native interoperability, notification operation, continuous recovery,
  portfolio-scale exercise, or provider/customer acceptance is claimed.
- **Third-party lifecycle and conditional assessments**
  (`third_party_lifecycle.py`,
  `[third_party_management] enable = true` plus
  `[third_party_management.lifecycle] enable = true`) — an exact-tenant,
  provider-neutral local control plane for immutable versioned questionnaire
  templates, independent approval, conditional required questions, assigned
  evidence-backed responses, deterministic routing and remediation tasks;
  lifecycle transitions, dependency-bound offboarding, legal holds, independent
  completion, callback intent leasing/dead letters, evidence exports, retention,
  and integrity verification. The strict REST surface and
  `/third-party/lifecycle` operator workbench bind tenant and a stable opaque
  principal digest server-side and reject caller-authored tenant or actor data.
  Callbacks are governed intent only: no network transport worker, provider
  write, raw vendor profile or credential handling, live provider acceptance,
  or live customer acceptance is implemented or claimed.
- **Technology-risk compliance scoping** (`compliance_scoping.py`,
  `[tech_risk_compliance] enable = true` plus
  `[tech_risk_compliance.scoping] enable = true`) — an exact-tenant local
  control plane for immutable closed questionnaires, independent publication,
  conditional required-question traversal, digest-and-reference evidence,
  deterministic scope computation, responsibility assignments, overlap and
  crosswalk views, independent approval, original-computer finalization,
  signed local exports, retention, and integrity verification. The strict REST
  surface and `/compliance/scoping` operator workbench bind tenant and a stable
  opaque principal digest server-side; caller-authored tenant, actor, raw
  evidence, framework prose, secret values, and signing-key values are not
  accepted. Signing input is an opaque `env:`, `vault:`, or `secret:` reference
  only. No licensed framework text, legal advice, external discovery,
  certification, network I/O, provider write, live provider acceptance, or live
  customer acceptance is implemented or claimed.
- **Technology-risk compliance scope actions**
  (`compliance_scope_actions.py`, `[tech_risk_compliance] enable = true` plus
  `[tech_risk_compliance.scoping] enable = true` and
  `[tech_risk_compliance.scope_actions] enable = true`) — an exact-tenant local
  authority, strict REST surface and mounted `/compliance/scope-actions`
  workbench translate an exact independently finalized scope through an
  independently approved opaque mapping catalog into deterministic reason-
  coded control and measurable evidence-task plans. Scope, assessment, catalog
  revisions and digests are pinned; shared evidence is deduplicated; first-
  line, second-line, control-owner and evidence-owner assignments are retained;
  and plan approval, apply/no-change, reconcile, rollback, history, signed
  export, retention and integrity paths are explicit. Apply requires a server-
  installed idempotent callback, callback and authority stores are not atomic,
  and no licensed framework prose, network/provider write, legal conclusion,
  certification or live acceptance is included or inferred.
- **Tech Risk & Compliance continuous evidence**
  (`trc_evidence_collectors.py`, `trc_continuous_evidence.py`,
  `trc_stock_evidence_collectors.py`,
  `trc_stock_evidence_composition.py`,
  `trc_continuous_evidence_scheduler.py`, the strict operator API and the
  `/compliance/continuous-evidence` liquid-glass workbench;
  `[tech_risk_compliance.continuous_evidence] enable = true`) — independently
  approved collector definitions and exact asset, credential, control and
  capability pins feed a tenant-local leased job authority. In addition to the
  digest-only local SOC 2 observation collector, the config-driven production
  composition installs normalized read-only collectors for AWS Security Hub,
  AWS Config, Azure Defender, Azure Policy, Google Cloud Security Command
  Center, GitHub security streams and Okta posture. Each source manifest pins
  an independently created enrollment and collector-definition version and
  integrity digest, enrolled origin/scope, capability revision, collector key,
  credential reference and control bindings. The shipped HTTP path is DNS-
  pinned and redirect-free, applies page/time/byte limits, resolves credential
  values only at execution, and persists normalized digest-only evidence rather
  than raw provider responses. The runtime preserves
  terminal cursor/completeness state, normalized observation equality,
  incomplete/truncated outcomes, retries, recovery, dead letters/replay,
  cancellation, retention, immutable histories, operations and hash-chained
  audit. A bounded active-tenant scheduler is separately gated, rejects
  overlapping cycles and invalid tenant aliases, isolates job/tenant failures,
  and is composed into dashboard startup/shutdown with status and an explicit
  run-once operator action. Config lint, installer selection and Copilot cover
  the same closed provider set; the installer intentionally does not invent
  tenant scopes, definition digests, enrollment authority or credential
  references. Readiness is a configuration/credential-reference preflight: it
  performs no provider request or credential-value resolution, and each job
  still rechecks the current approved definition and active exact enrollment.
  Observations are technical evidence only: the module writes no compliance
  conclusion, certification or control-implementation state. No live provider
  tenant was contacted and provider interoperability, estate completeness,
  continuous operation, outage/recovery, concurrency, scale and customer or
  auditor acceptance remain unverified.
- **Tech Risk & Compliance evergreen policy links**
  (`policy_publication_links.py`,
  `[tech_risk_compliance.policy_publication_links] enable = true`) — immutable
  versioned plain-text policy artifacts; configurable approval/four-eyes review;
  stable opaque public/private links; one-time private bearer capabilities;
  compare-and-swap publication pointers; rotation/revocation; scheduled
  publish/expiry/revoke jobs; fail-closed retrieval-time expiry; deterministic
  escaped HTML/text; tenant-scoped access evidence; hash-chained audit; and
  retention/integrity operations. The authenticated admin API and
  `/compliance/policy-links` workspace are separate from the narrowly exempt
  `/api/v1/public/policies/{link_id}` retrieval route, which accepts no tenant or
  policy selector. A live edge/CDN, customer usability, recovery, concurrency,
  and scale acceptance campaign is not claimed.
- The consent/data-use foundation is **not a complete accepted CMP/UCPM or
  production data-control service**: production IdP/JWKS and subject-digest
  custody plus live identity acceptance,
  governed logo/media/custom-domain branding, integrated DSR intake, built-in
  object/provider delivery,
  complete pre-consent tag-manager enforcement, named downstream MarTech/AdTech
  adapters, native mobile/OTT SDKs, complete TCF/GPP sections, shared-database
  scale, and live customer/legal/provider acceptance remain separate work.
- **Secure by default** (`security_defaults.py`, `MAVERICK_SECURE_DEFAULT` /
  `[security] secure_defaults`) — the protective controls that don't break the
  happy path ship **on**: at-rest encryption (auto-key), audit-log signing
  (auto-key), fail-closed consent for high/critical-risk actions, and a `high`
  tool-risk ceiling (CRITICAL needs an explicit raise). Precedence: compliance
  floor > explicit arg > env > config > the secure-by-default switch; opt out per
  control or flip the whole posture off. OIDC, the egress lock, and Postgres RLS
  stay opt-in; the Shield stays fail-open. See `docs/security-hardening.md`.
- **Shield** at 3 chokepoints (input / tool-call / output); built-in rule set
  fail-open if the SDK isn't installed.
- **Floors** — secret detector, PII detector, jailbreak heuristics, unicode /
  zero-width filter, remote-content scan, output-policy classifier
  (regurgitation + refusal-leak), **phishing-content detector** (credential-harvest
  + deceptive-link heuristics, composed into `Shield.scan_output`),
  **operator-defined constitutional rules** (custom regex policy via `[safety]
  constitution`, `maverick_shield/constitutional.py`),
  Constitutional-Classifier-v2 cascade (`safety/`, `maverick_shield/`) — whose
  heuristic cheap probe can ensemble a **trained classifier**
  (`maverick_shield/probe_model.py`): plain-JSON linear weights over the probe's
  named features (no pickle → loading an operator model can't execute code),
  combined by MAX so the model only raises recall, opt-in via `[shield]
  probe_model` / `MAVERICK_SHIELD_PROBE_MODEL`, with validated content-digest
  refresh, finite failure retry and explicit stale-model status
  ([reload policy](operations/shield-probe-reload.md)),
  **voice safety pass** (`safety/voice_safety.py`): transcript screen for
  wake-word stuffing + spoken role-switch before an utterance drives the
  agent, and redact-before-speak (secrets/PII never read aloud) wired into
  the `speak` tool, **image-content classifier**
  (`tools/image_content_classifier.py`): model-free pixel heuristics — skin-
  tone ratio (NSFW pre-filter routes to human review), brightness extremes,
  photo-vs-graphic, dimension sanity — file decode via Pillow or raw pixels
  with no imaging dep.
- **Confidential-compute detection** (`confidential_compute.py`, `maverick
  confidential-compute`) — detects whether the process runs inside a hardware
  confidential VM (AMD **SEV-SNP** / Intel **TDX**) from standard guest
  indicators (`/dev/{tdx,sev}-guest`, TDX firmware sysfs, TDX guest CPU flag;
  AMD SEV CPU capability flags alone are not treated as guest proof), so a regulated
  deployment can verify (and gate on) hardware memory encryption; exits non-zero
  when not confidential.
- **Air-gap preflight** (`air_gap.py`, `maverick airgap check`) — verifies a
  deployment has no outbound path in *Lightwork's own config*: a remote model
  provider, a non-deny-all egress policy, or a sandbox with network access — and
  exits non-zero on any finding so it can gate a deployment. (OS-level air-gap
  is the operator's job; this catches the application-layer leaks.)
- **Shield ensemble** (`shield_ensemble.py`) — a **deny-wins detector ensemble
  with explainable reason codes** (the Shield-v3 framework): pluggable members
  screen a blob (injection via the jailbreak heuristics, exfil via the secret
  detector, PII via the PII detector) and any one firing blocks, with a
  structured `reason_codes` list saying *which* detector objected and *why*
  rather than an opaque refusal. A member is a small pluggable unit, so a
  trained small-model classifier drops in behind the same interface later.
- **Access control** — tool ACLs, consent prompts + a persistent **consent
  ledger** (`safety/consent.py`; `MAVERICK_CONSENT_MODE` =
  auto-approve / auto-deny / ask / dashboard), capability tokens
  (`capability.py`), **per-call token exchange** (`tool_token.py`, opt-in
  `[capabilities] per_call_tokens` / `MAVERICK_TOOL_TOKENS=1`): each tool call
  *exchanges* the run-long grant for a freshly minted, single-tool-scoped,
  short-lived (default 30s), single-use, Ed25519-signed token — verified before
  dispatch and recorded as a `token_exchange` audit row — so a mid-run
  compromise can only ever wield one tool for a few seconds, not the whole
  grant (zero-trust "token exchange for every tool call", mapped onto our own
  capability + audit-signing primitives — no new deps; fail-open and a no-op
  unless enabled), role-based access control over capabilities, the
  `self_capability` self-report tool, **capability boot negotiation**
  (`capability_boot.py`): a spawned child may declare a narrower requested
  scope (tools/max_risk/paths/hosts), and `negotiate_boot` resolves it against
  the parent grant narrow-only (never gaining authority the parent lacked),
  records the handshake, and fails the spawn when a *required* capability
  isn't grantable, **capability revocation**
  (`revocation.py`, `maverick capability revoke/unrevoke/revocations`): kill a
  still-valid grant before its TTL — the tool chokepoint denies a revoked
  principal's next call, and the list is re-read on change so a revoke in
  another process reaches agents already mid-run; `revoke_subtree` walks the
  delegation graph to revoke a principal and every descendant it spawned
  (fail-open, like the opt-in capability layer), **approval delegation rules**
  (risk/scope-based suggested reviewers, not enforced decision authority,
  `approval_delegation.py`), per-tool network egress
  policy (`sandbox/network_policy.py`), `maverick whoami`.
- **Out-of-process model proxy** — `model_proxy.py` (`python -m
  maverick.model_proxy`, `[model_proxy] upstream/auth_style/client_token`): a
  separate process holds the provider key (from its **own** env,
  `MAVERICK_PROXY_KEY`) and the agent points a provider's `base_url` at it. The
  agent process never holds the provider credential — a prompt-injected agent
  can't exfiltrate a key it doesn't have. The listener requires the agent to
  present a separate proxy client token (`MAVERICK_PROXY_CLIENT_TOKEN` or
  `[model_proxy] client_token`), strips that client auth + hop-by-hop headers,
  injects the real key in the upstream's scheme (bearer / `x-api-key`), and
  forwards only to its single configured upstream host plus model-inference
  routes by default (override with `[model_proxy] allowed_routes` or
  `MAVERICK_PROXY_ALLOWED_ROUTES`).
- **Audit & compliance** — signed append-only audit log (`maverick audit verify`).
  Includes date-windowed **SIEM export**, **WORM export** (`audit/worm.py`, `maverick audit
  worm push`) — ships closed day-files to S3 Object-Lock (COMPLIANCE/GOVERNANCE)
  or a local read-only mirror with a retention lock, so the historical trail is
  *immutable*, not just tamper-evident; `maverick audit worm verify` proves every
  closed file is durably shipped, encryption-at-rest (`crypto_at_rest.py`,
  `maverick encryption migrate`), SOC2 readiness (`soc2.py`), DSAR (`dsar.py`),
  **differential erasure verification** (`erasure_verify.py`, `maverick
  erase-verify`) — a right-to-erasure *proof*: combines exact post-delete
  counts with an immutable signed pre-delete scope receipt and a bound signed
  completion record for attachment files, user notes, the disposable LLM
  cache, and audit-chain maintenance. Any missing, failed, or tampered proof
  surface yields `INDETERMINATE`, never a false clean certificate. The
  before/after `differential` also confirms the erase actually removed data,
  **data-retention enforcement** (`audit/retention.py`, opt-in `[retention]`
  config, `maverick retention enforce [--dry-run]`) — prunes audit files,
  `episodes`/`goal_events` rows, **and the usage-ledger cost buckets**
  (`usage_days`: the per-principal `(principal, day)` chargeback tally accrues
  forever otherwise),
  per-run file-write + tool quotas, `maverick compliance --strict`, CycloneDX
  SBOM in CI.
- **Regulatory compiler — compliance by construction**
  (`regulatory_compiler.py`, `maverick regulatory show|check|verify`,
  `python -m maverick.regulatory_compiler --ci`, dashboard **Compliance →
  Regulatory Obligations** at `/compliance/obligations`: what is compiled, the
  anti-vacuity proof, a library preview per regulation, and "check an action"
  answered from the compiled policy — read-only by design, enforcement is
  chosen in config) — a policy document says what
  must not happen; this makes it *unable* to happen. Each regulation is a small
  library of obligations — a citation, a scope (tool names or a risk floor) and
  an effect — compiled into the same `Policy` the tool-call chokepoint already
  evaluates (deny-wins, strictest-wins) plus a capability attenuation that can
  only narrow and that every spawned child inherits. Shipped: **GDPR** (Art. 17
  erasure only through the governed path — a direct write to a personal-data
  store pauses for a human; Art. 32 a human confirms every outbound transfer;
  Art. 22 no solely automated high-impact decision), **EU AI Act** (Art. 14
  human oversight of every high-risk action), **HIPAA** (45 CFR 164.502(b)
  minimum necessary — PHI never leaves through an ungoverned channel, as an
  attenuation no ACL or role can widen). Activation is `[compliance] profiles`,
  the switch the compliance profiles already use, with a wizard step. Two
  things a document cannot do: **evidence the gate decision** — emitted denial
  rows retain `obligation_id`/`regulation`/`article`, and every admitted dispatch
  has mandatory `obligations_checked` attempt evidence. A trust receipt may cite
  that attempt; an executed/failed claim additionally requires its paired
  terminal result. **Anti-vacuity**: `verify` checks that each
  active obligation bites (every bound tool is a classified tool, the compiled
  policy denies or pauses it, a floor catches a real tool, an attenuation
  narrows a capability); the CI gate fails on a stale tool name or a silent
  overlay and exits 2 when it inspected nothing. Conduct prohibitions (EU AI
  Act Art. 5) stay the packs' hard refusals; this does not pretend a tool gate
  covers them.
- **Compliance mode profiles** — `[compliance] profiles = ["hipaa"]` turns on
  a cross-domain runtime posture (`compliance_profiles.py`): **HIPAA mode**
  asserts the 45 CFR Part 164 safeguards, names the protection floors it
  requires (PII redaction, encryption-at-rest, egress lock, audit), and folds
  a require-human-on-high-risk policy into the live governance policy
  (strictest-wins, via the same union the finance regimes use). Inert when
  unset — default behavior is unchanged.
- **Shield call rate-limit per goal** (`safety/shield_rate_limit.py`) — opt-in
  `[safety] shield_rate_limit = "100/60"` sliding-window token bucket per goal;
  throttling SKIPS the scan fail-open (the shield never blocks the agent by
  being busy), with once-per-window suppressed-call alerts.
- **Goal risk-tier auto-classifier** (`safety/goal_risk.py`) — deterministic
  low/medium/high scoring of a goal's wording before it runs (money/infra/
  credential/bulk-comms/PII/irreversibility signals, read-only de-escalators,
  documented weights). Every goal's tier is recorded on its start audit event
  and shown on the task list. `[safety] goal_risk_require_human` (off by
  default) holds risky-looking goals on the Approvals page until a person
  decides; `goal_risk_floor` raises every goal to a minimum tier. A lexical
  tripwire only: per-action gates still apply.
- **Containment mode** (`containment.py`, opt-in `[containment]`, the
  dashboard's "Locked-down mode") — lock every run into no-egress + ephemeral
  0700 workspace: when on, the tool registry denies the exfil tools (config
  *extends*, never replaces the default deny set), `build_sandbox` turns
  container networking off and gives the run a throwaway folder, the local
  backend black-holes the proxy env for subprocesses (advisory; the
  load-bearing layer is the ACL + container backends' network deny), and the
  task budget is capped at `max_wall_seconds`.
- **Cryptographic budget receipts** (`budget_receipts.py`) — HMAC-signed,
  hash-chained spend receipts per goal (prev-hash inside the signed payload
  so deletion/reorder is unforgeable; append-only 0600 ledger; refuses to
  mint unsigned), verify + chain verification with break index.
- **Quorum approval for config changes** (`quorum.py`) — N-distinct-approver
  gate over protected config keys (fnmatch patterns; self-approval and
  duplicate approvers refused; required count snapshotted per proposal so
  policy edits can't shrink a pending quorum; TTL-pruned proposals).
- **Capability-leak fuzzer** (`capability_fuzzer.py`) — seeded adversarial
  probes (case/homoglyph/prefix/separator/NUL/glob/long-name) against
  Capability.permits; CI `python -m maverick.capability_fuzzer` exits 1 on
  any leak. Run against the real implementation: **0 leaks in ~2000 probes**.
- **Provider-level cost caps** (`provider_cost_cap.py`, `[budget.provider_caps]`)
  — provider-period capacity is reserved atomically for each physical LLM call,
  including hedges, alongside run budgets and principal quotas. Settlement
  uses response-local usage; crash holds never expire, unknown final charges
  and unreadable configured accounting block admission. Local files use a
  required-state marker; shared PostgreSQL uses transactional counters and
  receipts with no local fallback. Prices remain estimates of external billing.
  Global administrators can review exact receipts and isolated complete local
  accounting repair in [Provider spending](provider-spending.md), reached from
  Workspace recovery; no provider call is automatically retried.
- **Supply-chain pinning** (`supply_chain.py`) — pin the deployment's Python
  dependency tree (`write_pins` → 0600 JSON), verify drift/missing/unpinned
  (`verify`/`render` PASS-FAIL), opt-in startup warning via
  `[safety] supply_chain_pinning` (never raises).
- **Crash-only logging** (`crash_only_log.py`) — append-only JSONL safe to
  kill -9 at any byte: one fsync'd `os.write` per record, seq resumes after
  reopen, replay tolerates (and counts) the torn tail vs mid-file corruption,
  gap detection; fsync policy knob for test/throughput mode. Live sink:
  `[logging] crash_log` keeps a crash-safe copy of warnings and errors
  (`logging_config`).
- **Tamper-evident screenshots** (`screenshot_seal.py`) — every capture is
  sealed into a per-directory hash-chained, HMAC-signed ledger (replace /
  edit / delete / reorder all detectable; re-capture legitimately
  supersedes); wired into the computer tool's screenshot path, opt-in purely
  by key presence (`[safety] screenshot_key`), best-effort so evidence
  capture never breaks the screenshot the model is waiting on.
- **Red-team CI** — a named CI job (`redteam` in `ci.yml`) runs the labelled
  adversarial corpus (`maverick_shield/redteam_corpus.jsonl`, grow-by-PR)
  through the shield's built-in detector via `python -m maverick_shield.redteam`
  and fails the build on any missed attack or over-blocked benign case.
- **Shield calibration dashboard** — the same runner swept across every block
  threshold yields the operating curve (recall/precision/fp-rate per
  threshold) + per-rule hit counts: `--calibrate` CLI and
  `GET /api/v1/shield/calibration` on the dashboard (auth-gated; operator
  corpus via `MAVERICK_REDTEAM_CORPUS`).
- **Sandbox-escape canaries**, per-tool rate limiter, killswitch.

## Governed agent runtime and onboarding

- **Conversational intake** — interviews a user, collects docs, and proposes a
  domain configuration (intake agent + LLM proposer + `run_intake`).
- **Capability provisioning** (`provision.py`) — the agent factory equips a
  pack *at birth*, not reactively mid-run: `analyze_profile` diffs a draft's
  workflow + declared `allow_tools` against the installed skills and live tool
  registry (`tools.base_tool_names()`) and surfaces the gaps at the approval gate;
  on approval, `apply_plan` installs the matching catalog skills
  (`self_learning.acquire_skill`) and synthesizes any missing declared tools
  (`self_learning.write_generated_tool` — stdlib-only, import-validated
  out-of-host, consent-gated). Analysis is read-only and always safe; applying
  it is gated on `[self_learning] enable` + the new `provision_packs` sub-knob
  (wizard step) + the same human approval `save_profile` requires, and never
  widens the pack's already-clamped envelope.
- **Programming by demonstration** (`demonstration.py`) — the factory's second
  front door: watch a person do their job, then build the agent that does it. A
  `Demonstration` is an ordered record of observed actions + narration (from any
  capture front-end), ingested by `parse_demonstration`/`load_demonstration`
  (JSONL or prefixed text like `ACTION[email]: send digest -> ops@`;
  secret-redacted at the door, byte/step-bounded, and fail-soft — a malformed
  or oversized capture drops bad lines rather than raising).
  `induce_profile` turns it into a `DomainProfile`
  by reusing the intake pipeline wholesale — it builds the same
  `propose(spec) -> dict` and routes through `generate_profile` →
  `validate_profile`, so a demonstrated pack inherits the identical envelope
  clamp + persona shield-scan as a described one. LLM path (model proposes from
  the transcript) and deterministic path (workflow mirrors the steps, tools =
  what the person used) both supported; a human review gate is always appended.
  CLI: `maverick learn-demo <file>` → induce → approve → save → provision.
- **Self-improving factory** (`factory_learning.py`) — closes the loop back onto
  *generation quality*. Provisioning/approval gaps (a tool a draft kept omitting,
  a skill its workflow kept needing) are attributed to the pack's suite and
  mined into proposer **corrections**; each is promoted through the existing
  `SelfImprovementController` on the `prompt` rung (guidance text widens no
  capability, so no escalation proof or human sign-off is required — only the
  evidence + calibration gates), and promoted guidance is folded into future
  pack generation (`augment_system_prompt`, scope-matched per suite). Default-on
  and byte-identical to before while disabled; gated by `[self_improvement]
  enable` + the `factory_learning` sub-knob (wizard step) or
  `MAVERICK_FACTORY_LEARNING`. Live promotion requires self-digested v2 paired
  evidence with immutable data/split/evaluator/model/prompt provenance and uses
  the shared PREPARE/CAS/COMMIT promotion ledger; v1 evidence is preview-only.
  CLI: `maverick factory-learn [--dry-run]`.
- **Governed adapter rung — in-tenant weights** (`adapter_rung.py`,
  `[adapter_rung]`) — LoRA adapters for a LOCAL open-weights base, trained on
  tenant-provenance data and promoted through the existing `weights` rung.
  Training data passes a provenance boundary (frontier-model output refused by
  default — the distillation-ToS guard; synthetic opt-in; unknown always
  refused) and is content-hashed into the manifest. The payload passes a
  hygiene boundary BEFORE any eval (safetensors/gguf/json/text only; code and
  pickle-bearing formats refused structurally, so weights can never smuggle
  executable authority). Fitness is held-in/held-out with the code rung's
  overfit refusal; the Ed25519 approval payload EMBEDS the weights digest
  (a post-signature weights swap stops verifying); promotion lands in the
  append-only ledger; activation is an atomic pointer swap whose previous
  pointer is the byte-identical one-step rollback handle. Serving: a rendered
  Ollama Modelfile (`ADAPTER`) + emitted `ollama create` command; the Ollama
  provider client resolves base → tuned at request-build time
  (`adapter_rung.effective_wire_model`, mtime-cached, fail-open), so spec
  parsing, admin allow-lists, pricing, and telemetry keep the stable base
  model id. Trainers:
  `stub` (deterministic; proofs/tests) and `dpo-lora` (delegates to
  `training/rlaif.py`, `[training]` extra). OFF by default AND inert until
  `base_model` is set (never hard-coded; wizard suggests an Apache-2.0 base).
- **Governed specialist-model improvement** (`training/environments.py`,
  `training/specialist_models.py`, `training/qualification.py`,
  `training/receipts.py`, `[model_improvement]`) — locked deterministic PIA,
  DSAR, and Article 28 environments; structured tenant consent and redaction
  evidence; strict source-span citation rewards; immutable-revision candidate
  research; non-weakenable exact runtime/hardware qualification; and
  dual-signed, hash-chained, tenant-private training receipts verified against
  server-owned trust policy. Public seed packs are bakeoff fixtures and
  deliberately fail promotion readiness because their holdout answers are
  published. Cross-tenant training is refused. No external training-backend
  integration ships: `environments.export_rows` returns backend-neutral rows
  and refuses sealed answers, and an operator-provisioned backend records its
  run in the training receipt. Live pointers bind the effective policy and
  resolve approver fingerprints through global deployment trust. The complete
  design, model matrix, and rollout gates are in
  [`MODEL_IMPROVEMENT_PLATFORM.md`](./MODEL_IMPROVEMENT_PLATFORM.md).
- **Domain packs** — spawn domain agents from profiles (legal / privacy / generic
  packs) on the sector-seal foundation.
- **Pack output contract** — a pack's optional `[output]` block declares the
  *consumption* side of the deliverable: its render `shape` (prose / report /
  table / forecast), a human `deliverable` label, the `consumers` (persona
  roles who receive it), a `cadence`, and the `gate` (review / approval) it
  needs before it is acted on. Additive and lint-checked (`OutputContract` in
  `domain.py`); absent means today's behaviour — a free-text prose result with
  no declared consumer. The dashboard reads it to render, route, and gate a
  result by domain rather than showing every output as the same text box.
- **Deliverable rendering** — the goal page (`/chat/goal/<id>`) renders a
  result as the artifact its pack declares: a `forecast`/`table`/`report` shape
  whose result carries a grid becomes a real titled, gated `<table>` (the FP&A
  13-week cash forecast lands as a week-by-week grid, not a wall of monospace),
  while `prose` and contract-less goals keep the plain text result. Server-side
  and dependency-free (`deliverable.py` parses the pipe table agents emit; cells
  go through template autoescaping), so a malformed or table-less result
  degrades gracefully to prose.
- **Artifacts** — a goal can produce versioned, kind-tagged artifacts
  (markdown / code / table / text) stored apart from the single `goal.result`
  blob (v18 `artifacts` table; `add_artifact` / `latest_artifacts`, title
  plaintext for version-keying, content encrypted at rest). The goal page shows
  the latest version of each, rendered by kind — a `table` artifact as a grid
  (reusing the deliverable renderer), others as text — with a per-title version
  count; `GET /api/v1/goals/<id>/artifacts` lists them. Governed take on
  Claude-style artifacts: rich *rendering*, never arbitrary HTML/JS execution in
  the operator's browser. **Agents emit them automatically**: on goal completion
  the orchestrator records a structured deliverable as an artifact (best-effort,
  byte-identical re-finalizes are deduped), so re-runs accrue version history.
  The goal page grows a **version/diff viewer** — a per-artifact history
  disclosure that fetches each version with a server-computed unified diff
  (`/artifacts/history`), rendered with add/del coloring (textContent only, no
  innerHTML).
- **Projects / matter workspaces (`/projects`)** — group related goals into a
  persistent workspace (a close cycle, an audit, a deal). v19 `projects` table
  (name/description encrypted; owner/domain plaintext) + a nullable
  `goals.project_id`; `create_project` / `list_projects` (with goal counts) /
  `set_goal_project` / `list_goals(project_id=...)` / `project_status_counts`.
  The page lists + creates projects; a detail page shows member goals and a
  status rollup; the goal page gains a Project selector to file a run (or clear
  it). Owner-scoped like goals (a project you don't own 404s). The maverick take
  on Claude Projects: a governed, attributable workspace, not just a chat folder.
- **Output styles (`/styles`)** — a user-selectable response style (concise /
  explanatory / formal / executive / technical / bullet) appended to every
  agent's system prompt — tone and format only, never capabilities or the safety
  surface (the Claude "styles" analog; sibling to the operator `[persona]`
  block). `styles.py` is the registry + renderer; the active selection is a
  dashboard runtime overlay (`styles.active`, like plugin toggles — not
  config.toml), set on the page (operator role, validated against the registry).
  Injected in `agent.py` beside the persona block, additive and fail-open.
  There is no per-conversation selection or custom style.
- **Share links (`/share/<token>`)** — a revocable, expiring, read-only link to a
  goal's deliverable for someone without a dashboard login. v20 `share_links`
  stores only the token's SHA-256 (like a password-reset token), so the DB never
  holds anything that grants access and the clear token is shown exactly once;
  `create_share_link` / `resolve_share_link` (rejects unknown / revoked /
  expired) / `revoke_share_link` (goal-scoped) / `share_links_for_goal`. The
  public view is auth-exempt (the token IS the credential — bearer + OIDC
  middleware both skip `/share/`), renders only title + deliverable + artifacts
  (never the worklog, spend, controls, or nav; `noindex`), and 404s a bad token
  with no detail. Create/revoke are operator-role + goal-access-gated; the goal
  page grows a Sharing panel (create → copy-once link, list, revoke). 7-day default.
- **Chat answer actions** — the conversation shows role-filtered product
  navigation and puts Copy answer, Print conversation, Download answer,
  Read aloud, Edit and Share beside a saved result under current permissions.
  Actions appear when live work finishes without discarding the next message;
  a failed refresh has an explicit retry. Copy uses the saved answer rather
  than unsaved edits. Earlier answers have snapshot copy/download and an Open
  answer link. Downloads recheck access and review requirements; structured
  exports contain the reviewed table. Print includes stored clarifications and
  wraps wide content. Sharing retains approval, expiry and revocation across
  selected workspaces. Native desktop and real-customer acceptance remain open.
- **Deliverables inbox (`/deliverables`)** — presents each team's results as
  the deliverable their pack declares and scopes them to the consumer role, so an
  FP&A analyst sees "my forecasts" and a risk officer sees "assessments awaiting
  my sign-off" instead of the flat `/goals` stream. Filter chips per consumer
  role; a gated deliverable whose run has finished surfaces in an "Awaiting
  sign-off" queue whose Review action opens the rendered deliverable. Keyed off
  the existing `goals.domain` attribution (`list_goals(domain=...)`) and the
  pack output contract; the model is shaped by a pure `deliverables.build_inbox`.
  **Persona identity:** with a `[personas]` binding (principal → consumer roles,
  with a single-user `default`; a wizard step), the inbox defaults to the
  signed-in user's own deliverables — a risk officer lands on their assessments,
  an analyst on their forecasts — with a "Mine / All" toggle. Distinct from the
  RBAC role (admin/operator/viewer, which gates *actions*); this says which
  deliverables are *yours*. No binding = the full list, as before.
  The finance suite declares output contracts across its towers (FP&A forecasts,
  controllership reconciliations, treasury schedules, tax provisions, assurance
  memos, reporting drafts, risk/credit), so the inbox is populated with ~29
  deliverables across 11 consumer roles, not just the one proof pack. The
  insurance suite extends this with ~38 more (claims files, underwriting files,
  reserve indications, reinsurance reconciliations, statutory filings) across
  its own 11-role vocabulary (underwriter, actuary, claims_adjuster/manager,
  reinsurance_analyst, compliance_officer, ...). The banking suite adds ~37
  (CECL allowance, SAR/CTR filings, AML queues, loan files, call/liquidity
  reports, ALM sensitivity) across bsa_officer, credit_officer, loan_officer,
  treasurer, operations_manager, ...; and the IT-GRC / risk suite adds ~55
  (enterprise risk register, DPIA/RoPA, control-test results, incident/breach
  reports, vendor TPRM, audit evidence) across risk_officer, ciso,
  privacy_officer, internal_auditor, security_analyst, ... -- so the inbox spans
  ~159 deliverables across ~30 consumer roles.
- **Governed hand-off (deliverable sign-off + export)** — closes the loop the
  output gate opens: a human certifies a finished, gated deliverable
  (`POST /api/v1/goals/<id>/signoff`, recorded in the v16 `signoffs` table with
  who/when and an encrypted review note), and an approved deliverable can be
  pulled downstream as CSV (`GET /api/v1/goals/<id>/deliverable.csv`) instead of
  re-keyed by hand. The goal page grows a sign-off panel (Approve / Reject + note,
  then the decision + hand-off download); a signed-off deliverable drops out of
  the persona inbox's "awaiting sign-off" queue. Agents draft; humans certify.
- **System-of-record routing** — when a deliverable is approved, Lightwork POSTs
  it to a configured downstream endpoint (treasury / GL / Jira), so "approved in
  Lightwork" lands in the system of record automatically instead of being
  re-keyed. Opt-in via `[deliverables] handoff_webhook` (a wizard step;
  env-referenceable URL), signed with the existing `[webhooks]` HMAC secret and
  delivered over the SSRF-safe webhook path. Best-effort and never blocks the
  sign-off; the payload carries the parsed deliverable (table rows) and
  attribution. Fires only on `approved` (`webhooks.fire_deliverable_handoff`).
- **Deadline alerts** — warn before a data-subject request, an incident's
  72-hour notification clock, an assessment renewal or review, a vendor contract
  renewal or an approval card runs out. `maverick.deadline_alerts` evaluates every such record per workspace and
  sends plain-language alerts (`due_soon_<lead>`, `due_today`, `overdue`;
  lead times per type under `[deadline_alerts.lead_days]` /
  `[deadline_alerts.lead_hours]`, quiet hours, immediate or one summary per
  person) through `notifications.notify`, so every configured backend — and
  any backend added later — carries them. Each (record, state, deadline)
  alerts once, recorded in the `deadline_alerts` ledger table (world-model
  migration v47) so restarts never re-send; the record pages show an "Alerts"
  section and `GET /api/v1/deadline-alerts` lists them. Routing prefers the
  record's assignee, else the workspace owner named in `[deadline_alerts]
  owner`. Run by `maverick_dashboard.deadline_alerts_scheduler` (a wizard step,
  rows on All settings). On by default while the privacy register is on.
- **Webhook subscriptions, delivery log and retries** — outbound webhooks are
  records (`maverick.webhook_subscriptions`: address, event filter, sealed
  secret, on/off, description) managed on Settings → Webhooks
  (`/settings/webhooks/manage`, `/api/v1/webhooks/subscriptions`,
  `/api/v1/webhooks/deliveries`) with "Send test event" and "Retry now"; the
  `[webhooks] outbound` list keeps working as a legacy default subscription.
  Every delivery is logged (attempts, status, latency, response snippet, next
  retry), with five attempts total (the initial attempt plus four retries) over
  about an hour with jitter before it is parked as dead. Record events (`dsar.*`, `incident.*`, `assessment.*`,
  `vendor.*`, `approval.*`, `policy.published`; `maverick.webhook_events`)
  share one envelope (event id, type, occurred_at, workspace, record summary,
  link) documented in `docs/webhooks.md`; the HMAC signature scheme is
  unchanged. Addresses go through the same SSRF guard as the dispatcher.
- **In-dashboard skill authoring** — the `/skills` page can *create* a skill,
  not just install one: a form (name, trigger phrases, tools, instructions)
  composes a `SKILL.md` and writes it via the same validate + secret/shield-scan
  path as install (`skills.create_skill` / `build_skill_md`). Kebab-cased id,
  injected into matching agents on the next run. Shares the
  `MAVERICK_ALLOW_SKILL_INSTALL` opt-in (skills land in agent prompts), so it's
  off by default in a locked deployment. Skills are instructions, not code —
  the safe, governed equivalent of an in-app extension.
- **Allowlisted plugin install** — the `/plugins` page can one-click `pip
  install` a *code* plugin package (tools / channels / skills / personas entry
  points), but only one the operator pre-approved in `[plugins] installable`.
  Fail-closed and quad-gated: same-origin, the `MAVERICK_ALLOW_PLUGIN_INSTALL`
  opt-in, the admin role, and the install allowlist — and pip runs as argv (no
  shell), so nothing is injectable and a compromised token can't pull arbitrary
  code, only pre-vetted packages (`plugins.install_plugin` / `installable_plugins`).
  pip runs `--isolated` (no `pip.conf`, no `PIP_EXTRA_INDEX_URL`, so no second
  index can win a name), `--no-deps` and `--only-binary :all:` (a wheel; no
  `setup.py` runs); an entry written as `name==version sha256:<hex>` installs
  under `--require-hashes`, so only the reviewed wheel bytes can land, and an
  unpinned entry is logged as such.
  Distinct from the *load* allowlist (`enabled`); installed slots appear in the
  toggle list to enable.
- **Finance suite (Office of the CFO)** — 31 domain packs across 7 towers
  (Controllership, FP&A, Treasury, Tax, Assurance, Procurement, Reporting) + a
  Finance Controller, each a sealed read-only/draft-by-default compartment with
  the "never move money without a human" guardrail. The governance wrapper:
  amount-aware authorization (`[governance] deny_above`/`require_human_above`
  dollar tiers), a segregation-of-duties linter (`maverick finance lint-sod`),
  OFAC/SDN sanctions screening (`screen_sanctions`), finance assessment templates
  (sox_control / fraud_risk / itgc / credit_risk / close_readiness),
  compliance-regime packs (SOX/COSO/GAAP/PCI DSS 4.0.1/GLBA/AML/SEC/IRS plus
  DORA, Basel III final reforms, and IFRS 17; strictest-wins), and the
  `maverick finance status` posture report (`maverick/finance/`). The opt-in
  `[finance_operations]` control plane adds: SSRF-guarded Federal Register,
  opt-in official Texas Register RSS, opt-in EU feeds (EUR-Lex
  Parliament/Council legislation and EDPB news, both verified live at
  source before encoding), and configured state-register polling;
  atomic deterministic content versioning,
  enabled-scope matching, field diffs, and a citation-bearing review queue;
  versioned 50-state money-transmitter and insurance-producer source-routing
  packs persisted into the same register; duplicate-payment, Benford-eligibility,
  approval-threshold/split-payment, and off-hours anomaly rules with exact,
  bounded evidence; governed AML/KYC/sanctions list versions, fail-closed
  completeness, transparent typo-tolerant matching, and four-eyes case
  disposition; and crash-resumable scheduled finance observations routed into the existing
  Security/GRC audit and evidence-request APIs as `needs_review` tests, with
  evidence-backed human dispositions reconciled to finance cycles. The
  finance-suite-gated `/finance` workspace and 24 permission-tiered
  `/api/v1/finance-operations/*` routes expose the queues. No LLM makes a
  regulatory, anomaly, sanctions, or
  audit decision. See [`FINANCE_OPERATIONS.md`](./FINANCE_OPERATIONS.md).
- **maverick-knowledge** — per-domain vector RAG package backing
  `knowledge_search`; config-selected embedders (`embed.py`): hosted **Voyage**
  (or any OpenAI-compatible endpoint), **Cohere** (`/v2/embed`, typed
  `embedding_types`), local, or deterministic — fails loud rather than silently
  degrading.
- **Role-based page visibility** (`maverick_dashboard/ui_visibility.py`) — one
  page registry drives the sidebar nav, a per-role visibility policy, and the
  Settings "Page visibility by role" matrix. Each RBAC role (admin/operator/
  auditor/viewer) sees only the pages its work needs by default (a viewer gets
  read-only pages, an auditor the audit surfaces, an operator no admin
  plumbing), and an admin can show/hide any page per role from Settings.
  Hidden pages leave the nav AND 403 on direct access (an app-level dependency
  after `require_principal`); overrides can never show a page past the role's
  enforced permission floor, admins can never lose Settings/Users (lockout
  guard), and /api routes are untouched. Auth off = full nav, nothing
  enforced (single-user mode unchanged). Store: diffs-only
  `~/.maverick/dashboard-ui-visibility.json` (0600), global control-plane.
  The registry also declutters the sidebar to one entry per job: secondary
  composers/detail surfaces (`in_nav: False` — Quick Goal, Goal Map, Workflow
  Builder, Flow Designer, Billing, Learned, Redaction) stay governed but are
  reached from their primary page's own links; Walkthroughs/Facts live under
  Observe and Response Styles under Extend, matching their real audience. The
  shell's design system + behaviors ship as static assets
  (`/static/lightwork.css`, `/static/lightwork-ui.js`) rather than inline in
  `base.html`, and the /settings + /users routes live on their own router
  (`maverick_dashboard/admin_pages.py`).
- **Reverse-proxy SSO** — trusted forwarded-identity header for enterprise auth.
- **OIDC resolver lifecycle** — [bounded signing-key reuse and off-loop identity
  verification](./oidc-resolver-lifecycle.md), with current request-task tenant
  binding, per-request revocation/membership checks and bounded refresh/admission.
- **Dashboard lifecycle** — [one shutdown deadline](./dashboard-lifecycle.md)
  covers owned schedulers, goal admission/drain and cleanup; timed-out workers
  retain ownership and prevent overlapping restart.
- **SAML 2.0 SSO** (`maverick_dashboard/saml.py`, the `[saml]` extra / pysaml2) —
  a SAML SP browser-login front-end (`/saml/metadata`/`login`/`acs`) for IdPs that
  mandate SAML over OIDC. The IdP's signed assertion is verified by pysaml2 (no
  hand-rolled XML-dsig) and mints the SAME `mvk_session` cookie as the OIDC login,
  so a SAML user flows through RBAC / `require_principal` identically
  (`user:<NameID>`); open-redirect-safe RelayState; off by default (404s until
  `[auth.saml]` is set). pysaml2 calls are isolated + unit-tested; certify a live
  IdP round-trip before production.
- **SCIM 2.0 provisioning** (`maverick_dashboard/scim.py`) — the RFC 7643/7644
  `/scim/v2` surface (Users CRUD + `ServiceProviderConfig`/`ResourceTypes`, the
  `userName eq` filter, Okta/Azure PATCH-deprovision forms) so an enterprise IdP
  drives user lifecycle automatically: a SCIM user provisions a backing tenant,
  `active=false`/DELETE suspends/removes it. Carries its own static IdP bearer
  (`MAVERICK_SCIM_TOKEN`, constant-time compare), exempt from the dashboard-token
  middleware and OIDC gate; 404s when unset, so it's inert off by default.
  Deprovision also **force-revokes live sessions**, not just future logins: a
  per-principal revocation epoch (`session_revocation.py`, fail-closed on a
  damaged store) rejects any credential issued before it, and a login-time
  **subject directory** (`subject_directory.py`, sha256-keyed for privacy)
  reaches a session even when the IdP issues a pairwise/per-app OIDC `sub`
  (Entra) that's in no SCIM attribute. "Log out everywhere" bumps the same epoch.
- **Tenant-aware persistence** — workspaces wall each tenant into
  `~/.maverick/tenants/<t>/` (`workspace.py`, `paths.py`), with a per-tenant
  world DB and `data_dir()`-routed audit / quotas / DSAR / fleets. The shared
  **Postgres** backend (`[world_model] backend = "postgres"`) carries a
  **versioned migration runner** (the world-model `MIGRATIONS` ledger), a
  `tenant_id` on every root table (write-stamped, read-scoped), **tenant-aware
  UNIQUE constraints**, a **strict-isolation mode** (`[world_model]
  strict_tenant_isolation`), **database-native Row-Level Security**
  (`[world_model] rls` / `MAVERICK_PG_RLS`, **auto-on under enterprise mode**
  with a boot preflight that refuses to start on legacy NULL-tenant rows: a
  FORCE-RLS policy on every
  tenant-scoped table keyed on a transaction-local `maverick.tenant` GUC, so
  the database — not just the app-layer predicate — enforces the boundary; the
  policy fails closed when the tenant GUC is unset/empty and startup fails if
  the requested policy cannot be installed or verified; applied by the table
  owner, enforced for non-superuser connections, validated
  against a live Postgres under a non-superuser role), and an opt-in
  **`psycopg_pool` connection pool** (`[world_model] pool_size` /
  `MAVERICK_PG_POOL_SIZE`) that hands each transaction its own pooled
  connection for horizontal scale (default 0 = the original single-connection
  model, unchanged).
- **Bounded governed-record Postgres connections** — the governed backend shares
  the world-model libpq timeout policy and offers separate opt-in
  `[governed_records] pool_size` / `pool_timeout_seconds` / `pool_min_size`
  (connections kept open while idle, default 1) settings. Transactions
  retain current RLS, schema, role and encryption-key checks; pooled tenant state
  is cleared before reuse and unknown writes are never replayed automatically.
  The installer offers a one-connection starting point. See
  [connection limits and validation](operations/governed-postgres-connections.md).
- **Per-tenant KMS at fleet scale** — envelope encryption with a per-tenant DEK
  wrapped by a KEK in a pluggable `KMS` (`tenant/kms.py`; LocalKMS or AWS/GCP/
  Vault/Azure Key Vault BYOK via `kms_backends.py`). **Deterministic per-tenant BYOK**:
  `get_kms(tenant_id)` reads each tenant's own `[kms]` overlay independent of the
  active context. A **DEK-cache TTL** (`MAVERICK_KMS_DEK_CACHE_TTL`) bounds how
  long a revoked cloud key keeps opening data. **Fleet KEK rotation** is operable
  and resumable: `maverick tenant kms-rotate --old-kek --new-kek [--dry-run]`
  skips tenants already on the new KEK (re-run finishes an interrupted rotation)
  and refuses success while any tenant is still on the old KEK (re-wrap only — no
  data re-encrypted).
- **Online-migration preflight + governance** — `schema_migrations.py` + `maverick
  schema-plan`: the *operations* view over that ledger. It classifies each
  pending statement `online` (cheap/non-blocking: `ADD COLUMN`, `CREATE INDEX IF
  NOT EXISTS`, FTS rebuild) or `offline` (table rewrite / long write lock),
  `plan(current, target)` lists the pending steps, and `online_only()` gates a
  hot deploy — failing **closed** on any unclassifiable statement so an unknown
  migration is reviewed before it runs against a live, high-traffic world. On top
  of it, **`migration_governance.py`** is the integrity ratchet (CI-gated):
  per-version sha256 checksums pinned in `migrations.lock.json` make released
  migrations immutable, new ones must be additive (no `DROP`/`RENAME`), and both
  backend ladders (SQLite + Postgres) must stay at the same declared head.
- **Proven control/data-plane split** — the dispatcher seam hands goal execution
  to a separate worker (`queue_dispatcher.py` arq/Redis, `grpc_dispatcher.py`
  gRPC, both installed at startup). Two CI-gated proofs back the claim:
  `control_data_plane_e2e.py` (one goal provably runs out-of-process, with a JSON
  evidence artifact) and `control_data_plane_soak.py` (many goals under
  concurrent workers reach `done` zero-loss with **exactly-once claims** — the contention
  test of `JobQueue.claim`'s `WHERE status='pending'` guard; a job reclaimed after a
  worker dies can run again, so handlers must be idempotent). The HTTP
  plane has its own proof: `maverick_dashboard.load_harness` drives the
  real app with concurrent clients and asserts no 5xx, that admission
  holds under contention (N clients racing one vendor name end with
  exactly one record, losers seeing the governed-record 409), a clean
  `PRAGMA integrity_check`, and that every issued request was metered.
  Latency percentiles are recorded and never asserted — a wall-clock
  gate in CI is a flake generator.
- **The production security posture is CI-enforced** (`posture_gate.py`,
  `posture.baseline.json`) — the suite runs with secure defaults off so
  each control's on/off mechanics stay under test, and the same tree is
  measured every build under the real posture (audit signing on, at-rest
  encryption on, consent fail-closed for high-risk actions, tool-risk
  ceiling applied); the job BLOCKS on any posture failure.
- **Process table** — `maverick ps` (unified view of runs/workers).
- **Scheduling** — recurring autonomous goals from a prompt; `worker --once`
  cron-friendly drain (`scheduler.py`, `job_queue.py`, `worker.py`).

## Hosted control plane and multi-tenancy

The backend for running Lightwork as a governed, multi-tenant platform (each piece
opt-in; single-tenant/self-hosted deployments are unaffected):

- **Tenant lifecycle / provisioning** — `tenant/registry.py` + `maverick tenant
  create/list/suspend/resume/quota/delete`: a roster of tenants with status,
  plan, and per-tenant daily spend quota; `assert_tenant_active` refuses a
  suspended tenant. **One-step onboarding** — `maverick tenant onboard <id>
  --admin-email <email>` provisions the tenant and mints its first-admin
  dashboard invite (via `maverick_dashboard.invites`), printing the single-use
  link once.
- **Managed customer sandbox workspaces** —
  `customer_sandbox_lifecycle.py`, `customer_sandbox_api.py` and
  `customer_sandbox_composition.py` add a deployment-global, default-off
  (`[customer_sandbox_lifecycle] enable = true`) lifecycle that reads one exact
  production source revision and creates an isolated local workspace containing
  only closed safe projections of AI Governance, Consent & Preferences, Data
  Use Governance, Privacy Automation, Tech Risk & Compliance and Third-Party
  Management configuration. Immutable source/snapshot digests, module and
  quota plans, independent create/destroy or failure-abandon approval,
  suspend/resume/resync/expiry, target-collision authority, tombstone retention
  and bounded crash/retry recovery are explicit. Admission fails closed when
  disabled while existing exact-authority remediation remains available to a
  global administrator. This is not a registered Lightwork tenant, runtime or
  network sandbox; it copies no arbitrary configuration, secrets or tenant
  data. Integrity verification covers the SQLite lifecycle authority, not the
  whole workspace, and the audit chain is unkeyed. Hosted operation, live
  customer acceptance and production recovery/concurrency/scale remain
  unverified.
- **Metering → billing & entitlements** — `billing.py` + `maverick billing
  invoice/entitlements`: rate the usage ledger (pass-through+markup or
  token-priced) into per-period invoices; plan → feature/limit entitlements
  (`tenant_entitled`).
- **Stripe billing collection (turn invoices into charges)** —
  `billing_stripe.py` + `maverick billing stripe-status/stripe-preview/stripe-sync`:
  a config-gated (`[billing.stripe] enable` / `MAVERICK_STRIPE_ENABLE`), default-off
  integration over the platform's own Stripe account. One customer + platform-fee
  subscription per tenant (create-or-lookup, idempotent; the `cus_...` id is stored
  on the tenant record), the metered invoice pushed as Stripe invoice items behind
  the `bill_metered_usage` flag (off = platform fee only; no
  markup hardcoded), and a signature-verified webhook (`MAVERICK_STRIPE_WEBHOOK_SECRET`,
  stdlib HMAC) that downgrades a past-due tenant to the base entitlement tier and
  restores it on payment. The `stripe` SDK is an optional extra
  (`maverick-core[stripe]`), lazily imported; the module and its gate report
  "disabled" cleanly without it. (Distinct from the agent-facing `stripe` tool.)
- **Go-live readiness gate** — `maverick launch-check` (`health.py:
  run_launch_check`): PASS/FAIL for each production switch — cost-cap
  enforcement, per-user tenancy, at-rest encryption, and a resolvable provider
  credential — each reading real config/env, exiting non-zero if any is off so
  a deploy pipeline can gate on it.
- **Signed offline update bundles** — `release_update.py` +
  `release_manifest_signing.py` (`python -m maverick.release_update
  verify-bundle|plan|apply|rollback`): an Ed25519-signed release manifest lists
  the version, each artifact's sha256 and size, the oldest version it upgrades
  from and its governed migrations. A bundle verifies offline against the
  trusted publisher keys (`MAVERICK_RELEASE_PUBKEYS` / `[release]
  publisher_pubkeys`, also under All settings > Server & deployment > Updates)
  and every artifact hash before a version-gap-checked plan runs. The
  per-deployment install hooks that swap the running binary are not built.
- **Per-tenant envelope encryption** — `tenant/kms.py` (fleet KEK rotation in
  `tenant/kms_fleet.py`): a DEK per tenant, wrapped by a KMS KEK (LocalKMS
  default; cloud KMS is a drop-in `wrap`/`unwrap`); one tenant's DEK can't open
  another's data; instant KEK rotation.
- **Per-tenant egress plane** — `tenant/egress.py`: a per-tenant allow/deny
  egress policy composed (AND) with the per-tool policy at the egress chokepoint.
- **Multi-tenant `maverick serve`** — the channel server enforces the tenant
  roster at the door: with per-user tenancy on and tenants provisioned, a
  suspended/unknown tenant's message is refused before any goal exists, and a
  tenant over its provisioned `max_daily_dollars` (`maverick tenant quota`) is
  refused. Admission includes today's tenant-scoped usage across principals
  and outstanding provider holds. Unknown charges survive UTC-day rollover;
  a configured tenant's unreadable policy refuses execution. Calls without an
  active tenant do not acquire an organization allowance.
- **Out-of-process execution** — a swappable goal **Dispatcher** (`runner.py`)
  with a **QueueDispatcher** (`queue_dispatcher.py`) that enqueues goals for a
  worker pool (arq adapter behind `[queue]`; `install_from_config` wires it).
- **Isolation test suite** — `tests/test_multitenant_isolation.py` proves the
  tenant walls across the primitives that actually carry tenant data: `data_dir`
  path routing (distinct ids never collide onto one segment), `world_for_tenant`
  DB separation (A's goal invisible to B), per-tenant KMS (a DEK wrapped for A
  does not unwrap under B's AEAD context), and clean `set_tenant`/`reset_tenant`
  scope discipline.

## Evaluation and benchmarks

**Long-running plugin reliability drill** (`plugin_reliability.py`, `python -m
maverick.plugin_reliability`): the plugin counterpart to the chaos game-day —
a host-agnostic sustained-load drill (give it any `call(payload) -> str`)
that injects crashes/timeouts/errors at seeded rates over thousands of calls
and asserts the reliability properties a host must hold: **recovery** (a crash
is followed by a later success — no permanent wedge), **isolation** (a faulted
call never poisons the next), bounded **error rate**, and **no monotonic
memory growth** (a leaking plugin, via an injected sampler). Deterministic;
exits non-zero in `--ci` on any property failure. **Chaos game-day drill** (`chaos_gameday.py`,
`python -m maverick.chaos_gameday`): scripted fault scenarios against the
real retry layer — 20% tool flakes must be absorbed (≤5% surfaced), a total
outage must exhaust retries in bounded attempts (backoff virtualized so the
drill runs in milliseconds), plus a no-chaos control; exits 1 when a
resilience property fails. Standalone drill, not for serving processes.

**Cost/perf release canary** (`release_canary.py`, `maverick canary
record/compare`): snapshot a release's cost/latency/success-rate metrics and,
before shipping the next, compare against the recorded baseline — a
**direction-aware** relative check (lower-is-better for cost/latency,
higher-is-better for success-rate/throughput) that exits non-zero on a
regression beyond tolerance, gating a release the way tests do. Deterministic;
the snapshot store is an atomic JSON keyed by release tag.

**Marketplace moderation**
(`marketplace/moderation.py`, `python -m maverick.marketplace.moderation
<path>`): static pre-publication checks over a submitted skill/plugin —
manifest completeness, permission-escalation (declared vs used), secret scan
(reuses the secret detector), prohibited patterns, license — with a
strictest-wins approve/flag/reject verdict. **Skill search engine**
(`skill/search.py`, `python -m maverick.skill.search`): zero-dep BM25-lite
ranked search over the local skill library with HF-dataset export/import
(`skills.jsonl`, network via an injected fetcher; pulled skills re-validated
through the skill validator). **Self-hosted relay reference**
(`relay_reference.py`, [`docs/self-hosted-relay.md`](./self-hosted-relay.md)):
the self-hostable inbound-webhook relay (quick-vs-ack-then-run classification,
deadline enforcement, secondary-channel delivery) as a framework-agnostic,
fully-injected core that runs as a Worker or a local service.

`benchmarks/`: GAIA, τ²-bench-style stateful harness, terminal-bench-style
harness, recall-precision memory suite, and an **adversarial-cost suite**
(`eval_adversarial_cost.py`): scripted money-wasting scenarios — tool loops,
token bombs, runaway iterations — each asserted CLAMPED by the cache /
output-cap / Budget ceilings; `main()` exits 1 on any unclamped scenario. All
CI-runnable on shipped fixtures.

## Observability and reliability

OpenTelemetry traces (spans carry the **full OTel GenAI semantic-convention
attribute set** — `gen_ai.operation.name` / `system` / `request.model` /
`request.{max_tokens,temperature,top_p,frequency_penalty,presence_penalty}` /
`response.{model,id,finish_reasons}` / `usage.{input,output}_tokens`, plus the
`execute_tool` tool-span attributes AND the `invoke_agent` agent-span leg
(`gen_ai.agent.name/id` around every `Agent.run`) with semconv `error.type`
stamped on failed spans — so any OTel-native backend reads them
with no custom mapping), Prometheus `/metrics` (and, with `MAVERICK_OTEL_METRICS=1`, the same series over OTLP, plus one server span per dashboard request named by route template, `request_spans.py`) — which serves the
platform series **and** Lightwork's own always-on counters from a
dependency-free registry (`runtime_metrics.py`: dashboard requests by
route TEMPLATE never raw path, request wall time, gateway calls,
governed-record ops, with a per-metric series cap and a dropped-series
counter so cardinality cannot run away silently) in one scrape — and a **Sentry performance
tab** (all opt-in) (`observability.py`): `MAVERICK_SENTRY_DSN` (or
`[observability] sentry_dsn`) initializes Sentry tracing and every existing
`trace_span` call feeds it — a transaction at the root (episodes), child spans
inside (tools) — sample rate via `MAVERICK_SENTRY_TRACES_SAMPLE_RATE`, PII off,
`[sentry]` extra; per-tool latency profiles + extended stats
(`tool_latency.py`); **tail-latency hunting** (`tail_latency.py`, `GET
/api/v1/diag/tail-latency`): flags tools with a fat tail (p99/p50 ≥ ratio) —
usually fast, occasionally terrible — which is where the bug hides, not just
the slowest by p95; opt-in per-tool **latency budget** (`latency_budget.py`) and
cross-span **budget propagation** (`latency_span_budget.py`); **speculative tool execution**
(`speculative_tools.py`, opt-in `[tools] speculative`): pre-execute predicted
read-only (`parallel_safe`) tool calls concurrently into the tool-output cache
— `predict_from_history` warms only calls repeated across turns; the agent
loop warms them after each tool turn under the caller's cache scope and
principal (`ToolRegistry.speculate_reads`), budget-checked; **async
compaction** (`async_compaction.py`, opt-in `[context] async_compaction` together
with `[context] compact`): a bounded, tenant-scoped cache reuses immutable token
counts and lexical features of exact source text. Every call reranks the complete
current history for its current query and budget. The obsolete background worker
and lossy prefix-result cache have been removed. Optional model-assisted agent
strategies use native async completion under the agent's wall/halt guard; the
default heuristic makes no model call. See [compaction execution and feature
reuse](operations/compaction-execution.md); **cost projection at plan time** (`cost/projection.py`): token/dollar
estimates per plan step from the role's model + MODEL_PRICES, iterations
multiplier, OK/TIGHT/OVER budget verdicts; **cross-run learning cache**
(`cache/learning.py`, opt-in `[memory] learning_cache`): memoize *verified*
sub-results across runs (required `verified_by` provenance, TTL + LRU cap,
refuses to store anything the secret detector flags; the orchestrator keys
each goal by owner + title + details, briefs a repeat run with the checked
answer as untrusted history, and stores an answer only when the answer checker
actually ran and accepted it); **energy/CO2
accounting** (`energy_accounting.py`; the `energy_accounting` tool's token and
grid defaults come from its `[energy]` coefficients): clearly-labeled estimates from configurable
Wh/1k-token + grid-CO2 coefficients (output tokens weighted 3x), disclaimer
always rendered; **Redis tool cache** (`cache/redis_tool.py`,
`[tools] output_cache_backend = "redis"`): cross-process/cross-host tier
reusing the same key canonicalization, namespace-scoped purge, fail-open on
any Redis error; **WAL contention audit** (`test_wal_contention.py`): pins the
16-concurrent-writers / zero-lock-errors promise + the WAL/busy_timeout pragmas
in CI; **cold-start guard** (`test_cli_cold_start.py`): `maverick --help` stays
fast (~0.1s, well under the 300ms target) because importing the CLI defers
every heavy/optional dep — a fresh-interpreter test fails CI if a module-level
`import httpx`/provider-SDK/vector-store/numpy sneaks into the import path; **query-plan regression CI** (`test_query_plans.py`): hot world-model
queries must SEARCH via an index, never full-scan; **cost-attribution API**
(`GET /api/v1/cost/by-tag` on the dashboard): spend bucketed by episode/goal
tag — the JSON face of the tag split for chargeback/BI; **real-time SSE event
stream** (`GET /api/v1/goals/{id}/events/stream`): a `text/event-stream` live
tail of a goal's events that emits each as it lands and ends on terminal status
or disconnect — tails the durable `goal_events` log so it works across the
worker/dashboard process split (the polling `/events` endpoint stays for simple
clients); **streaming tool_result**
(`ToolRegistry.set_chunk_listener`): a tool fn may be an async generator or
return a sync generator of chunks — chunks stream to the registered listener
(dashboard/TUI live view) as they're produced while the model still receives
the joined text, so the model protocol is unchanged; **tool-output cache**
for read-only tools (`cache/tool.py`) with opt-in **warm-on-start** (`[tools]
output_cache_snapshot`: persist entries to a JSONL snapshot, reload the
still-fresh ones on the next run's first lookup); **network egress accounting**
(`egress_accounting.py`); **run health score** (`health_score.py`); **replayable
trace** format (`replay/trace.py`) with **trace pinning to commit**
(`trace_pin.py`: every run stamps a `trace_meta` event carrying the
workspace's commit/branch/dirty state at start — best-effort, never blocks —
and `trace_commit()` reads it back so replays tie to exact code); **cost split by tag** (`cost/by_tag.py`) and
**provider cost-curve fitter** (`cost/curve_fitter.py`); provider health board
(`provider_health.py`); proactive **provider rate-limit predictor**
(`rate_limit_predictor.py`); shared tool-reliability layer (`tool_reliability.py`,
`retry/`); circuit breaker (`circuit_breaker.py`); adaptive thinking budget
(`thinking_budget.py`). **Self-tuning budgets** (`budget_tuner.py`, `maverick
budget-tune`): learn a `max_dollars` recommendation from the historical
per-goal spend distribution (a high percentile + margin, so the common case
fits while a runaway still trips it), bucketable by an injected task-class
classifier; read-only — the operator sets the value. **Failure-mode telemetry** (`failure_telemetry.py`, `maverick failures`,
default-on `[telemetry] failure_modes`): a failed run records a canonical mode
(budget / auth / timeout / shield / sandbox / network / error) to a local JSONL
sink — the orchestrator tees from its budget and generic failure seams,
best-effort and a no-op when the telemetry is off — so an operator sees the
*distribution* of failures and fixes the dominant cause. Local-first, no
mandatory egress. **Continuous profiling daemon** (`profiling_daemon.py`,
`python -m maverick.profiling_daemon`, opt-in `[perf] profiling`): a sampling
profiler that periodically runs `py-spy record` against the live process and
drops speedscope/flame-graph profiles under `data_dir("profiles/")` — py-spy
samples from outside the interpreter (no GIL cost) so it's safe to leave on in
production; default-OFF, with an injectable runner/clock so the schedule is
tested without spawning py-spy.

## UX surfaces

- **Computer-use calibration + vision clicking**
  (`computer_calibration.py`, `vision_click.py`):
  per-axis affine calibration fitted by least squares over clicked targets
  (deterministic target grid, residual/drift report, atomic 0600
  persistence) corrects model-space clicks to screen space;
  `resolve_click("the blue button")` consults the
  GUI element memory first, falls back to an injected vision seam with a
  confidence floor (`LowConfidenceError` below it, nothing memorized on
  refusal), upserts what it learns, and applies the saved calibration.
- **Hardware sensors tool** (`tools/hardware_sensors.py`, `[sensors]` extra,
  opt-in `[tools] hardware_sensors = true` or
  `MAVERICK_ENABLE_HARDWARE_SENSORS=1`, wizard step included): read host
  temperatures/fans/battery via psutil with a `/sys/class/thermal` fallback
  and an injected reader for tests; unavailable categories say "unavailable on
  this host" — readings are never fabricated. The psutil import ignores the
  process current directory so workspace files cannot hijack the optional
  dependency.
- **Voice biometric unlock — companion factor only** (`voice_unlock.py`,
  opt-in `[voice] biometric_unlock`): speaker verification over an injected
  embedder with three hard stances — a voice match **never authenticates on
  its own** (`decide()` returns `companion_ok`; callers combine it with an
  existing factor — replay/synthesis is practical), profiles are local
  embedding centroids (never raw audio, 0600) with first-class
  `delete_profile`, and the whole feature is off by default.
- **Power-user keymap** (`keymap.py`, `[tui.keys]` /
  `MAVERICK_TUI_KEYS`, `python -m maverick.keymap [--validate]`): validated
  TUI keybindings — conflicts, unknown actions, and invalid keys are
  rejected, Ctrl-C is reserved as the unrebindable emergency exit, and a bad
  override set degrades to the stock keymap rather than an unusable one;
  `handle_key` is the pure key→action adapter the monitor/focus model
  consume; `maverick monitor` loads the keymap at start (quit, refresh,
  move/open/close plan steps, pause/follow).
- **Director mode** (`director_mode.py`): state an *outcome* and pick the
  autonomy level — `supervised` / `semi` / `autonomous` profiles map to the
  existing controls (consent mode, review-checkpoint intervals, a budget
  multiplier over the configured cap, plan-execute-reflect topology) so one
  choice sets the whole envelope. `direct()` is pure assembly (starts
  nothing; the hard Budget ceiling still applies at run time); `maverick start
  --director <profile>` applies it to its own one-goal process, with the
  budget clamped to the configured cap; profiles are
  config-overridable (`[director.profiles]`, All settings) and unknown profiles are refused — an autonomy level is
  never guessed.
- **Predictive approvals** (`predictive_approvals.py`): learns the operator's
  historical approve/deny rate per (action, risk tier) from approval history and
  *suggests* a default — auto-approve-candidate / auto-deny-candidate /
  always-ask — with a confidence from sample size. A suggestion surfaced to the
  human, never an auto-decision; high/critical actions are never auto-approve
  candidates.
- **Channel auto-routing** (`channel_autorouting.py`, `[channels.routing]`): a
  pure decision function picking the best-fit reply channel/handler from an
  inbound message's signals (length, detected language, urgency, attachment
  types, an injected classifier) against a configurable rule table, with
  `explain()`; passthrough when unconfigured.
- **Consent ergonomics** (`tools/consent_ergonomics.py`, the
  `consent_ergonomics` tool): turns a raw permission request (action, scopes,
  data, duration) into a minimal plain-language consent prompt with a
  low/med/high risk badge and flags over-broad requests (wildcard scopes, more
  scopes than the action needs). Deterministic and offline; it renders the
  prompt and never decides consent.
- **Static accessibility audit** (`a11y_audit.py`, `python -m
  maverick.a11y_audit --ci`, wired as a CI step): an offline structural WCAG
  pass over the shipped dashboard templates — img alt, form-control labels
  (`for`/`id`, wrapping `<label>`, `aria-label`), `<html lang>`, positive
  `tabindex`, empty interactive controls, heading-level skips — with Jinja
  placeholders treated as opaque text. Complements the live `a11y` tool
  (pa11y/axe).
- **TUI mouse mode** (`tui_mouse.py`, opt-in `[tui] mouse`): `maverick
  monitor`'s plan tree becomes clickable — SGR (xterm 1006) mouse tracking
  enabled/restored around the Live view, a click hit-tests its row to the
  plan-tree node and focuses/expands it (`NodeHitMap` + `FocusModel`, pure and
  terminal-free so it's unit-tested without a tty). Off by default; degrades
  to keyboard/auto-refresh on terminals that don't report mouse events.
- **CLI** — `maverick init` (wizard — with **branching paths**: a mode picker
  routes consumer users to a tailored short flow (`run_consumer`) while
  advanced users get the full step sequence, and the deployment answer
  (desktop/docker/vps/phone) filters the channel/sandbox questions that
  follow; `--fast` and `--resume` skip/restore branches), `start`, `resume`, `monitor` (Rich plan-tree
  TUI), `status --cost`, `export`, `replay`, `logs`, `ps`, `whoami`,
  `maverick diag` (circuit-breaker states, provider rate-limit counts, per-goal
  health score, cost-by-tag, and replay of a `MAVERICK_TRACE_DIR` run trace),
  `maverick config-lint` (validate `~/.maverick/config.toml` for unknown
  sections/keys + obvious type mistakes with closest-match suggestions;
  `config_lint.py`), and `maverick costs` (cross-run per-day spend from the
  recorded episode ledger; `cost/report.py`).
- **GitHub App** — `/webhook/github` verifies event signatures, but automated
  issue-to-PR execution is unavailable until agent checkout and publication
  are isolated. **GitLab Issues** — `/webhook/gitlab`:
  assign an issue to the bot, get a goal (`X-Gitlab-Token` constant-time
  verify, `X-Gitlab-Event-UUID` replay dedup), completing the
  Linear/Jira/GitHub/GitLab issue-trigger family (`issue_webhooks.py`).
- **N-of-M dual control** (`safety/dual_control.py`, `WorldModel.decide_approval`
  / `approval_signoffs`) — the **two-person rule** / segregation of duties: a
  high/critical-risk action needs N **distinct** approvers before it's granted
  (`[security] approvals_required`, flat or per-risk), and the requester can't
  approve their own request (`allow_self_approval = false`). Each dashboard
  approve is a vote by a verified principal; a single deny rejects; a repeat vote
  counts once (enforced by the `(approval_id, approver)` PK); `GET
  /approvals/{id}/state` shows quorum progress; a barred self-approval is 403.
  Off by default (`required = 1` = legacy single approver); SQLite migration v21.
  With one approver, `[approval] separate_approver` (default `when_available`)
  has someone other than the requester approve a high/critical action whenever
  another eligible approver exists (`channel_approvals.separate_approver_refusal`,
  enforced in `record_vote` for the dashboard, Slack and Teams).
- **Web dashboard** — run list, plan-tree, chat at `/chat`,
  [root conversation summaries and shared durable SSE replay](./dashboard-read-models.md)
  (schema 37 root indexes; monotonic heartbeat deadlines), and an approval queue with
  **collaborative supervision** (claim/release endpoints so two supervisors
  never double-handle a review — atomic claims, 409 on conflicts, claims
  surfaced in the pending list — plus `decided_by` attribution on every
  decision; SQLite migration v13 + Postgres parity, tenant-scoped), and
  an **oversight console** (`/oversight`): live fleet state, the approval queue,
  a per-guardrail intervention roll-up, and an inline **"why this action"
  drill-down** (the reasoning/tool chain + cost for a running agent, owner-scoped)
  (`maverick dashboard`). **Search across runs** — a live search box on the
  goals page over `GET /api/v1/goals/search` (text match on title/description/
  result, owner-scoped, decrypt-then-filter since those fields are encrypted at
  rest). **Pinned watch list** (`/api/v1/pins`, per-principal,
  most-recent-first), **saved dashboard views** (`/api/v1/views`: named
  filter/query-param sets), **annotated traces**
  (`/api/v1/goals/{id}/annotations`: human notes pinned to replay-trace steps),
  **multi-run dashboard** (`/api/v1/runs/compare?ids=…`: side-by-side
  status/events/errors for up to 8 runs), and **plain-language explanations**
  (`/api/v1/goals/{id}/explain`: a deterministic, template-rendered narrative
  of the run — `plain_language.py`, no LLM call, never hallucinates beyond the
  log). Pins/views/annotations persist tenant-aware in `ux_store.py`.
  **Run-events firehose** — `WS /ws/v1/runs/{id}/events`: a goal's events
  stream over WebSocket as they land (resume via `since_id`, terminal status
  closes the stream; auth mirrors the HTTP policy and OIDC applies to WS).
  **Inline cost preview** — `GET /api/v1/goals/{id}/cost-preview`: plan-time
  token/dollar projection + OK/TIGHT/OVER verdict before a goal runs.
  **"Why this cost" drill-down** — `GET /api/v1/goals/{id}/cost-breakdown`:
  spend decomposed by episode outcome (dollars/tokens/counts).
  **Replay export to MP4** — `replay/video.py` +
  `GET /api/v1/goals/{id}/replay-storyboard`: a run rendered to a watchable
  video — the deterministic core builds a captioned frame storyboard with
  per-step durations from the event gaps (secret/PII-scrubbed), then encodes
  via Pillow + the sandbox-mediated ffmpeg tool when present; when the video
  stack is absent it still emits the frame manifest + the exact ffmpeg command
  for out-of-band encoding (no new hard dependency).
  **Run gallery** — `GET/POST/DELETE /api/v1/gallery[/{id}]`:
  deployment-wide curation of exemplary runs (blurb + curator attribution,
  upsert, capped), each entry enriched with live status and links to the
  tutorial/explain exports; access-checked per viewer.
  **Run-as-tutorial export** — `GET /api/v1/goals/{id}/tutorial.md`
  (`tutorial_export.py`): the run rendered as step-by-step markdown (goal →
  approach → steps with preserved code fences → dead ends → outcome),
  deterministic templates over the event log, secret-scrubbed, no LLM call.
  **Cross-run anomaly detection** — `GET /api/v1/goals/{id}/anomalies`
  (`cross_run_anomaly.py`): a run scored against the deployment's behavioral
  baseline — novel event kinds (high), event-volume spikes (runaway-loop
  signal), error-rate spikes — conservative 3σ thresholds, silent on cold
  deployments (<5 baseline runs); signals for a human, not verdicts.
  **Cost anomaly alerts** — `GET /api/v1/cost/anomalies`: per-goal spend
  outliers above mean + Nσ over the recent window (needs ≥3 priced goals).
  **Accessibility + i18n** — a font axis independent of the theme
  (`?font=dyslexic` / cookie: OpenDyslexic-preferring stack with wider
  letter/word spacing, composes with the high-contrast theme) and **chrome
  i18n in en/fr/de/ja/zh** (`maverick_dashboard/i18n.py`: dict catalog +
  `t()` template helper; `?lang=` → cookie → `Accept-Language`; user data is
  never translated; catalog-completeness pinned by test).
- **Cost** — per-run reports, live cost meter, `maverick start --dry-cost`
  forecasting (`cost/forecast.py`).
- **Templates / marketplace v2** — starter-goals library + community template
  registry (`maverick template browse/add`), **hash-verified installs**
  (`catalog.py` sha256 pinning), **ratings**: indexes carry display-only
  `rating`/`ratings_count` aggregates (clamped, malformed-safe), `browse`
  renders ★-bars, and a local ledger (`marketplace/ratings.py`,
  `maverick template rate <name> <1-5>` / `ratings-export`) keeps your own
  ratings ready for an index-PR submission — no hosted ratings service.
- **Marketplace stats** — `GET /api/v1/marketplace/stats` (`marketplace/stats.py`):
  aggregates the local ratings ledger into total / average / 1–5★ distribution /
  per-kind breakdown / top-rated — the JSON face of the stats view. Self-host-first
  (the operator's own ratings; no hosted community service); pure aggregation.
- **Skill validator service** — `POST /api/v1/skills/validate` on the
  dashboard: lint a SKILL.md body (same linter as `maverick skill validate`)
  from CI or an editor against a self-hosted instance; size-capped, nothing
  persisted.
- **Localized money display** — `format_money` tool (`money_format.py`): format
  an amount per a (locale, currency) pair — symbol placement, grouping/decimal
  separators, the currency's decimal places — with an optional operator-supplied
  FX rate (`$1,234.56` → `1.234,56 €` → `¥1,235`). Offline display layer,
  distinct from the live-FX `currency` conversion tool; a curated locale subset.
- **DuckDB analytics** — `maverick analytics` (`duckdb_analytics.py`, `[duckdb]`
  extra): load the world model's goals/episodes into an in-memory DuckDB and run
  OLAP over the history — per-goal cost percentiles, time-bucketed spend, top
  goals, and **ad-hoc read-only SQL** (`--sql`, refuses anything but
  SELECT/WITH). This is the analytical use DuckDB is actually good at; the live
  transactional world model stays SQLite/Postgres (DuckDB is the wrong engine
  for the concurrent write path).
- **Cost retrospective** — `maverick cost-retro` (`cost/retrospective.py`): a
  spend review over the recorded per-goal/episode costs — the costliest goals,
  how much went to **failed** work (effort with no delivered result), how
  concentrated spend is (a Pareto signal), and rule-based observations to act
  on. Deterministic over the world model; read-only.
- **Dashboard views and personalization** — **plan-tree minimap** (`plan_minimap.py` +
  `GET /api/v1/goals/{id}/minimap`): a compact glyph-per-node subtree render
  with a depth budget; **multi-tenant overview** (`/tenants/overview`,
  admin-only like `/tenants`): per-tenant goal rollups + today's spend +
  suspended flags; **replay annotation export** (`annotation_export.py`):
  a run's annotations to markdown or SRT-timed cues; **personalized starter
  templates** (`starter_templates.py` + `GET /api/v1/templates/suggested`):
  the catalog ranked from the user's own goal history; **adaptive UI
  density** (comfortable/compact via `?density=`/cookie/config); **pluggable
  themes** (`themes.py`: `[dashboard] themes` rendered as CSS variables,
  strict `#hex` validation so config can't inject CSS); **templates
  marketplace** (`/templates`: catalog + ratings, "use" prefills the chat
  form — no auto-start); **live voice captions** (`live_captions.py` + SSE
  `GET /api/v1/voice/captions`): a rolling caption window over an injected
  transcript source (finalized vs in-flight, word-boundary trimming);
  **dashboard voice commands** (`POST /api/v1/voice/transcribe` + a mic
  button on the chat composer): record a spoken goal in the browser
  (MediaRecorder), re-encode it to 16 kHz WAV client-side (`_voice_mic.js` —
  no server ffmpeg needed), transcribe it server-side through the kernel STT
  backends (OpenAI/Groq Whisper, local faster-whisper, or the built-in local
  whisper.cpp engine, warmed at dashboard startup with a 503+Retry-After
  "warming" handshake while the first-run model download finishes — via
  `tools/voice.py`), and
  fill the goal field for review — speech never auto-submits; falls back to
  the browser's own speech recognition when no STT backend is configured;
  on by default, off via `[voice] dashboard_commands = false` /
  `MAVERICK_VOICE_COMMANDS=0`; the goal page's clarifying-question reply
  box has the same mic, and finished results get a **read-aloud** button
  (`POST /api/v1/voice/speak`: kernel TTS backends with the voice-safety
  redaction pass, browser speechSynthesis fallback).
- **Browser extension** (`extensions/browser/`, opt-in `[dashboard]
  allow_extension` plus `MAVERICK_DASHBOARD_TOKEN` — fail-closed CORS scoped
  to extension origins only): a
  Manifest-V3 WebExtension (no build step, loopback-only host permissions,
  `script-src 'self'`) with popup chat against the existing goals API and a
  "send this page" action shipping title/URL/selection as goal context;
  static tests pin the manifest security properties (no remote code).
- **ARIA-first navigation** (`tools/aria_navigate.py`, registered with the
  browser tool): drive the page via the accessibility tree — `snapshot`
  (stable node ids), `find` (role+name), `activate` (click/focus by node) —
  the live counterpart to the static `a11y_tree` extractor.
- **Audio understanding** (`tools/audio_understanding.py`, `[clap]` extra):
  zero-shot NON-SPEECH classification — a CLAP model embeds the clip and
  free-text labels ("glass breaking", "dog barking", "fire alarm") into one
  space and ranks them; `op=embed` returns the raw audio embedding. The
  embedders are injected seams (ranking math tested offline); the default
  adapters lazy-load transformers' ClapModel (`MAVERICK_CLAP_MODEL`,
  workspace-confined paths, stdlib-only WAV decode).
- **Conversational supervisor** (`conversational_supervisor.py`): natural-
  language supervision of running work — a deterministic intent grammar
  (reusing the voice-command compiler, with an optional llm seam that
  re-parses paraphrases through the *same* grammar, never a guess that
  mutates) answers reads ("what's running?", "how much today?", "what
  failed?") from cheap indexed passes over the world model + usage ledger,
  and routes mutating intents (pause/resume/reprioritize) through a strict
  `as_bool` confirm gate to world-model methods that actually exist
  (pause = status `blocked` + a supervision event; prioritize = a
  `goal:<id>:priority` fact — stated in the docstring).
- **Voice-only mode** (`voice_only.py`, `[voice] only_mode`, default OFF):
  an all-speech session loop — injected utterance source → handler →
  injected `speak` seam (default routes the TTS path, which redacts) — with
  a tested deterministic speech-shaping pass that turns markdown/code into a
  spoken summary ("I wrote 40 lines to app.py"). Mic capture + playback
  hardware are the operator's adapters behind the seams.
- **Augmented terminal charts** (`terminal_charts.py`, `maverick charts`):
  inline sparklines (▁▂▃▄▅▆▇█) and bars for spend/day (usage ledger), goal
  throughput (world), and tool-latency percentiles (`tool_latency`) — the
  ASCII renderer is the tested core, `rich` panels a thin lazy wrapper;
  honest empty-state lines when there's no data.
- **Image edit tool** (`tools/image_edit.py`): the edit verbs to pair with
  replicate's generation — hosted inpaint/variation/upscale over the same
  Replicate API surface. All settings > AI models > Images and the installer
  provide reviewed choices for repainting, variations and enlargement; the
  actual tool reads them on each operation. Existing
  `MAVERICK_{INPAINT,VARIATION,UPSCALE}_MODEL` overrides remain authoritative; local
  images inlined as data URIs) and local crop/resize/rotate via Pillow
  (`[computer-use]` extra, no key). Every model-supplied path is
  workspace-confined.
- **Embedded-device tool** (`tools/embedded_device.py`): JTAG + I2C access
  to the **operator's own** devices. JTAG mediates OpenOCD strictly through
  `sandbox.exec()` — halt/resume/reset, bounded memory reads (reads never
  auto-halt, so they can't silently change target state), flash write; the
  destructive ops (flash, reset) stay refused until `[embedded] allow_flash
  = true` (default OFF, wizard-exposed). I2C is a pure protocol layer over
  an injected bus seam (`smbus2` via the `[i2c]` extra). Every op names its
  explicit target — no autodetect-and-flash; failures are `ERROR:` strings.
- **Perceptual hashing** (`perceptual_hash.py` +
  `extensions/webgpu-vision/ahash.js`): an 8×8 average-hash specified in
  integer-only arithmetic so the Python implementation
  (`average_hash_from_pixels`/`average_hash_file`, `[computer-use]` Pillow)
  and its JavaScript twin produce a **bit-identical** hash — a
  cross-language "are these two screenshots the same screen?" primitive
  (Hamming distance). It knows coarse luminance layout only; it is not a
  trained vision model.
- **Mobile companion v1 + offline cache** (`apps/mobile-companion/` +
  `offline_bundle.py`, `GET /api/v1/offline/bundle`): a read-only Expo
  scaffold (Runs list, Run detail, Glance, Settings) that consumes only
  existing GET endpoints with a bearer token in `expo-secure-store`; zero
  mutating calls. The **offline bundle** is a compact, bounded, versioned
  snapshot (`maverick-offline/1`: glance + goals + recent events, every
  list capped, no secrets — enforced by test) the app caches in
  AsyncStorage and renders behind an "as of N min ago — offline" banner
  when the dashboard is unreachable.
- **Benchmark reproducibility audits** (`benchmark_reproducibility.py`):
  every new benchmark run can carry a manifest
  (`maverick-bench-repro/1`: host fingerprint, config + input digests, env
  key presence/absence — never values); `verify_reproduction(a, b)` says
  exactly which digests differ and calls runs "comparable" only when
  config+inputs match; `audit_report()` sweeps the stored history. Two
  runs with differing digests are never claimed comparable.
- **Compaction v6 hybrid** (`compaction/hybrid.py`, *experimental — opt-in
  via `[compaction] hybrid`, wired into the live compaction path*): the
  strategy picker learned from this deployment's own outcomes —
  deterministic features over the message window, a per-(feature-bucket,
  strategy) outcome ledger (atomic 0600), epsilon-greedy with an injected
  PRNG, and an optional pure-Python logistic `fit()` (no torch) whose
  versioned weights the picker consults when present. Cold start = the
  existing default strategy; every failure falls open like all compaction
  paths. An online-learning heuristic, not a pretrained model — stated in
  the docstring. With the knob on, `compaction.plugins.compact_with` (the
  agent's live dispatcher) consults the picker, maps its abstract
  vocabulary onto the registered implementations (truncate/structural →
  heuristic, retrieval → graph, summarize → learned), and records the
  achieved shrink back into the ledger so selection improves on this
  instance's own results; an explicitly configured
  `[context] compaction_strategy` always wins, with a one-time warning
  when both knobs are set.
- **Sandbox pool: Firecracker-warm + cross-run pooling**
  (`sandbox/firecracker.py` + `sandbox/pool.py`, `[sandbox]
  cross_run_pool` default OFF): Firecracker warm mode keeps one e2b
  microVM alive between execs (the local firectl path can't, and says so
  honestly). The optional cross-run API transfers an immutable Docker/Podman
  policy into a fresh, digest-pinned backend and retires the old handle.
  It excludes protected mounts, unknown state, active operations, unresolved
  cleanup and warm guests. Ordinary runner teardown does not park instances:
  the current architecture adds image checks without avoiding guest startup,
  so automatic activation and startup benefits remain unqualified. See
  [sandbox policy handoff](operations/sandbox-pool.md) for ownership and limits.
- **Out-of-process model proxy** (`model_proxy.py`): the provider key lives
  in a separate proxy process; the agent's `base_url` points at it with only a
  proxy client token, not the provider credential — the proxy authenticates the
  caller, strips the client token, injects the real key, and allows only
  model-inference routes by default.
- **Glance endpoint** (`GET /api/v1/glance`): a fixed tiny status payload
  for small-screen clients.
- **Granular redaction UI** (`GET /redact` page + `POST
  /api/v1/redact/preview`): paste text, see every secret/PII finding as a
  kind + span (never the raw value), and pick per-kind what to scrub —
  empty selection runs full provable redaction; a granular selection
  replaces only the chosen kinds' spans and *honestly* reports
  `proven_clean: false` with the residual kinds left behind, instead of a
  false guarantee. Preview-only: nothing is stored server-side.
- **Goal Map — visual graph editor** (`/graph-editor` + `GET /api/v1/goal-tree` +
  retitle/reparent/add-child endpoints): the goal forest as an interactive
  SVG node graph — server-side layered layout (pure, unit-tested), pan/
  zoom, status colors — with editing that refuses cycles and self-parenting
  (400), access-checks both ends, and creates children **pending, not
  auto-run** (stated in the UI). A keyboard path via labeled selects keeps
  it accessible.
- **Drag-and-drop goal builder** (`/goal-builder`): compose a goal from
  blocks — steps (ordered checklist), budget, channel, priority — native
  HTML5 DnD plus keyboard add/move/remove buttons, live brief preview. The
  budget block is enforced as the runner's real `max_dollars` (clamped to
  the server cap); channel/priority ride in the brief and say so.
- **Embedded analytics web component**
  (`/static/lightwork-analytics.js` + `/embed-demo`; the pre-rebrand `/static/maverick-analytics.js` URL and `<maverick-analytics>` tag still work): a self-contained
  `<lightwork-analytics>` custom element (Shadow DOM, no framework, no CDN)
  fetching the real spend + goals endpoints and hand-drawing SVG
  sparklines/bars; same-origin/token limits documented in the JS header and
  on the demo page; errors render as HTTP status, never fake data.
- **Benchmark live dashboard** (`/benchmarks` + `GET /api/v1/benchmarks`):
  installation-admin-only per-suite trend sparklines + regression verdicts over the real
  `continuous_benchmark` history (`bench_track`), via the real
  `detect_regression`; honest empty state naming the record command. No
  fabricated competitor numbers — this page is *this deployment's* recorded
  runs.
- **Embedded video walkthroughs** (`/walkthroughs` + `POST
  /api/v1/goals/{id}/walkthrough`): standardizes `~/.maverick/walkthroughs/`,
  drives the real `replay_video.render` (sandbox-mediated ffmpeg; reports
  encoded vs manifest-only honestly with the exact argv), generates a real
  WebVTT captions track from the storyboard frames, and lists MP4s with
  native `<video controls>` + `<track>`; strict name-pattern media serving.
- **3D plan view** (`/plan-tree-3d`): raw WebGL (no three.js) point-sprite
  nodes + line edges over the same `goal-tree` endpoint, orbit/zoom,
  click-to-focus overlay; the text tree is always present in `<details>`
  as the accessible/no-WebGL representation, and the WebXR "Enter VR"
  button appears only when `navigator.xr` reports support (untested
  without headset hardware — stated on the page).
- **RTL language support** (`i18n.py` `RTL_LANGS` + `dir_for()`):
  `dir="rtl"` driven by the language the page body is written in (ar/he/fa/ur
  via `content_lang()`, so an English page is never mirrored by a browser
  or cookie that selects Arabic chrome strings), logical-property CSS in the base layout, and an
  Arabic community-seed catalog (genuinely translated starter keys, English
  fallback; he/fa/ur activate the moment a catalog lands — they're not
  offered in the picker until one does, to avoid implying support).
- **Live-run IDE extensions** (`apps/vscode-extension/` +
  `apps/jetbrains-plugin/`): the VS Code extension gains "Watch run live" /
  "Stop live watch" — a dependency-free SSE tail of the dashboard's
  per-goal event stream into an output channel (manual SSE parse,
  exponential-backoff reconnect, terminal-control stripping, token header
  honored, settings for URL/token; type-checks clean). The JetBrains
  scaffold mirrors it as a Runs tool window (Kotlin, same SSE endpoint,
  same backoff); building it requires the IntelliJ SDK, stated in its
  README.
  Browser/mobile viewers drain server-cursor pages before declaring completion;
  IDE streams resume from the last displayed event and stop on terminal
  acknowledgement or access denial. Requests have owned deadlines/cancellation
  and bounded display history. Editor halt/clear actions require a checked local
  CLI acknowledgement; remote start timeouts remain unconfirmed until reviewed.
  See [client lifecycle and qualification limits](client-request-lifecycle.md),
  including older React Native transport buffering and native-app test gaps.
- **Glance payload** (`glance.py`): a tiny fixed payload sized for a small
  screen — active count, today's done/failed, today's spend (summed from the
  usage ledger), and the last terminal result (60-char bound) — computed in
  one cheap pass and served at `GET /api/v1/glance`.
- **Smart notification batching** — opt-in `[notifications]
  batch_window_seconds` (`notification_batcher.py`): coalesces the
  low/normal-priority push stream (ntfy/Pushover/Discord/Slack) into one
  windowed digest ("5 updates" with the lines folded in) so a long run doesn't
  turn a phone into a slot machine; **high/urgent** notifications cut the line
  and deliver immediately (flushing any pending batch first, so order holds). A
  daemon flusher drives the window; unconfigured, `notify()` is unchanged.
- **First named local owner** — `maverick_dashboard.local_owner` and
  `local_owner_routes` let a fresh loopback-only installation create its first
  administrator inside Start. A salted local passphrase reopens the existing
  signed invite session; the claim closes anonymous access before role setup.
  Managed sign-in, existing identities, deployment invite policy, current roles,
  and SCIM revocation remain authoritative. The installer exposes
  `[dashboard] local_owner_setup`; see [first run](getting-started.md#first-run).
- **Personal device pairing preview** — default-off `[device_pairing] enabled`
  lets named members approve an expiring device code. Scoped credentials read
  only their own work in one workspace, with protected renewal and explicit
  removal in Your paired devices. Mobile settings store the connection
  securely. See [scope, retention and qualification](device-pairing.md).

## Packaged governance, evidence and external privacy control planes

- **Packaged governance agents** (`governance_agents.py`, dashboard
  `/governance-agents`, opt-in `[governance_agents]`) — five closed agent kinds
  (`breach_response`, `privacy_risk_assessment`, `program_copilot`,
  `knowledgebase_governance`, `third_party_risk`) share immutable tenant policy,
  independently resolved principal/context and adapter/dispatcher authority,
  bounded analysis reservations, closed cited findings/actions, distinct human
  review, signed execution receipts, retry/recovery/revocation, tenant quotas,
  retention and integrity. HTTP callers cannot supply raw evidence, runtime
  identity, credentials or dispatch destinations. Consequential execution
  requires a deployment-installed durable one-time token vault; encrypted
  storage and HSM/KMS custody remain deployment responsibilities, and the
  product does not bundle a licensed OneTrust-equivalent knowledge corpus.
- **Multimodal AI Evidence Analysis** (`ai_evidence_analysis.py`, dashboard
  `/ai-evidence-analysis`, opt-in `[ai_evidence_analysis]`) — bounded PDF, JPEG,
  Excel and text artifacts are raw-transient adapter input. Durable records
  contain only metadata/digests, immutable dynamic criteria, independently
  attested extraction and analysis receipts, closed cited facts, deterministic
  summaries, transparent justification components, criterion assessments,
  gaps/remediation, provenance and human-review state. A distinct authorized
  reviewer releases results; revocation, retention and integrity are explicit.
  The tenant-configured authority-history budget fails closed while preserving
  a bounded terminal-revocation reserve. Case quotas count only live,
  unrevoked artifact authority, so expiry releases capacity without erasing
  retained history. Maintenance purges retention-due analysis data and then
  compacts retention-due artifact, criteria and reviewer authority chains into
  digest-only replay tombstones; after a second retention interval it folds
  expired tombstones into a constant-size rolling anchor and VACUUMs/truncates
  the active SQLite registry. Local adapter authority remains on its explicit
  rotation/revocation path and is never silently bootstrapped by compaction.
  Status reports only the current tenant's enabled media and configured byte
  limits. Legacy XLS/OCR availability is true only when that parser is enabled
  for the tenant and the side-effect-free operational readiness check succeeds;
  configuration alone is not reported as runtime availability.
  The schema-bound API result covers the public `aiEvidenceAnalysisResult`
  outcome locally without claiming OneTrust wire compatibility, calibrated
  detection quality, preview entitlement or customer acceptance.
  **Upgrade note:** the local evidence adapter is revision 4; its
  implementation identity differs from revision 3 because the store closes its
  SQLite connections. A registry that enrolled revision 3 must enroll it again.
  Enrollment is `POST /api/v1/ai-evidence-analysis/authorities/bootstrap`
  (global admin permission). The installed store and registry factories also
  enroll it on the first analysis or authority request, including the purge
  request `POST /api/v1/ai-evidence-analysis/retention/purge`, so those requests
  need no separate step. No dashboard control or CLI command calls the bootstrap.
  Until enrollment, the cross-suite context reports `integrity_unverified`
  and readiness reports not ready. Analyses recorded before the upgrade carry the
  revision 3 adapter authority: review and `get_released` refuse them, but `get`,
  `history`, the analysis list and the cross-suite context still show their
  stored status (for example `review_approved`). Do not treat a pre-upgrade
  approved record as released; run a new analysis for each one that still needs
  review.
- **Assessment-question comments** (`assessment.py`, assessment-session API) —
  create audited, bounded comments only for section/question pairs pinned to
  the saved questionnaire and retrieve deterministic bounded pages ordered by
  section, question and time. Comments do not mutate the assessment follow-up
  workflow. This is a local contract, not accepted OneTrust API compatibility.
- **California DROP request/status management**
  (`privacy_drop_management.py`, `/api/v1/privacy/drop`,
  `/api/v1/privacy/drop/authority`, opt-in
  `[privacy_automation.drop_management]`) — independently resolves exact
  tenant, registered-broker, subject, request, template and principal authority;
  composes `DataDeletion` or `OptOut` through the existing privacy-rights intake
  callback; and records evidence-bound `PENDING`, `EXEMPTED`, `DELETED`,
  `OPTED_OUT` or `NOT_FOUND` outcomes. Only opaque references and digests are
  durable. The mounted liquid-glass workbench and Copilot context cover broker
  enrollment/revocation, record import/revocation, outcome proposal/approval,
  revisions, integrity and principal-binding key rotation/retirement/migration.
  Every authority mutation uses a durable proposal, server-resolved tenant and
  actor, independent administrator approval, CAS and idempotency. Versioned
  secret-provider/KMS key references keep current and previous bindings
  verifiable; retained dependencies block retirement and unknown, retired or
  revoked revisions fail closed. An opt-in managed scheduler provides a durable
  cross-process lease, retry/recovery state, per-tenant failure isolation and
  lifespan shutdown while preserving the one-shot coordinator. Readiness
  separately reports `configured_for_attempt`, `locally_operational`, authority
  counts, scheduler health and `request_executable`; zero active records means
  no request can execute. It does not scrape DROP, accept raw caller-supplied
  subject identity or key material, or prove live California authority/broker
  interoperability, subject matching, legal/regulator acceptance or production
  delivery.

## Software development: the code vault

- **Vaulted repositories** (`codebase/vault.py`, `maverick code add|sync|export`):
  every branch and tag in one sealed git bundle per repository; plaintext only
  in private, short-lived working copies; credentials named by environment
  variable, never stored; hardened host git.
- **Feature swarms** (`codebase/features.py`, `maverick code feature|proposals|
  show|merge|push`): a governed swarm builds the change on a branch, labelled
  `code:<repo>` and enforced at the repository's protection mode; the repo's
  tests run in the sandbox and the independent reviewer reads the diff; the
  sealed proposal waits for a `codebase_merge` approval before any merge or push.

## Information-flow control

- **Runtime label tracking** (`ifc.py`, `[ifc]`): a sensitive read labels the
  agent (`data:<tool>`; a codebase run starts `code:<repo>`), labels propagate
  through the blackboard, spawns and the peer bus, and a labelled agent's call
  to an external sink is recorded, held for human approval, or blocked at the
  tool gate. Fingerprints witness literal copies; `ifc_flow` audit rows record
  labels and outcomes, never data.

## Adaptive immunity

- **Composition-risk discovery** (`immune/network.py`, `maverick immune network`):
  finds data paths from sensitive reads to external reach across agents
  (Rule of Two), evaluated at each pack's runtime capability or on any agent
  graph, with a tool-level witness and the risk of the least-guarded sink.
  `domains-audit` reports `runtime_expansion` / `runtime_reachable_dangerous`.
- **Proof of Oversight** (`immune/oversight.py`): opt-in canary approvals
  (`[immune] canaries`) measure reviewer catch rates per person and decision
  class; Wilson-bounded earned authority; no-agent capability drills; crux
  finding; signed oversight records. Canaries never feed agent graduation.
- **Discovery Title** (`immune/title.py`): commit-reveal priority, pre-run
  input commitments, human conception gates with a claim-to-conception map,
  verification and coverage; signed and verified offline. Governed research
  runs supply gates and input commitments from their hash-chained planning
  events (`maverick immune title research`).
- **Production twin** (`immune/twin.py`, `maverick immune twin replay`): opt-in
  recording (`[immune] twin_record`) of each goal's tool results, sealed and
  tenant-scoped; a replay re-runs the goal with the recorded results served in
  place of the tools, so nothing live is touched and nothing marks the run as a
  test. Near-identical calls are served within a similarity tolerance and
  reported as divergences; anything further is refused and counted.
  `maverick immune awareness --goals` replays recorded goals with and without
  an evaluation cue and tests the behaviour gap. `canary-auto` models canaries
  on real approvals with one planted flaw.
- **Analyses** (`immune/policy.py`, `invariance.py`): rule replay and
  contradiction discovery, evaluation-awareness gap and model-swap drift.

## Unified cross-suite audit projection

- **Closed, signed projection plane** (`unified_audit.py`): the default-off
  `[audit.unified]` capability requires `[audit] sign = true` and always tracks
  exactly six source families: AI Governance, Consent & Preferences, Data Use
  Governance, Privacy Automation, Tech Risk & Compliance and Third-Party
  Management. The source set is not tenant-configurable, and the normalizer
  accepts only closed action and limitation codes rather than raw payloads,
  free-form actions or raw actor/resource identifiers.
- **Separate source and verification authority**
  (`suite_audit_capture.py`, `stock_suite_audit_capture.py`,
  `stock_unified_audit_sources.py` and `unified_audit_sources.py`): the reusable
  core provider exposes canonical digest-only histories from the AI-governance
  loop, consent outbox, data-use mutation ledger, signed privacy audit, TRC
  continuous-evidence audit and third-party lifecycle audit without importing
  the dashboard or audit sink. Lightwork installs thin lazy page readers plus
  separately instantiated local re-verifiers over that provider. A deployment
  can replace the complete pair
  through the existing app-state factories. Exact source revision, capture
  digest, head, count, schema, completeness and retention limitations are
  double-read; drift or tampering fails closed. A source can become complete
  only when signed-and-anchored verification names the exact source authority,
  verifier identity, trust-root revision and source key. A self-asserted local
  re-verification remains visibly incomplete.
- **Stable, receipt-bound projection:** canonical source records receive stable
  projection identifiers, and every page -- including an empty terminal page
  -- produces a mandatory signed page receipt. The tenant-bound strict sink
  writes only to the canonical tenant audit directory, verifies the containing
  signature chain and binds its receipt to the exact projected event before a
  cursor can advance. Authority, schema, verifier, trust-root or source-key
  rotation must match an explicit pending authorization pin.
- **Recovery and operator surface:** generation sweeps prevent stale prior
  success from appearing current; CAS leases support renewal, bounded reclaim,
  retry/backoff and replay; revocation, immutable state history and local
  state/history integrity linkage are explicit. Mounted audit/admin APIs expose
  status, source state, history, integrity, reconcile, replay, revoke and
  rotation authorization. A bounded lifespan scheduler uses only active tenant
  registry records, a stable tenant-bound worker identity and one six-source
  reconciliation run per enabled tenant per cycle.
- **Managed custody composition** (`unified_audit_custody.py`): the separately
  opted-in `[audit.unified.custody]` run uses the existing checkpoint, WORM and
  SIEM primitives under one strict tenant-local cross-process lock. It verifies
  signed day chains and cross-day anchors, stages a tenant-exact checkpoint,
  can push only already anchored and already sealed closed days to a
  tenant-namespaced local or S3 Object-Lock target, and can forward bounded
  unified-projection batches to an exact tenant HTTPS path. A durable,
  integrity-linked cursor provides at-least-once recovery; authority revision
  rollback, same-revision drift, mid-run config drift and cursor mismatch fail
  closed. The runtime never seals files automatically.
- **Boundary:** The six stock readers cover one canonical authority per suite,
  not every module/history within each suite, and therefore report
  `source_history_incomplete` and `source_retention_unverified`. Their separate
  verifier process boundary has not been independently operated or accepted.
  Tenant-local checkpoint staging is not independently operated assurance, and
  configured S3/SIEM code is not proof of a live Object-Lock account, off-host
  key custody, provider acceptance, or customer operation. Live scheduler
  crash/recovery, concurrency, scale and full provider/source completeness
  remain unverified.

## Distribution and install

- **Private workbench recovery**: vendor onboarding, account connections,
  workspace members and knowledge access share response classification and
  request epochs. Session/context loss clears private state and keeps controls
  locked; action denial preserves authorized views and disables that action.
  See [Workbench access recovery](client-access-recovery.md).

- **Workspace recovery center** (`workspace_recovery.py`, dashboard
  `/workspace/recovery`): opt-in administrator snapshots, authenticated bounded
  import/export, separate key custody, real restore drills, and account/build-
  bound reviews with safety snapshots and transactional rollback. Separate
  desktop recovery mode holds a fresh control-plane lock and starts no normal
  background lifespans. Shared/external stores, independent workers, shared
  administration and cross-build restoration remain excluded. See
  [Workspace recovery](workspace-recovery.md).
- **Windows MSI installer candidate** (`apps/installer-msi/CUSTOMER.md`):
  complete frozen runtime, desktop and offline WebView2 without a Git, Python
  or source checkout on the target machine; Windows install/repair/upgrade acceptance,
  protected Authenticode/minisign signing and reviewed in-app maintenance.
  Protected completed-upgrade rollback retains exact signed installers and
  restores their matching, quiesced whole-local-home snapshot after verifying
  the old runtime; interrupted operations keep a startup block, resumable
  review and in-app logs. Native MSI, signed distribution and clean-machine
  acceptance remain release gates; fixture checks are not installation acceptance.

- **Packaging** — release tooling for an 8-package lockstep cohort (public PyPI
  publishing remains disabled until every name is reserved), a GHCR image,
  PyInstaller binaries, checksums, SBOMs,
  and Sigstore material. None of these artifacts is published yet; see
  [DISTRIBUTION.md](./DISTRIBUTION.md). Existing source-bootstrap Tauri/MSI
  outputs retain their engineering boundary; the separate MSI candidate and its
  acceptance gates are described above.
- **Container import-path hardening** — the deploy image sets
  `PYTHONNOUSERSITE=1` for the harness interpreter: system site-packages are
  root-owned, so the only writable import path a model-driven `pip install
  --user` could reach was the user site — where a mid-run install shadows any
  module the harness lazily imports later (poisoning the process that holds
  credentials and enforces the gates). The sandbox's child-shell env drops
  the var (`scrub_env`), so packages the agent installs for its OWN scripts
  keep importing; only the harness process is closed off.
- **Backwards-compat tooling** — `maverick migrate` (`migrate.py`): walks an
  existing config forward — real migration advisories (Twilio WhatsApp → the
  first-party Cloud API adapter), unknown-section lint with did-you-mean
  suggestions (a typo'd section silently no-ops), and a mechanical-rename
  engine that only writes behind a timestamped backup (rename table empty
  today; 2.0 renames land on it). Dry-run default.
- **Deployment blueprints** — reference architectures for **Kubernetes / AWS
  ECS (Fargate) / Fly.io / Railway** (`deploy/reference-architectures/`):
  contract-tested manifests sharing the canonical image, `:8765` dashboard
  surface, `/home/maverick/.maverick` state volume (image runs as the unprivileged `maverick` user, not root), and secrets-from-platform-store
  rule. **Devcontainer + Codespaces template** (`.devcontainer/`) mirrors CI's
  editable install so `maverick --help` and the test suite work on open.
- **Scaffold generators** — `template_generator` tool: emit a validator-clean
  `SKILL.md` (op=skill) or a `Channel`-subclass adapter scaffold with the
  start/send/stop seams (op=channel); deterministic codegen.
- **IDE / CI** — VS Code extension (`apps/vscode-extension/`), **Emacs
  package** (`apps/emacs/maverick.el`: M-x maverick-start/status/monitor/
  logs/halt/unhalt over the CLI, deps-free, Emacs 27.1+), **Neovim plugin**
  (`apps/nvim/`: :MaverickStart/Status/Monitor/Logs/Halt/Unhalt, lazy.nvim-
  ready, terminal-split UX), **Zed extension** (`apps/zed-extension/`:
  registers `maverick mcp` as a context server — Zed extensions run in a
  WASI sandbox and cannot exec, so CLI verbs ship as Zed tasks; compiling
  needs the Zed SDK, stated in its README), GitHub Action wrapper
  (`maverick-action`) — all contract-tested against the real CLI verb set.
- **Native desktop engineering scaffold** (`apps/desktop/`): a Tauri v2 shell for the local
  dashboard — splash probes `127.0.0.1:8765/healthz` with bounded aborts and
  elapsed-time recovery controls; stale attempts cannot navigate after retry.
  It spawns `maverick dashboard` when the port is closed and requests owned
  child shutdown over a private pipe before bounded process-tree termination.
  Maintenance still requires observed process/socket quiescence. See
  [Dashboard lifecycle](dashboard-lifecycle.md). macOS/Windows/Linux targets ship unsigned
  (installer-desktop posture), building needs Rust + Tauri CLI. It is not
  attached to product releases or claimed as a signed installer.
- **Windows MSI engineering build** (`apps/installer-msi/`): WiX v4 authoring set — per-user
  scope, stable UpgradeCode + MajorUpgrade, user-PATH component, a launcher
  that bootstraps the bundled wheel into the console-script target —
  plus `build.ps1` and a dispatch-only `build-msi.yml` workflow; building
  and signing happen on a Windows host (maintainer act); the output is not a
  current product-release artifact.
- **Reduced multi-arch builds** (`deploy/multiarch/`): buildx Dockerfile +
  script for exactly linux/amd64 and linux/arm64, installing the constrained
  core + shield cohort with an optional dashboard. The runtime includes native
  dependencies; RISC-V is rejected because there is no tested wheel/toolchain
  path. Use the standard image for the complete eight-package platform.
- **Hosted demo cluster blueprint**
  (`deploy/reference-architectures/demo-cluster/`): compose + k8s manifests
  for a public read-only demo — the dashboard has no global read-only flag,
  so an nginx deny-proxy (`limit_except GET HEAD`) fronts it with the
  bearer injected upstream; a seeder creates finished demo goals through
  the real world model; DNS, TLS and hosting a public instance are outside
  the blueprint. Contract-tested like the other reference architectures.
- **Interface contracts** ([`docs/contracts/`](./contracts/README.md)) — the
  versioned contracts the supplier workflow and platform layer implement:
  platform contracts v1, worker authority binding, staged local restore
  reference validation, supplier request cancellation and the supported
  supplier evidence journey.
- **Embeddable widgets** — two dependency-free `<script>`-tag surfaces,
  both self-hosted: the floating **chat widget**
  (`extensions/chat-widget/maverick-chat-widget.js`) posting to your own dashboard's
  `/chat/send`, and the read-only **status widget**
  (`extensions/widget/maverick-widget.js`): a Shadow-DOM pill → panel
  polling the real goals API and bucketing counts client-side, with the
  auth posture documented exactly (Bearer header only; same-origin or a
  reverse proxy — the dashboard ships no CORS; the token is the full
  control surface, so embed only where you'd paste the token).
- **Self-hosted relay** — a stdlib edge service (`deploy/relay/relay.py`) that
  HMAC-signs an inbound POST and forwards it to a dashboard's `/webhook/start`
  exactly as `maverick.webhooks` verifies (replay-defended; signature
  round-trip tested) — the self-hostable counterpart to a hosted bridge.
- **Docs** — MkDocs site, [getting started](./getting-started.md), 30-recipe
  [cookbook](./cookbook/), [architecture](./architecture.md),
  [embedding guide](./embedding.md), [security hardening](./security-hardening.md),
  and a self-serve
  [observability integrations guide](./integrations/observability-partners.md)
  (OpenRouter provider, OTLP-generic tracing incl. LangSmith, Helicone via
  base_url override).
- **Long-form handbook** ([`docs/handbook.md`](./handbook.md)): the front
  door — mental model, guided tour, day-2 operations, safety posture,
  extension points, and a map of every other doc; every cited command and
  module verified against the tree.
- **Localized docs** ([`docs/i18n/`](./i18n/)): real, native-quality human
  translations of the getting-started guide into **9 languages** — Spanish,
  Japanese, German, French, Brazilian Portuguese, Korean, Russian, Italian,
  Hindi — each following its language's software-docs register, with code
  blocks/commands/paths kept byte-identical and a source-commit header so
  staleness is trackable. The **docs MT pipeline** (`docs_i18n.py`, `python
  -m maverick.docs_i18n`) machine-translates the tail under hard quality
  gates (fenced code preserved, glossary + structure verified before
  anything is written, human translations never overwritten); `--check` is
  offline, and the model resolves by the `translator` role.

## Customer workflow completion and readiness

- **Action Center** (`maverick_dashboard.action_center`, `action_center_api`):
  permitted approvals, current deliverable sign-offs, assessment review dates
  and assigned project review packets share a personal list. Account/workspace
  read and snooze state binds to source versions and optimistic revisions;
  overdue actions remain visible and missing sources remain explicit.
- **Guided reviewed outcomes** (`guided_outcome`, `onboarding_state`): setup
  paths for permitted deliverables, privacy assessments and vendor evidence
  complete only on a current qualifying human review. Scheduled or completed
  activity alone never establishes customer success.
- **Recoverable authoring** (`draft_store`, `draft_api`, `domain_edit`): sealed
  private recovery copies, source CAS and exact retry identities for supported
  editors. Credentials and attachments are excluded. Consent catalog/version
  pickers keep publication decisions bound to explicitly selected content.
  See [draft recovery](draft-recovery.md).
- **Current record search** (`record_search`, `record_search_sources`): bounded
  authorized metadata search in the app page finder. Source failure and scan
  limits are visible; paging binds to the current result snapshot and account.
  See [record search](record-search.md).
- **Privacy source connection setup** (`privacy_discovery_credentials`):
  saved versioned connection selection, principal/connector/origin checks on
  transport requests, sealed evidence-key rotation and explicit source probes.
  See [privacy discovery setup](privacy-discovery-setup.md).
- **Governed document intake** (`vendor_onboarding_documents`): bounded native
  Google Docs/PDF/text evidence and reviewed local Word/Excel uploads, with
  explicit human transcription for unreadable PDFs (no OCR). Transient previews
  require original comparison before adding evidence; retained hashes and
  paragraph/page/cell references distinguish extracted and user-supplied text.
  Multiple sources, contradictory facts, exact source versions and renewal
  differences remain governed. Live provider and customer
  acceptance remain deployment-specific. See [vendor onboarding](vendor-onboarding.md).
- **Held GRC reconciliation** (`grc_sync`): capture the attempted payload and
  target; compare a remote record read-only; confirm a fresh exact match or
  keep delivery held with an audited explanation. Confirmation never resends.
- **Project team reviews** (`project_reviews`, `project_reviews_api`): selected
  fixed task results, current workspace membership, independent reviewer
  decisions, comments and revocable access. This grants no live execution or
  sign-off authority. See [project reviews](project-team-reviews.md).
- **Workspace recovery** (`workspace_recovery`, `recovery_api`, `recovery_mode`):
  signed snapshot custody/inspection, measured temporary restore and controlled
  restoration in an isolated local control plane. External/shared stores and
  encryption-key dependencies remain explicit. See [workspace recovery](workspace-recovery.md).
- **Reviewed signing identity bridges** (`release_identity_transition`,
  `installation_recovery`): default-off global Settings/wizard control, dual
  updater-key proof, exact publisher/release/hash binding and separate in-app
  administrator admission. Retained exact-pair resume survives admission expiry;
  Windows publisher checks and accounting/replay drift refusals remain. Real
  rotated-publisher installation acceptance is separate. See
  [signing transitions](windows-signing-identity-transition.md).
- **Help and diagnostic controls** (`maverick_dashboard.support_api`,
  `support_center`): `/help` provides in-app status, troubleshooting guidance
  and reviewed diagnostic exports. Discarded authoring-copy retirement removes
  retained payloads while preserving their monotonic revision floor. See
  [help and diagnostics](help-and-diagnostics.md).
- **Provider spending recovery** (`provider_spending_recovery`): in-app
  administrator review of unavailable accounting and unresolved reservations,
  exact-receipt reconciliation and bounded diagnostics. Local corrupt-state
  repair requires isolated recovery and complete reviewed authoritative totals;
  unknown costs are not refunded automatically. See
  [provider spending](provider-spending.md).
- **Durable usage receipts** (`quotas`, `checkpoint`, `orchestrator`): cumulative
  atomic ledger receipts, lost-ack reconciliation, safe missing-checkpoint
  refusal and a private Billing trail. These are internal quota records, not
  provider invoices. See [runtime recovery](runtime-accounting-recovery.md).
- **Workflow pilot observations** (`outcome_pilots`, `outcome_pilot_sources`):
  prepare tasks without running them, freeze case plans, record attributed
  effort/review/rework/corrections and compare current paired observations.
  Every planned case remains in the acceptance denominator. Recorded runtime
  prices, reported full costs, actual provider evidence and controlled held-out
  acceptance remain separate. Goal-only plans can explicitly exclude holdouts
  and their child goals from supported automatic local learning paths, retain
  prior-exposure statements, and request a different named administrator's
  evidence-bound review. This does not verify prior or provider exposure.
  See [workflow pilots](workflow-pilots.md).
- **Outcome accounting contract** (`outcome_accounting`,
  `outcome_accounting_api`): tenant-scoped admitted-work records retain source-
  versioned observations, corrections, human decisions, cancelled/failed work,
  failed-attempt costs, and explicitly unpriced amounts. The in-app projection
  keeps technical verification, business acceptance, and cost completeness
  separate. Portfolio responses use bounded cursor pages, reconcile every row
  shown, and label when more admitted records remain. Detail responses include
  the shared `lightwork.contract.outcome-record.v1` projection. This is an
  application accounting record, not an independently authenticated invoice.
- **Workflow readiness** (`workflow_readiness`): an in-app inventory labels
  available/bounded workflows, live validation requirements, previews,
  experimental features, prototypes and the Windows release candidate.
  Effective enablement is shown separately from acceptance and certification.

Each configurable surface is represented in Settings and the installer wizard.
Native signing, clean-machine installation, provider permissions, live external
mutations and customer acceptance are not qualified for the surfaces in this
section.

### Document text coverage and private engine jobs

Attachment companions and knowledge ingestion use versioned, loss-aware
extraction with ordered DOCX table/XLSX cell locations, source/normalized hashes,
explicit omitted regions and truncation. Unsupported binary formats are never
UTF-8 replacement text. See [Document extraction](document-extraction.md).
Office export, image OCR and LaTeX share private document jobs with backend
capability checks and verified output manifests. Missing or invalid outputs
retain previous artifacts; native image execution remains separately qualified.
See [Document processing](document-processing.md).

Chat and REST uploads share bounded staging and serialized attachment admission.
Chat retries use owner/tenant-bound submission receipts, invalid batches create
no task, interrupted storage stays an explicit draft, and companion availability
is recorded before dispatch. Keyed REST admission shares the atomic receipt
transaction; browser/widget lost responses reconcile the original key through a
read-only endpoint without repeating a start. See
[Attachment submissions](attachment-submissions.md) and
[Client request lifecycle](client-request-lifecycle.md).

- **Named OAuth renewal** — [per-connection refresh ownership](connection-refresh.md), with short shared-store transactions and conservative recovery for ambiguous rotating tokens.

- **Messaging delivery receipts** — durable receipts and conservative recovery; see [Durable channel delivery](channel-delivery.md).

- **Bounded social polling** — notification pagination retains durable continuation and explicit incomplete status; see [Bounded social polling](channel-polling.md).

Signal/IRC readers run independently of serial durable agent work; see [Transport supervision](channel-transport-supervision.md).

Voice callbacks preserve saved results with explicit uncertain delivery; see [Live interaction boundaries](channel-live-interfaces.md), including blocked bootstrap authority restoration.

The [persistence authority inventory](operations/persistence-authorities.md) maps local/shared store ownership, transaction and recovery contracts. The control-plane singleton restriction remains in force.

### Owned CLI and TypeScript plugin processes

The optional Codex CLI provider owns cancellation, bounded output and process cleanup; the TypeScript host and version-2 SDK add bounded framing, execution deadlines and explicit no-replay outcomes. Legacy plugins remain supported under the same conservative replay policy. See [operating limits](operations/owned-cli-and-plugins.md).

### Bounded model proxy streams

The optional Python and Go proxies authenticate before admitting bounded bodies, stream responses with backpressure, and close owned upstream requests on disconnect or deadline. See [model proxy request ownership](operations/model-proxy-streams.md) for limits and buffered compatibility exceptions.

### Effective provider configuration

Provider adapters declare supported settings and refuse unsupported nonempty fields before dispatch. Immutable admitted settings preserve tenant-aware cache rotation and constructor environment identity. See [provider configuration admission](operations/provider-configuration-admission.md) for the capability matrix and migration guidance.

### PostgreSQL client I/O deadlines

WorldModel and governed-record connections bound established-socket waits, including commit, rollback and pool reset, while preserving unknown outcomes without replaying writes. See [PostgreSQL client I/O deadlines](operations/postgres-io-deadlines.md) for the independent client, connection and server timeout settings and reconciliation contract.

PostgreSQL learning stores use tenant-scoped keys for addenda, line metadata, transfer memory and corpus rows. [Migration 39](operations/learning-store-tenant-keys.md) preserves existing data and refuses unrecognized constraint layouts.

### Personal daily work and first-job activation

Today composes authorized native work, decisions, occurrences and template pins with personal card order, period and starting-page preferences. Employee activation keeps sample/real source drafts private, returns from scoped connection repair, starts through native submission receipts, requires current human acceptance and hands off reusable private workflow instructions. Both expose reviewed native Copilot operations; see [employee activation](employee-activation.md).
- **Selected-source analysis tasks** (`knowledge_task_context.py`, opt-in
  `[knowledge_access] task_context`): named members select exact approved sources
  in Knowledge for one budgeted, tool-free AI attempt. Native and typed Copilot
  admission share immutable references and current-use checks. Private results
  revalidate source access; ordinary task history and exports contain only a link.
  See [Selected-source analysis](knowledge-source-analysis.md).

- **Assessment precedent provenance**: per-question suggested answers show exact
  saved fragments, source dates, pinned/current questionnaire versions, named
  approval and supporting versus dissenting votes. Stale and unreviewed precedent
  stays visibly distinct from current approved precedent. Each value can be
  rejected or added to the respondent draft independently under `assessments.learn`.
### Bounded model samples

Settings > Models combines reported capability/pricing evidence with separately enabled,
explicitly reviewed synthetic text/image generation tests. Each uses one admitted physical
request, narrow existing Budget limits, no failover/retry, and a durable account/workspace
receipt with native Stop and recovery. Copilot's Models family uses the same service.
Tool support remains provider-reported and untested. See [model choice tests](model-choice-tests.md).

- **Historical metadata discovery** — finder source/date/oldest filters, bounded
  current-authority continuation beyond recent-list caps, exact record and
  recovery links, and the shared typed Copilot operation. See
  [record search](record-search.md); governed by existing record-search Settings
  and installer controls. Migration 45 adds owner/date indexes; no content index.

### Local rule combinations, single-step checks and reported financial alternatives

| Product control | Native path and operating boundary |
| --- | --- |
| Check local rules together | Learning → Check local rules together. Choose two owned published pure rules and permitted retained cases. All supported finite starting values, both orders and separate native references count toward one reviewed work allowance. A qualified request can run with ordinary named inputs; it remains unpublished. |
| Prepare an answer for this request | Learning → Prepare an answer for this request. Choose up to three existing taught steps, permitted original cases and explicit desired answers. Every sequence through three steps is checked by the native runner. Only complete agreement among all surviving arrangements supports an answer. No arbitrary code or connected action is generated. |
| Try one taught step | Workflow builder or Designer → select a taught local rule with AI fallback off → Try. Ordinary exact text, whole-number and Yes/No inputs lead to a complete review and one native step. AI calls and connected actions are refused; the original request is retained without automatic replay. |
| Compare additional-work economics | Promise reviews → select current additional-work qualification → enter complete financial assumptions. Exact currency amounts and all incremental expenses are compared across jointly feasible offer/addition combinations while every accepted commitment stays protected. Demand, source availability and financial premises remain team reports. |

Each capability has a default-off Features control and an installer choice.
Native ownership, current authority, source custody, learning stops and review
expiry apply. Original records are distinct from fresh calculations and remain
unconfirmed after a calculation-to-receipt gap. Historical private values require
current source permission. These local mechanisms do not publish workflows,
reserve resources, establish future accuracy or demonstrate research superiority.

### Complete teaching-question plans and native original recovery

Learning → Plan teaching questions starts from an owned saved taught step and
all its surviving simple rules. Ordinary selectors choose an optional owned
published check rule, its named answer and earlier permitted effort reports.
The complete finite question plan covers every possible answer branch;
unreported effort uses the explicitly entered default. Yes/No and exact
whole-number/text answers have complete source and use-permission review.
Independent whole-domain native execution checks a proposed rule before Teach
can open its private unsaved draft. A separate full acceptance review and
source grant are required before normal Save; publication remains separate.

This default-off Features/installer control supports one to three inputs,
thirty-two complete situations and sixteen different surviving behaviors.
Question, planning and native-run allowances remain spent after withdrawal,
removal, interrupted replies or worker restart. Original history and an owner's
metadata-only Stop remain available when the capability is off or its original
workflow was removed. Current permissions, source versions, meaning and review
dates are checked again at admission, execution and the physical writer.

All settings, Chat's specialist questions and consent-banner withdrawal
have ordinary complete review and exact native original readback. Their
Copilot paths share the same protected services or hand off to their complete
ordinary forms. Copilot does not repeat uncertain original work.

### Reviewed access-key changes and exact original recovery

Account > Access keys collects named owners, permitted work, expiry and current
workspace choices. Create, rotate and revoke use a complete consequence review
and a native original request. A lost reply never issues another key. The secret
is shown once only to the current authorized account; original history retains
metadata without recovering or exposing the secret. A separately reviewed
revocation and replacement handles a lost one-time key. Copilot opens the same
protected ordinary controls and original reader. Existing API-key settings and
installation choices govern the feature.

### Recorded learning cycles and complete operating reads

Learning requires a confirmed signed start before a cycle can save insights.
Recent activity distinguishes recorded completion from an interrupted or
unrecorded result and opens the actual retained saved point for separate
restoration review. Copilot reads the same current-authority metadata without
starting another cycle. Existing audit-signing and learning settings apply.

Task starts use the current workspace helper-depth ceiling, including ordinary
starts that omit a depth. A reviewed narrower choice remains available from
Copilot. Original-outcome checks read the existing native task admission and
never dispatch a replacement.

Privacy source checks honor the configured Microsoft 365 token source. Failed
or incomplete checks stay visibly incomplete instead of implying no personal
data was found. AI-literacy reports either read every record within their
supported bounds or clearly withhold a complete report. Governed-agent activity
orders by actual last update, including after reopening the native store.

Task maps package their pinned Cytoscape library locally with its MIT notice.
Map, ordinary task navigation and live updates do not need a public CDN.

### Available recovery controls and accurate learning signals

The safety-settings error page opens real installation health controls on Help,
which remains available when the normal Settings page cannot read its policy.
A current installation administrator explicitly consents to service checks;
Copilot opens that protected form without starting a check or repairing settings.

AI-literacy assignment and completion forms expose every supported role and
training choice through ordinary search while keeping selected choices. Hybrid
context compaction keeps each workspace's existing weights and outcomes in its
own native storage. Read-only file denials remain refused tool results, not
successful signals for an agent or its learning loop.

Vendor evidence keeps incomplete sets visibly incomplete and their work-item
freshness unknown. Failed documents do not contribute an epoch date to usable
source freshness. API reference pages package their fixed Swagger distribution
and notices locally, retaining the ordinary endpoints and sign-in behavior.

Native scheduled skill retirement was also confirmed to stay within its
current tenant and configured skills directory.

### Correct task setup and routing feedback

Invalid task limits stop new work before admission, preserve the entered task,
and open the actual Settings repair control. Reviewed numeric repairs distinguish
an unknown prior limit from a safe relaxation and keep deployment-owned limits
visibly locked. Copilot reviews the same current limit.

Equivalent reviewed website findings share one native tracker registration while
retaining their separate observations. Conflicting mappings across the full report
stop before an update. Existing exact original requests remain the retry authority.

Optional route learning keeps each workspace's native history separate and binds
feedback to the original role, tier and selected model. Retained clients preserve
that decision; ordinary explicit model strings do not invent one. Failed calls
remain failures, and refused pre-send work contributes no routing outcome.
API-reference authorization and request protections also honor a real deployment
mount prefix without trusting forwarding headers or matching arbitrary suffixes.

### Saved installation safety settings recovery

Help can separately restore an exact retained installation safety-settings copy.
A global administrator chooses a saved copy, reviews its complete supported
settings and explicitly confirms. Current source, authority and review lifetime
are checked at native replacement. Original requests remain readable after an
interrupted reply; an unknown outcome is never repeated automatically.

This uses the existing Backup and recovery opt-in and requires it enabled before
damage, a verified retained copy and the original deployment encryption key.
The last 32 distinct policy copies are retained. Protected connection credentials
can roll back with the selected copy; their bytes stay hidden. Unsupported or
unsafe inline-credential reviews refuse without changing settings. This does not
restore workspaces, sign-in configuration or external services.

The rehearsal evaluation bridge reads the native current workspace queue
under the configured installation location, retaining explicit-path support and
local-source filtering. Explicit deployment-isolation off values agree with
the native work-area builder; independent container requirements and invalid-mode
refusal remain enforced. Signed workflow callbacks distinguish unavailable
workspaces from an unreadable workspace inventory before admitting continuation.

Local ranking training requires actual comparable saved work details.
Missing details, zero-confidence comparisons and structurally indistinguishable
examples cannot become invented training evidence. The ordinary form and
Copilot show usable, skipped and unresolved counts before admission. Cross-checks
abstain from missing or tied structural evidence; original answer-preference
pairs remain available for their separate purpose.

### Current signed skill preparation and local provider choices

Learning shows whether automatic skill preparation is off, needs trusted
publishers, lacks available signature verification, or can check signed matches.
The ordinary status and Copilot use the same current protected read. A working
Settings link opens the existing publisher-file upload. Missing prerequisites
stop before catalog search or optional AI analysis and post a plain task
observation; native signature enforcement remains unchanged. Readiness never
promises that a matching signed skill exists.

Local-first model choices use actual native provider identities and aliases,
preserving the selected model string. Unsupported adapters are excluded. Probe
ports agree with native Ollama and TGI dispatch; explicit role choices, the
existing opt-in and configured fallback retain their precedence.

Nightly learning review stops the combined scheduled command visibly when
the native learning stop is active, configuration cannot be read, or the review
fails. It reports a nonzero exit and warns that earlier changes may already be
saved. Explicitly disabled review stays a no-op; failure payloads are not copied
into the user-facing refusal.

Page controllers and styles in trusted literal template tags use the same
content-versioned URLs as the shell. Public unchanged scripts and styles can
revalidate without another response body; private or refused assets keep their
native authorization and cache policy. File metadata changes refresh cached
hashes, including a file that appears after an earlier missing-file check.

### Configured gateway screening and bounded web content

When request screening is explicitly enabled, an unavailable built-in checker
returns a readable service refusal before upstream forwarding or spending
admission. Existing text-free and screening-off behavior stays available, and
actual detector refusals remain blocked. Activity keeps digest/count metadata;
private request or exception payloads are not copied into the new refusal.

Web-page reads keep their 64KB default and accept at most 10MiB of retained
response content. Invalid download limits refuse before request preflight.
The ordinary workflow input uses the same native schema range; exact-limit
completion is distinguished from actual omitted content with one extra byte.

### Reviewed improvement cycles and visible incomplete learning

Learning and Copilot offer the same reviewed improvement cycle. Before it starts,
the customer sees the complete current and proposed safeguards and habits,
including removals and strength changes, the workspace, permitted work and local
cost limit. The cycle uses existing recorded work and native causal admission;
observational patterns alone do not qualify new guidance as proven improvements.

The reviewed source, permission, settings and guidance are checked again before
native writes. Empty permitted work preserves existing guidance. A required
learning safety copy and stop controls remain in place. Failed writes or missing
activity confirmations produce a visible incomplete or uncertain outcome,
including any earlier saved changes. The original task stays readable after an
interrupted reply without automatically repeating the cycle.

The combined nightly command also stops with a nonzero exit when this cycle is
incomplete or halted. Earlier changes may remain saved; failure is not reported
as a successful empty review.

### Reviewed product switches and truthful queued-task outcomes

All current product switches are available through the existing reviewed Settings
controls, with plain On/Off comparisons and original-save recovery. The Features
overview opens those controls. An old whole-form Features submission refuses
instead of overwriting newer switches. Current configuration precedence and
configured administrator verification are checked before physical replacement.

Queued tasks defer for a confirmed concurrency-slot refusal. A deleted task,
closed admission or unconfirmed outcome stops with its actual reason instead of
repeatedly reporting a busy slot. Scheduled task creation records its intent
before creation; a later attempt with an unconfirmed original creation reads that
state and stops instead of creating another task. Ordinary confirmed task failure
keeps the existing retry policy, and future schedule occurrences keep clean inputs.

### Local lesson maintenance when AI checks are held

Enabled stale-lesson retirement can run for the selected model even when the
AI testing prerequisites are incomplete. New lessons and trial acceptance,
failure and relapse decisions remain held. The result distinguishes held checks
from actual retirement; missing model selection does not retire every model.

Reviewed maintenance checks the current learning stop, sources, permissions and
planned guidance generation at physical writes. A failed write or missing
activity confirmation retains an incomplete outcome and any earlier saved
change. Reading the original task does not start another pass. The nightly
summary reports inspection-only when all model reports have held qualification.

Assessment lists, due items and details use current specialist or workflow names
from the authorized picker. A name unavailable in that view is identified as
unavailable; an optional recorded reference remains available for support.
Native record identity, version checks and review permissions are unchanged.

### Scoped trial decisions and protected assessment review

Recorded trial outcomes change only the exact model and scope that supplied
them. Identical lesson text in another department stays intact. Governed passes
check current sources, evidence, learning stops and budgets at the native write,
confirm each change before advancing, and retain failed or partial outcomes.
Unreadable transfer history refuses its rewrite. Result summaries distinguish
accepted, removed and returned-to-trial lessons. Legacy deliberate whole-model
rollback and transfer-attempt memory keep their existing meaning.

On Assessments, Copilot can open the selected specialist or workflow's complete
current findings and, for an administrator, its existing human review controls.
The protected handoff binds account, workspace, record version and content;
opening it records no new review decision. Auditors retain readable findings
without enabled administrator actions. A changed account clears private
assessment content and its owned evidence dialog. Current review permission is
checked after writer waits and again at physical replacement. A decision already
published before a later refusal remains explicitly unconfirmed until read back.

### Assessment actions and interrupted bulk refresh

Refresh, evidence changes and removal recheck the current actor and workspace
at native replacement, after waiting for another writer. A refused write leaves
the original unchanged; a refusal after a saved effect asks the person to check
the current record before retrying. Assessment reviews also require the named
decision scope when called with an access key.

Bulk refresh reports confirmed checks and unavailable or unconfirmed checks.
A changed account stops the operation and clears private screen content.
Interrupted responses offer a read-only current-state check. That check is not
the original operation's receipt and does not repeat a refresh, decision or
removal. Unsaved frequency and evidence drafts survive ordinary same-account
errors; losing access clears private findings and disables write controls.

### Model checks, spending and add-on readiness

Model checks belong to the current workspace and configured connection. Changing
the key or endpoint invalidates the old evidence. A failed refresh preserves
previous model choices and their last successful check, while showing that they
are unconfirmed. Settings updates that status without discarding unsaved choices;
changed lists offer an explicit reload. Overlapping checks cannot let an older
response replace a newer check, even after a connection changes away and back.

An expired OpenRouter zero-price listing is checked before a new request when
discovery is enabled. Waiters share one bounded check, and a recent failure has a
short retry pause. Only fresh evidence from the official listing with all
advertised prices at zero grants a zero-price quote. OpenRouter advertises
[request and other price fields](https://openrouter.ai/docs/api/api-reference/models/list-all-models-and-their-properties)
as well as input and output prices; an additional charge excludes that row.

Each actual SDK attempt retains its admitted price for response accounting.
Expiry or a changed connection after dispatch does not discard an already
returned answer. Retries, hedges and compatibility resends recheck the current
connection and price before their own sends. Async initial metadata checks run
off the event loop; accounting does not make model-list requests.

Python add-ons with a declared unsupported or unreadable contract are refused
before their entry point loads. Older supported contracts and add-ons without a
manifest retain their existing behavior. The add-on page shows the reason, and
Copilot offers a complete count summary plus a selected add-on's current
compatibility and practice-readiness details, including refused add-ons.

### Read connection status without enabling actions

Copilot connection diagnostics use a read-only control, so they remain available
when its write actions are disabled. The summary shows the saved credential's
presence, dated check, permitted related-work counts and coverage gaps, with a
link to Connections. An earlier credential revision or unconfirmed check time
is explicit. Current ownership and account context still apply. Reading this
summary contacts no service and does not prove current task access.

Recovery's source-checkpoint form keeps the chosen date and collection effect
visible when paging or another lookup fails. A new read clears confirmation;
manual changes are identified, and invalid manual fields reveal their remedy.
The ordinary form and its Copilot host retain the same exact checkpoint binding.
Choosing a collection checkpoint does not confirm an earlier message's delivery.

### Named access requests and interrupted decisions

Access requests offer named dashboard and tool actions, search and ordinary
paging instead of requiring an internal action name. The complete review shows
the selected action, current policies, responsible administrator and business
reason. Copilot uses the same choices and native review. Supported built-in
actions and authorized personally created actions are discoverable without
loading add-on code; the interface explains that add-on choices are unavailable
through this listing. A listed action is not evidence that its connection works.

A request or review whose reply was lost offers a read-only check of the exact
saved operation in Copilot. It rechecks the current account and workspace and
does not submit another request, decision or activity write. Incomplete history
or a pending activity receipt remains explicitly unconfirmed. Recording a review
does not grant access; only the actual current policy can confirm permission.

Privacy-notice release approval, approval withdrawal and update-proposal review
require current administrator authority. Access keys also need approval
permission in addition to administrator scope. Those decisions recheck the
account, workspace, session and current key permissions after a writer wait and
before the native transaction finishes. Independent reviewers, exact versions,
original operation keys and native activity records keep their existing meaning.
An unconfirmed decision asks the person to read the current notice before
deciding again; ordinary failure messages distinguish missing key permission
from author or approval-ownership restrictions.

Copilot's standard change review shows named business headings and complete
values. When both an existing and proposed value are supplied, their comparison
is explicit. Other review shapes keep all their details, and an incomplete
review still cannot be applied from the compact panel.
