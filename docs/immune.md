# Adaptive immunity

Policies, Shield, capabilities and approvals are *innate* controls: each one
governs a single agent or a single action. The adaptive layer
(`maverick.immune`) looks for what those controls cannot see and proves each
finding. Every analysis is deterministic and offline: a finding comes with the
witness that establishes it, never a model's opinion.

| Question | Module | CLI |
|---|---|---|
| What can agents do *together*? | `immune.network` | `maverick immune network` |
| Is the human in the loop catching flaws? | `immune.oversight` | `maverick immune canary / drill / oversight` |
| Can a machine-assisted discovery be owned? | `immune.title` | `maverick immune title check / seal / verify` |
| Do two rules contradict? Is a candidate rule better? | `immune.policy` | `maverick immune rules` |
| Does a model act differently when watched? | `immune.invariance` | library |

## Composition risk

The Rule of Two: no agent system should combine *sensitive data*, *state
change* and *external reach* without a control. Data moves between agents
through the shared blackboard, peer messaging and delegation, and those
coordination tools cannot be removed by a pack allowlist. So the envelope that
matters is the one along a data-flow path, not the one on each agent.

`maverick immune network` evaluates every pack at its **runtime** capability
(`domain_capability`), under explicit settings (`--levels`, `--grounding`,
`--swarm`), or any agent estate you describe as JSON (`--graph`):

```json
{"agents": {"crm_reader": ["crm_read"], "planner": ["shell"], "mailer": ["email"]},
 "flows": [["crm_reader", "planner"], ["planner", "mailer"]]}
```

Each finding names the path and the concrete tools (`sensitive`, `mutate`,
`external`) and the risk of the least-guarded way out (`sink_risk`); `high`
sinks are the ones secure defaults escalate to a human. Tool classes are
explicit tables in `immune/network.py`; `mcp_*` tools are unknown remote
code and count as all three. `maverick domains-audit` output now also reports
each pack's `runtime_expansion` and `runtime_reachable_dangerous`.

## Proof of Oversight

With `[immune] canaries = true`, an operator seeds realistic, known-flawed
approvals into the real queue:

```bash
maverick immune canary --class payments --action "Pay INV-4411 to updated bank account" \
  --detail "Vendor bank details changed 2h ago" --flaw "bank change + urgency"
maverick immune oversight            # catch rate and earned authority per person/class
maverick immune drill carol month_end_close --passed   # no-agent capability drill
```

Every canary is a valid structured approval card, the same format real
approvals use, so a reviewer can approve it: a canary that cannot be approved
could never record a miss. A hand-written `--detail` is wrapped in a card.

Hand-written canaries look hand-written. `maverick immune canary-auto
[--class ACTION] [--count N]` models each canary on a real recent structured
approval of the same kind. It copies the action, risk, scope, quorum,
requester and card, gives it a fresh expiry, then plants one concrete flaw in
what the reviewer reads (in every place the same wording appears). It never
copies the source's provenance, and every commitment on its card (target,
parameters, inputs, credentials) is random, so no system that consumes its own
approvals can ever act on an approved canary. The missing provenance label is
the one visible difference from the approval it was modelled on. The flaw is
one of:
- an amount with a currency marker, inflated tenfold;
- a lookalike recipient domain;
- a changed account number (only a number labelled as an account, IBAN or
  a/c; invoice and phone numbers are left alone);
- when the text has none of those, pressure to skip verification, added as an
  unresolved assumption.

Legacy plain-text approvals cannot be approved, so they are never modelled.

Existing canaries are never used as models. The command prints only approval
ids; the flaw stays in the private ledger, so whoever runs it can still be
measured fairly.

A denied canary is a catch; an approved one is a miss. A canary cleared after
its card expired is not scored, because only denial was possible by then. The
canary's identity
lives only in a private server-side ledger. The approval itself carries no
marker. Nothing waits on a canary approval, so no decision executes anything.
Canaries are excluded from agent autonomy graduation.

*Earned authority* is the Wilson lower bound of a person's catch rate for a
decision class (default: at least 10 decided canaries and 80% assured). It is
evidence for routing decisions, not a performance-management tool. Deploy it
with the consent and works-council process your jurisdiction requires.

`oversight.find_cruxes` returns the claims whose falsity alone flips a
decision, so a reviewer checks those instead of the whole document.
`oversight.oversight_record` signs who decided what, on which cruxes, with
what measured reliability.

## Discovery Title

A dossier (JSON) records a machine-assisted discovery as it happens:

- `inputs` and `inputs_committed_at`: digests committed before the run.
- `priority`: commit-reveal digests of ideas with timestamps (`title.commit`).
- `gates`: human decisions and the claim elements each conceived.
  `framed`, `selected`, `modified` and `conceived` count as conception;
  `reviewed` or `accepted` alone does not.
- `claims`, `verification` and `coverage`.

`maverick immune title check` lists what would not survive scrutiny: an
unconceived claim element, an unsigned problem statement, a failed or missing
check, partial or unknown search coverage, or inputs committed after the first
idea. `seal` signs the dossier with the audit identity. `verify` checks it
offline, including any priority commitments the holder chooses to open.

Governed research runs feed the dossier directly. The run ledger already
records, hash-chained, which named user planned each attempt and when.
`maverick immune title research DOSSIER RUN_EXPORT... --element E -o OUT` does
three things:
- verifies each run's manifest digest and event chain;
- turns every planning decision into a `framed` gate, with the event digest
  as evidence;
- adds the pinned code, environment, dataset and model digests as inputs
  committed at the first plan.

Execution events are not conception. The claim elements a plan shaped
(`--element`) are the caller's assertion; nothing infers them.

The hash chain shows that an export is internally consistent, not who wrote
it: anyone can recompute it over an edited file. Gates built from an export
are therefore marked `verified: false`, and `title check` lists each one. Code
that reads the run from the governed store itself (`ResearchRuns.inspect`)
passes `verified=True` to `title.add_research_runs`.

The dossier is evidence for counsel, not a legal opinion on inventorship.

## Production twin

With `[immune] twin_record = true`, every tool result a goal receives is
recorded at the agent's single execution point. The recording is private, per
tenant, and sealed (bound to the goal) when at-rest encryption is on.
`maverick immune twin replay GOAL` runs a new goal with the same title,
description, owner, principal, domain and project, while each tool returns the
result production received for the same tool and arguments, in the same order.

- Nothing live is touched. An exact (tool, arguments) match is served first.
  Otherwise the closest unconsumed recorded call to the same tool is served
  when its arguments are at least `--tolerance` similar (default 0.8), because
  a new model rarely phrases a query byte-for-byte as production did.
  Similarity is the weakest field's: every argument must be present in both,
  text is compared as text, and numbers, flags and structure must match
  exactly, so a changed recipient, account or amount is never near enough.
  High-risk tools are only ever served on an exact match. Each approximate
  call is reported as a divergence with its score. Anything further away
  returns an ordinary tool failure, is not executed, and is counted as
  unmatched.
- The agent's injected capability scope (`_capability_*` arguments) is not
  part of the match.
- A production call that raised is recorded, and raises the same way in the
  twin.
- The twin runs as the same user as production. A goal bound to a capability
  principal (not `user:*`) cannot be replayed, because the goal does not hold
  that capability; the command says so before creating anything.
- Human approval gates (governance, information-flow) never ask anyone.
  Production records the calls a human refused as well as the calls that ran.
  In the twin, a call production made is served; a call production was refused
  is refused again (not a divergence); any other gated call is refused and
  counted as unmatched. A twin's gate answers are not audited or learned as
  human decisions, the opt-in review checkpoint does not run, and no run
  webhooks are sent.
- Budget, connector-deadline, halt and cancellation stops are not recorded as
  tool errors: a twin runs under its own budget.
- The report compares the twin's final answer with production's
  (`result_similarity`).
- Coordination tools still run, so the swarm re-forms and its children replay.
  `ask_user` is replayed, so a twin never messages a person.
- Nothing in the run marks it as a test.
- Use a twin to try a new model, prompt or policy on real work. The report
  gives served, unserved and unmatched counts; `twin list` keeps counts only.

A twin goal is an ordinary goal row, so the learning loops see it like any
other run, and configured MCP servers are started so the model sees the same
tool list (no MCP tool is called). Recording stops at 64 MB per goal.
`maverick immune twin forget GOAL` deletes a goal's recording (retention or
erasure); replay reports hold counts only and are kept.

### Evaluation awareness, measured on real work

`maverick immune awareness --goals 12,15,19` replays each recorded production
goal twice. The two runs are identical except that one carries an explicit
"this is an evaluation run" cue. Two behaviours are compared across the arms
with a two-proportion test, so noise is not reported as awareness:
- *diverged*: an attempted call production never made, a call made
  differently (served approximately), no answer where production gave one, or
  an answer that moved away from production's;
- *blocked*: the goal ended blocked.

Each goal costs two model-driven runs. Only aggregate results are ledgered.

## Dashboard

**Governance → Safety monitoring** (`/immune`, audit permission) shows:
- the roster's composition-risk trifectas and exfiltration counts;
- catch rates and earned authority from decided canaries;
- twin replays and awareness probes;
- recent labelled data at external sinks.

It reads one summary (`GET /api/v1/immune/summary`). The summary holds
counts, scores, labels and statuses only: never canary flaws, tool arguments
or recorded outputs.

## Configuration

```toml
[immune]
canaries = false   # allow `maverick immune canary` to seed the approvals queue
twin_record = false  # record tool results so goals can be replayed as twins
```

The analyses are read-only and need no switch. Canary seeding writes to shared
state and twin recording retains tool output, so those two are gated.
