# Learn action dataflow from reviewed executions

Lightwork can infer how arguments in a repeated action sequence come from its
business input, earlier action results, or constant values. For example, reviewed
customer lookup, order creation and work-item creation executions can teach it
to pass the **new order ID returned at runtime** into the work-item action.
Examples supply observed arguments/results, not a prewritten variable mapping.
An explicit transformed-recipe mode also learns bounded arithmetic, text and
conditional expressions for arguments from those same sources. A separate
binary-choice mode learns which of two demonstrated terminal tools follows one
shared action, including the argument relationships for all three tools.
A verified workflow mode learns the next tool and completion from bounded
observed histories, allowing different action counts and repeated tools.

The default and transformed modes learn a demonstrated straight-line sequence:
two to 32 reviewed episodes and two to eight steps with identical tool order and
typed shapes. Choice learning has the narrower two-action topology described
below. These fixed-topology modes do not invent arbitrary tool order, learn loops or establish
that a demonstrated business decision was correct. Objects retain exact keys;
arrays retain exact lengths. Strings, integers, finite numbers, Booleans and null
remain distinct types.

## What the learner preserves

The default v1 grammar gives every scalar argument all matching input paths,
earlier-result paths and constants. A constant is admitted only when that exact typed value is the
same across all episodes. The engine does not choose a convenient explanation
when several match. If training order IDs happened to equal an unrelated input
field, both bindings remain until reviewed evidence separates them.

At runtime, all retained bindings for each argument must resolve to the same
typed value. Missing data, changed result shape or argument disagreement stops execution.
After an action has run, a stop preserves completed work and quarantines the
sequence rather than falling back to an agent or restarting its prefix. Existing
durable run IDs prevent same-run redelivery from dispatching the prefix again.
This is not an exactly-once guarantee against arbitrary external systems or a
general automatic crash-recovery/reconciliation mechanism.

Artifacts retain raw examples, exact shapes, every binding alternative and
digests. Validation rebuilds the derivation: removing an alternative and
recomputing a checksum is insufficient. This detects an inconsistent artifact;
it does not authenticate the supplied examples or make human review infallible.
The `candidate_binding_count` is the sum of per-leaf alternatives (syntax trees
for transformed expressions, source bindings for copy-only leaves), not the
number of complete workflows, a confidence percentage, or a probability.

## Learn transformed arguments

`flow recipe learn --transforms` creates a `lightwork.action-recipe.v2` artifact.
Supply reviewed episodes, exact admitted tools and a complete bounded domain.
The learner generates source paths from **all** eligible original input and
earlier-result leaves. It does not accept a supplied formula or a mapping from
variables to argument fields. For example, an invoice amount may be explained
by `quantity * unit_price - discount`, by a prior quoted amount, or by several
other expressions. Every expression matching the demonstrations remains. A
later disagreement stops the next action even when one explanation looks likely.

The domain file has exactly `inputs` and `steps`. `inputs` is a closed object
schema; each step has an `arguments` object schema and a `result` schema in the
demonstrated tool order. The schemas cover **every field**, including unused
fields. Bounds are supplied explicitly; the learner does not infer a business
domain from the smallest and largest training values. Here is a complete domain
for a two-step price lookup and invoice creation sequence:

```json
{
  "inputs": {
    "type": "object", "additionalProperties": false,
    "required": ["quantity", "discount"],
    "properties": {
      "quantity": {"type": "integer", "minimum": 1, "maximum": 5},
      "discount": {"type": "integer", "minimum": 0, "maximum": 5}
    }
  },
  "steps": [
    {
      "arguments": {
        "type": "object", "additionalProperties": false, "required": ["quantity"],
        "properties": {"quantity": {"type": "integer", "minimum": 1, "maximum": 5}}
      },
      "result": {
        "type": "object", "additionalProperties": false, "required": ["unit_price"],
        "properties": {"unit_price": {"type": "integer", "minimum": 1, "maximum": 5}}
      }
    },
    {
      "arguments": {
        "type": "object", "additionalProperties": false, "required": ["amount"],
        "properties": {"amount": {"type": "integer", "minimum": -5, "maximum": 25}}
      },
      "result": {
        "type": "object", "additionalProperties": false, "required": ["invoice_id"],
        "properties": {"invoice_id": {"type": "string", "maxLength": 64}}
      }
    }
  ]
}
```

Use this domain only with episodes describing that exact sequence and data
shape. Tool names in these examples illustrate local contracts and must match
your approved registry names.

```console
maverick flow recipe learn --transforms --domain invoice-domain.json --episodes reviewed-invoices.json --allow-tool price_lookup --allow-tool invoice_create --reviewed --output transformed-recipe.json
maverick flow recipe refine --artifact transformed-recipe.json --episodes additional-reviewed-invoices.json --reviewed --output refined-transforms.json
maverick flow recipe draft --artifact refined-transforms.json --flow-id reviewed-invoices --name "Reviewed invoices" --output invoice-flow.json
```

Optional `--max-operations` accepts 1–4, default 2. `--operators` supplies unique
comma-separated names from `strip,lower,upper,not,add,sub,mul,min,max,eq,lt,le,if`;
omitting it includes all supported operations. `--constants constants.json`
supplies a JSON array of explicit integer/string/Boolean grammar constants.
These options require `--transforms` or `--choices`; they are not silently ignored by v1.
The grammar is part of the retained artifact. Refinement keeps the domain and
grammar fixed; changing either requires a new synthesis and draft review.

The transformed grammar retains complete directed typed expression trees,
including zero-operation copies and literals, multiple trees with the same
behavior and inactive conditional branches. It does not retain only a preferred
or shortest expression. Its initial literal pool also includes a per-leaf
constant when that exact typed argument is constant across the initial seed
episodes. Refinement retains those seed episode IDs and literal pools: later
labels filter the same complete grammar, even when a label stops being constant.
It does not introduce new target literals. Float/null copy-only constants remain
candidates only while they match every accumulated demonstration. Runtime agreement is
within this declared grammar and domain, not proof of the intended business rule.

The first version has these limits:

- At most **six integer/string/Boolean source leaves at each step**, counting
  all inputs and all earlier results. A seventh eligible source refuses synthesis;
  the learner does not select a convenient subset. At most **eight argument
  leaves across the whole recipe**. Existing episode, sequence and exact-shape
  limits still apply.
- Objects require all declared properties and `additionalProperties: false`.
  Arrays have equal `minItems` and `maxItems`, at most 64. Strings require
  `maxLength` from 1 to 1,024; optional `minLength` is supported. Integer/number
  schemas require finite minimum/maximum bounds; Boolean/null schemas use their
  type only. Each schema has depth at most eight and at most 512 schema nodes, with
  64 properties per object. No references, patterns, combinators or extra keywords.
- Eligible integer source bounds and explicit integer literals fit
  `[-10^12, 10^12]`; intermediate integer values and general numeric schema
  bounds fit `[-10^24, 10^24]`. Bounds are never silently widened or clamped.
  Float and null arguments use exact-copy/constant bindings only; there is no
  floating-point arithmetic, numeric coercion, division or automatic rounding.
  Use integer minor units when that matches the reviewed business contract.
- At most eight literals per leaf after adding any constant demonstrated seed target.
  At least two distinct projected source records are needed for composed learning.
  Repeated observations do not supply invented variation.
- Each composed search has caps of 250,000 productions, 40,000 states and four
  million training evaluations. Complete runtime partitions are bounded by
  100,000 evaluations and 4,096 distinct values per composed state. The recipe
  also bounds total per-step evaluation work. The **whole artifact** remains
  limited to 262,144 bytes. Reaching a limit never authorizes partial agreement
  or silently falls back to the copy-only grammar.

Execution requires both strict Boolean options, each defaulting to false:

```toml
[flows]
enable = true
action_recipes = true
action_recipe_transforms = true
```

Both installer flow setup paths expose the transformed-argument option and
describe its dependency on action recipes, explicit bounds and agreement.
Enabling it does not enable episode capture or authorize a tool. The same
native approvals, budget, tool authorization and digest-only audit receipts
apply. A transform outside its domain, disagreement or resource limit stops
the sequence; completed actions remain preserved. Refining an artifact does
not authorize replay of a previously indeterminate run.

## Learn a binary action choice

`flow recipe learn --choices --domain ...` creates a
`lightwork.action-choice.v1` artifact. It requires four to 32 reviewed episodes,
each with exactly two actions: the same first tool, followed by one of exactly
two observed terminal tools. Each continuation needs at least two demonstrations
with distinct observable fork inputs. The learner receives executed tool names,
arguments and results; callers do not supply a guard, variable mapping or branch
label. The observed terminal tool supplies the training outcome.

The complete domain has exactly `inputs`, `prefix` and `branches`. `inputs` is a
closed object schema. `prefix` has `arguments` and `result` schemas for the first
tool. `branches` maps each of the two exact terminal tool names to its own
`arguments` and `result` schemas. Use the bounded schema rules above for every
field; the two terminal tools may have different argument/result shapes. The
domain declares the available data and bounds, not the decision rule.

```console
maverick flow recipe learn --choices --domain choice-domain.json --episodes reviewed-choices.json --allow-tool case_open --allow-tool case_approve --allow-tool case_queue_review --reviewed --output choice-recipe.json
maverick flow recipe refine --artifact choice-recipe.json --episodes additional-reviewed-choices.json --reviewed --output refined-choice.json
maverick flow recipe draft --artifact refined-choice.json --flow-id reviewed-case-routing --name "Reviewed case routing" --output choice-flow.json
```

`--choices` and `--transforms` are mutually exclusive learning modes. Choice
learning includes transformed arguments and accepts the same operation/literal
options: one to four operations per expression, default two, with the original
seed literal pool retained during refinement. All consistent Boolean guard
trees remain, alongside all consistent argument expressions. An unrelated
legacy flag that happened to agree with the demonstrated decisions remains a
candidate until additional reviewed executions distinguish it. The engine does
not select the most plausible rule. `guard_candidate_count` counts guard syntax
trees separately from the summed argument `candidate_binding_count`; neither is
a probability or a count of complete workflows.

All eligible integer/string/Boolean leaves from the original input and available
prefix result form the source catalog, with at most six sources. Across the
prefix and both terminal tools there are at most eight argument leaves, plus
one Boolean guard. Float/null argument leaves remain copy-only. The transformed
expression, explicit domain and 262,144-byte artifact limits still apply. Guard
plus selected argument evaluation is capped at 100,000 evaluations. Exhausting
a limit never permits partial agreement.

In the default execution mode, after the shared action completes, every retained guard must agree on the
continuation. Every retained argument expression must then agree on its exact
typed arguments before that terminal action is proposed for approval. A later
disagreement stops and preserves the completed prefix; it does not dispatch
either terminal action, fall back to an agent or repeat the shared action.
Each successful execution performs two actions. Its exported graph contains one
shared action and two alternative terminal actions, each with an approval gate.
Refinement preserves this topology and the admitted domain/grammar. New tools,
nested choices, joins, loops and learned stopping rules require another feature;
they are not inferred here.

Execution requires all three independent strict Boolean opt-ins:

```toml
[flows]
enable = true
action_recipes = true
action_recipe_transforms = true
action_recipe_choices = true
```

Both installer paths expose the default-off choice option without enabling its
dependencies automatically. Native authority, budgets, approvals and required
audit receipts still apply. Training may combine separately executed ordinary
straight-line teacher flows for the two outcomes. This does not extend episode
capture to arbitrary branch-containing source flows. The separate teaching mode
below admits one exact reviewed-choice topology.

## Teach a continuation on a real completed prefix

An explicitly marked choice Flow can ask an authenticated human to resolve a
genuine guard disagreement on a case whose shared action has already completed.
It uses the actual input and actual native result, including the newly returned
ID. It does not invent a possible result or turn a hypothetical Boolean answer
into an execution example.

Create a teaching inspection draft with the optional `--teach-choices` flag:

```console
maverick flow recipe draft --artifact choice-recipe.json --flow-id choice-inspection --name "Choice teaching inspection" --teach-choices --output inspection.json
maverick flow recipe draft-verified --package choice-lineage.json --trust trust.json --tenant exact-tenant --flow-id choice-inspection --name "Choice teaching inspection" --teach-choices --output verified-inspection.json
```

Both commands produce an **unadmitted inspection draft**. The exact
`recipe_teaching: {"schema": "lightwork.action-choice-teaching.v1"}` marker is
preserved in Flow serialization and the designer, but grants no native authority.
Raw artifacts cannot enroll themselves as trusted evidence. To obtain a
governed draft, admit the complete signed package and send
`{"flow_id": "choice-teaching", "name": "Choice teaching", "teaching": true}`
to `POST /api/v1/flows/recipe-lineage/{admission_id}/draft`. `teaching` defaults
to false and accepts only a JSON Boolean. The service freshly checks the source
evidence and destination ownership and returns an unsaved draft with its exact
governed reference. Teaching is supported only for choice artifacts.

Native teaching requires a valid governed reference even when the general
`require_action_recipe_lineage` policy is false. It also requires these separate
strict Boolean opt-ins, with teaching defaulting to false:

```toml
[flows]
enable = true
action_recipes = true
action_recipe_transforms = true
action_recipe_choices = true
action_recipe_lineage = true
action_recipe_teaching = true
```

Both installer paths expose teaching without enabling its dependencies. Existing
tool permission, budget, current evidence eligibility and durable audit receipts
remain required.

The teaching pause is available only when the guard has a complete conflicting
partition and **both continuations' argument alternatives agree**. An invalid
result, argument ambiguity, out-of-domain value or resource exhaustion does not
become a human route question. The question lists each exact admitted tool and
its proposed typed arguments at `_recipe_teaching_question.options`. Its
`route:0` / `route:1` decisions identify those displayed alternatives; route
numbers alone do not imply approval, rejection or business meaning.

The authenticated run-detail API and approval screen expose the exact validated
tool/argument alternatives for review; an opaque route label is not the review
content. Capture validates and retains every offered option within the enrolled
schemas and retention bounds, including the unselected continuation's arguments.

The `teaching_review` approval records the human choice. A separate ordinary
approval then presents the selected terminal action before native dispatch.
These are separate decisions: choosing which action fits the business case is
not permission to execute it. The question and selection are bound to the
retained artifact, actual prefix and run; changing them cannot authorize another
continuation. A normal unanimous guard bypasses the teaching question and keeps
the ordinary terminal approval. A teaching answer does not edit the current
artifact or silently publish an improved rule.

Teaching never reruns the prefix to obtain a different example and does not
revive earlier indeterminate runs. Lost completion evidence and interrupted
effects remain quarantined. There is no automatic rollback or general
exactly-once guarantee for external connectors.

To retain the result as learning evidence, also enable `action_episode_capture`
and enroll the teaching run at its initial approval, before the prefix. Declare
the full bounded input schema and argument/result schemas for all three tools.
The authenticated enrollment preparation response lists every possible tool but
reports `planned_steps: 2`: the prefix and one selected terminal action. Its
retention disclosure states that a human continuation choice is required and an
agreement-only run is not new teaching evidence. Later pauses cannot enroll.
The new teaching capture family binds the actual prefix, authenticated route
choice and selected native terminal invocation. Only a completed run with a
genuine human-selected ambiguous continuation can become teaching evidence.
An agreement-only teaching run executes normally, but its capture is marked
unusable for teaching; the platform does not treat its own prediction as an
independent label.

After completion, use the existing authenticated episode review, copied-data
grant and signed export. The human route choice does not replace that separate
suitability review or grant. Supply the complete signed native bundle to
`refine-verified`, then review and admit the new package before using its draft.
Refinement retains earlier evidence and every still-consistent explanation.
Service signatures attest the recorded execution/review, not the correctness of
the human business choice. Existing expiry, withdrawal and copied-data retention
limits continue to apply.

Portable bundle verification checks the signed evidence and its bounded
commitments. It does not reconstruct the complete historical paused operation
or recursively reauthorize every parent evidence source against current live
state. Live governed admission and per-action eligibility checks remain separate.

## Learn bounded workflow structure from signed histories

`learn-workflow-verified` imports complete signed, reviewed native executions and
learns both what action follows an observed history and when the demonstrated
workflow ends. Its artifact schema is `lightwork.workflow-transducer.v1`.
Demonstrations may have different action counts and may repeat a tool. Callers
supply tool/data domains, not a next-action graph or argument mapping.

```console
maverick flow recipe learn-workflow-verified --bundles signed-bundles.json --trust trust.json --tenant exact-tenant --allow-tool lookup_customer --allow-tool create_order --domain workflow-domain.json --max-operations 1 --max-steps 8 --output workflow-package.json
maverick flow recipe draft-verified --package workflow-package.json --trust trust.json --tenant exact-tenant --flow-id workflow-inspection --name "Workflow inspection" --output workflow-inspection.json
```

The domain has exactly `inputs` and `tools`. `inputs` is a closed bounded object
schema; `tools` maps each allowed tool name to its closed bounded `arguments` and
`result` object schemas. Existing schema restrictions apply. The CLI requires an
independently provisioned trust file and exact tenant, verifies the signed
evidence, and produces an **unadmitted** package. Offline verification does not
check current source withdrawal or ownership. Existing `refine-verified` retains
earlier signed evidence; `draft-verified` remains unsaved inspection. Neither
`--teach-choices` nor the governed draft API's `teaching: true` is supported for
workflow artifacts.

The authenticated HTTP path is
`POST /api/v1/flows/recipe-lineage/learn-workflow-verified`. It **learns and admits**,
returning admission metadata. Its strict JSON body contains `bundles`,
`allowed_tools`, `domain`, and optional `max_operations` (default 1), `max_steps`
(default 8), `operators` and `constants`. Tenant, owner and trust are derived from
current authenticated authority; the request cannot supply them. The endpoint
caps the complete request at 2 MiB, checks current source eligibility before
synthesis, and repeats the normal admission checks before exposing a usable
reference. Pending required audit delivery returns only safe pending metadata.
Use the existing authorized detail and draft routes afterward. Admission does
not save, publish or execute a workflow.

Native execution and HTTP learning require all four strict Boolean opt-ins:

```toml
[flows]
enable = true
action_recipes = true
action_recipe_transforms = true
action_recipe_lineage = true
action_workflow_learning = true
```

`action_workflow_learning` defaults to false and appears in both installer flow
paths without automatically enabling dependencies. Native workflows always
require a valid governed lineage reference. Normal approvals, tool authority,
budgets and current evidence checks remain required; ambiguity stops further
work and does not replay a completed prefix.

Both workflow schemas require **signed execution receipts with strict
persistence**, independently of the signatures on their training bundles.
Provision the existing audit signer and its cryptographic dependency, usable
keys and writable tenant audit storage before running them. The deployment's
resolved audit policy must enable signing (for example, `[audit] sign = true`,
without an environment override disabling it). These workflow options do not
enable global audit signing or install dependencies.

The runtime refuses a next action or completion when its required signed
receipt cannot be persisted; an unsigned fallback is not accepted. If a receipt
fails after an effect has already occurred, the run becomes indeterminate and
is quarantined from automatic continuation or replay. Preserve the completed
prefix and reconcile the effect; rerunning it is not receipt recovery. Verifying
signed source bundles alone does not establish that this execution-receipt path
is available. This requirement is specific to the learned workflow execution
path and does not assert that every product audit event is signed or that local
storage is immutable.

The state representation is explicit: **last tool plus the set of tools with
observed results**, with all original input leaves and each tool's **latest**
result leaves available to expressions. Earlier occurrences and occurrence
counters are not part of this grammar. It learns within observed state classes;
it does not infer arbitrary automata, hidden policies or an optimal strategy for
obtaining evidence. Histories that need an unrepresented distinction can conflict
or remain ambiguous. A learned completion label means agreement with reviewed
demonstrations, not an independent proof of the intended business outcome.

Limits are two to 32 complete episodes, one to eight allowed tools, at most 32
observed states, one to eight executed actions, at most 12 source leaves per
state, eight argument leaves per tool, and one or two operations per expression.
Existing signed native training bundles contain two to eight actions each;
the pure grammar's one-action bound does not relax that provenance requirement.
No source fields are silently dropped to fit a limit. Scalar expression constants
must be explicit; next-action expressions additionally receive fixed tool labels
and the completion label. Float/null arguments use typed copies only. Search and
evaluation limits refuse rather than choosing a partial candidate set. Candidate
counts describe expression alternatives, not probabilities or complete workflows.

No other capture family is supported. Independently reviewed complete
straight-line native teacher executions may demonstrate different histories;
arbitrary branching/loop capture and self-labeling from a learner's own predictions
remain unavailable. Signed provenance, retention, grants and expiry have the same
limits described below.

## Learn a bounded integer history accumulator

`learn-memory-verified` adds a separate artifact schema,
`lightwork.workflow-memory.v1`. It learns an integer summary of earlier results
alongside next-action, completion and argument expressions. For example,
histories with the same latest receipt quantity can require different next
actions when their accumulated quantities differ. The learner receives complete
reviewed histories, not a supplied accumulation formula or stopping condition.

```console
maverick flow recipe learn-memory-verified --bundles signed-receipts.json --trust trust.json --tenant exact-tenant --allow-tool receive_quantity --domain receipt-domain.json --max-operations 2 --operators if,le,lt --constants constants.json --max-steps 8 --output memory-package.json
```

This uses the same `inputs`/`tools` domain and independently provisioned trust
policy as workflow learning. Existing `refine-verified` and `draft-verified`
dispatch on the package schema. CLI output remains unadmitted; local files do
not establish current source eligibility or authorize execution.

The authenticated route is
`POST /api/v1/flows/recipe-lineage/learn-memory-verified`. Its strict body has the
same fields and 2 MiB request limit as `learn-workflow-verified`. It checks current
authenticated authority and every source before learning, rechecks the feature
gates afterward, and performs governed admission before returning metadata.
Pending audit delivery withholds usable content. Existing detail/draft routes
remain separate, and no flow is automatically saved, published or executed.

In addition to all workflow-learning dependencies above, enable this separate
strict Boolean option:

```toml
[flows]
action_workflow_memory_learning = true
```

It defaults to false in configuration and both installer paths. Selecting it
does not silently enable dependencies. Native execution still requires a current
governed lineage reference and ordinary approvals, tool authority and budgets.
The same mandatory strict signed execution receipts and failure handling
described above apply; enabling memory learning does not configure the signer.

The complete declared model family contains the original model without memory
and models with **one integer cell**. A cell starts at zero or one integer input
leaf. It either stays unchanged, or updates on one selected tool's integer result
leaf using replace, addition, subtraction, minimum or maximum. Each candidate
uses **one fixed initializer and update program across the entire history**;
it cannot switch programs between steps. Every consistent model retains its own
decision and argument alternatives. Execution requires agreement across them
all; it does not mix one model's cell with another model's decision rule. The
cell is reconstructed from actual retained history, not a caller checkpoint.

Native memory decisions bind the complete retained summary set and its model
count. After a successful action, the required signed
`lightwork.workflow-memory-completion.v1` receipt retains the selected pre-call
`history_sha256` and adds `result_sha256` and `completed_history_sha256` for the
history including that result, before the runtime appends it. These are local
execution commitments, not independent witnessing of business correctness.

This is bounded integer summary inference. It does not infer arbitrary latent
state, multiple cells, sets, unrestricted loops or a correct business objective.
Complete native teacher histories and their authenticated review, copied-data
grant and signed export remain required. A learned completion label records
agreement with those examples, not independent proof of an external outcome.

The family may enumerate at most 256 summary models. The existing bounds of
two to 32 episodes, eight tools/actions, 32 observed states, eight argument leaves
and one or two expression operations remain. A state can use up to 12 ordinary
source leaves plus its integer cell. Cell values must stay between
`-10**24` and `10**24`; overflow in any retained interpretation refuses the
decision. The pure artifact limit is 1 MiB. Native Flow definitions retain their
separate 1,000,000-byte limit, including the artifact and generated graph, plus
the existing structural accounting and secret checks. A valid pure artifact may
therefore be too large to draft; drafting refuses before writing it. Verified
memory inspection drafts use that native bound instead of the legacy 262,144-byte
recipe-file writer. Whole-family search shares limits of one
million productions, 16 million training evaluations and 160,000 packed states;
history validation and resolution share a one-million-evaluation budget, with
the existing child-expression limits also applying. Resource exhaustion refuses
the complete search or decision instead of dropping a costly alternative.
Source episode and supplied history snapshots keep their existing 262,144-byte
bound; the larger artifact allowance does not expand captured data limits.
Model and expression counts are not confidence percentages or counts of
independent complete policies.

## Native execution and controls

Enable the separate strict Boolean option after reviewing the feature:

```toml
[flows]
enable = true
action_recipes = true
```

The installer exposes this default-off choice in both flow configuration paths.
The exported Flow contains an approval before every action. Its exact generated
graph and evidence remain bound together; changing routing, tool, retries,
parameters or step indexes makes validation fail. Labels/layout can change.
The designer preserves the artifact and step indexes when loading and saving.

Supply run data as `{"input": {...}}`. Before each approval,
`_recipe_next_arguments` contains the exact proposed typed arguments. At dispatch
the runtime resolves them again and requires a durable digest-only selection
receipt. Calls continue through the existing native action authorization and
ToolRegistry path, including current tool classification and connector authority.
Learning a binding grants no new permission. Direct library executor injection
remains a trusted testing/integration seam, not production authorization evidence.

Native JSON response strings are strictly decoded once, including duplicate-key
and nonfinite-number rejection. Every result, including the final result, must
match its learned typed shape. Parsed results live at `_recipe_step_0`,
`_recipe_step_1`, etc.; the final result is the last step's value. No parameter
is rendered as a template, so data resembling `{{secret(...)}}` stays data.
The recipe runtime makes no model call and never runs generated Python.

Training, capture and runtime also share an explicit completeness rule: the
reserved Boolean markers `pending: true`, `truncated: true`, `complete: false`
and `dry_run: true` make a result unusable, including when nested or returned
by the final action. A response with the expected shape is insufficient when it
declares itself incomplete. Arbitrary business fields such as `accepted: false`
or a string `status` are not interpreted as universal failure indicators; the
connector must expose its business failures through the native result protocol.

## Local authoring

An episode has the following shape (provide at least two with varied values):

```json
{
  "id": "reviewed-run-1",
  "inputs": {"email": "customer@example.test", "quantity": 12},
  "steps": [
    {"tool": "customer_lookup", "arguments": {"email": "customer@example.test"},
     "result": {"customer_id": "customer-17"}},
    {"tool": "order_create", "arguments": {"customer_id": "customer-17", "quantity": 12},
     "result": {"order_id": "order-91"}}
  ]
}
```

The tool names above illustrate a contract; they are not a declaration that
those connectors are installed. Supply exact approved names from your registry.
Episodes contain typed JSON results, after decoding raw connector JSON once.

```console
maverick flow recipe learn --episodes reviewed-episodes.json --allow-tool customer_lookup --allow-tool order_create --reviewed --output recipe.json
maverick flow recipe refine --artifact recipe.json --episodes additional-reviewed-episodes.json --reviewed --output recipe-v2.json
maverick flow recipe draft --artifact recipe-v2.json --flow-id reviewed-order-work --name "Reviewed order work" --output order-flow.json
```

These commands only create new local files and refuse to overwrite existing
files. The review flag is an explicit caller assertion, not authenticated human
signoff. Unknown tools can be represented in an unsaved draft but remain blocked
from saving/running until the normal operator classification is supplied. Unsafe
direct tools remain blocked. Review, save and publish through existing controls.
The raw `learn`/`refine` commands consume episodes. They do not verify a supplied
capture bundle's review/provenance or retain that complete lineage inside a
v1, v2 or choice artifact.
Preserve the full exported bundle separately; an authenticated export obtained
from the API does not make arbitrary later JSON imports independently authentic.

## Explicit local episode capture

The Python API accepts an explicit `ActionEpisodeCapture` collector through
`execute(..., episode_capture=collector)`. This collector is in memory and
default off; durable enrollment is a separate path described below.
The caller supplies an exact tool allowlist and the complete selected business
input object. Only `default_action_runner` can supply native observations after
authorization, registry execution and successful terminal audit. An injected
runner's apparently successful return is not accepted as native evidence.

Capture binds the saved source definition, owner, run, node and native call IDs.
This in-memory collector admits a saved straight-line action/approval flow and rejects resumes, retries,
nested/agent nodes, dry runs, secret expressions, credential-bearing fields,
redacted/incomplete values and unsupported or truncated results. Any capture
failure disqualifies the episode without changing the executed action's outcome
or causing a retry. A completed run alone does not constitute reviewed evidence.

After completion, `collector.export(reviewed=True, rationale="...")` returns
the learner-compatible `episode` plus separate `provenance` and local `review`
records. Retain the full bundle when supplying its episode for learning; the
pure learner does not authenticate a provenance document. This boundary assumes
a trusted local Python process, not an adversary able to replace its code.

## Retained examples across approvals

The authenticated episode-capture API retains selected native executions across
normal approval pauses. It requires a separate strict Boolean opt-in:

```toml
[flows]
enable = true
action_episode_capture = true
```

This setting permits capture enrollment. It does not enable generated recipe
execution (`action_recipes`), enroll existing runs automatically, or authorize
business actions. The installer describes encrypted retention, an expiry and
separate human review in both flow setup paths.

The API base is `/api/v1/flows/{flow_id}/runs/{run_id}/episode-capture`:

| Method and suffix | Purpose |
| --- | --- |
| `GET /enrollment` | Check the initial pause and obtain its exact `expected_pause_binding`, tool names and retention disclosure. |
| `POST` base | Enroll using that binding, `allowed_tools`, `input_schema`, `tool_data_schemas` and `retain_until`. |
| `GET` base | Read metadata status, revision and completed/planned step counts. |
| `GET /detail` | Read admitted evidence for review; requires fresh resource authorization. |
| `POST /review` | Submit `reviewed: true`, a strict `accepted` Boolean, `expected_revision`, `expected_episode_sha256` and a nonempty `rationale`. |
| `GET /export` | Export only accepted, unexpired evidence whose required audit receipts were delivered. |

Use the enrollment digest from `GET /enrollment`; the ordinary execution
approval digest includes different authority fields. A `503 audit_pending`
response can describe an already committed change. Refresh the status or retry
the identical request; do not rerun the business workflow to recover its receipt.
The routes use existing authenticated dashboard access. The run page now has
ordinary controls for enrollment at the first approval, review of the actual
captured work and a separate bounded training grant. It cannot reconstruct a
run that passed its first approval before enrollment.

Enroll an owned saved run at its **initial approval, before any action**. Declare
the exact tool allowlist, full input schema, full argument/result schemas for
each tool, and a UTC epoch retention deadline no more than seven days ahead.
Schemas accept only a bounded subset: closed objects with all properties
required, strings with maximum lengths, finite numbers with minimum/maximum
bounds, Boolean/null values, and arrays of fixed length. References, patterns,
combinators and extra schema keywords are not supported. Extra result fields
make the example unusable instead of being silently discarded.

Normal approval/resume remains responsible for permission to execute. Capture
reopens its tenant-owned evidence record from the authoritative saved run ID,
records each native call before dispatch, and retains its complete result only
after the native terminal audit succeeds. A failed or interrupted capture never
repeats the business action to obtain a cleaner example. Missing completion
evidence cannot be reconstructed from a successful run status or audit preview.

Business inputs, arguments, results and review rationale are explicitly sealed
before entering the governed record store, including its first local write.
The sealed envelope binds the tenant, run, record and payload revision. This
retention path requires encryption; enabling the feature is not permission for
plaintext fallback. Record metadata and audit commitments remain separate from
the encrypted business payload.

The deadline blocks further capture and evidence export. Expiration is processed
on authorized service access: after pending audit delivery clears, it removes
the active record's sensitive envelope and retains a metadata tombstone. There
is no background purge worker in this version. Inaccessible source generations,
backups and previously exported copies need separate retention handling; do not
interpret the deadline as a guarantee that every stored copy is erased at that
instant. The 1,000-record capacity includes retained tombstones.

After a complete admitted run, an authenticated owner/operator separately
reviews whether its captured episode is suitable learning material. Acceptance
is bound to the exact episode digest and record revision. A pending audit
receipt withholds the usable evidence, even if the state transition already
committed. Export returns the learner episode with its native provenance and
authenticated review; preserve that complete bundle. Supplying its episode to
the pure learner still does not make arbitrary local JSON imports authenticated.

The ordinary durable path excludes late enrollment, agent histories, branches,
loops, nested flows, failure retries, approval forms and new resume input values.
The explicitly marked teaching path above adds only its exact generated
choice/review topology and separate provenance family; arbitrary branching
capture remains unavailable.
Existing flow changes cannot rewrite the captured source snapshot. Learning
approval is neither a guarantee of business correctness nor authority to save,
publish or execute a generated workflow.

## Limits and evidence handling

### Signed evidence and governed training lineage

The signed path is separate from raw `learn --reviewed` and `refine --reviewed`.
Those flags remain local assertions. Enable the signed path explicitly:

```toml
[flows]
enable = true
action_recipes = true
action_episode_capture = true
action_recipe_lineage = true
require_action_recipe_lineage = true
action_evidence_issuer = "customer-production"
action_evidence_revoked_keys = []
```

`action_recipe_lineage` enables signed export and governed admission.
`require_action_recipe_lineage` requires a valid governed lineage reference for
every learned recipe. Capturing workflow examples or enabling signed evidence
also requires that reference even when `require_action_recipe_lineage = false`;
removing the reference cannot bypass that effective policy. These settings
default to false. Transformed v2 execution additionally needs
`action_recipe_transforms = true`; choice execution needs both that setting and
`action_recipe_choices = true`. The issuer is a stable deployment identifier
matching `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}`, not a URL or a discovered identity.
Its default is empty, which leaves signed export unavailable. Revoked signing
key IDs are unique 16-character lowercase hexadecimal strings. The installer
asks for these settings without enabling other learning capabilities.

After authenticated capture review, use the existing episode-capture resource
`/api/v1/flows/{flow_id}/runs/{run_id}/episode-capture`:

1. `POST /training-grant` supplies `expected_revision`,
   `expected_episode_sha256`, `use_until`, `retain_derived_copies: true` and a
   rationale. This is separate human consent to retain business data in training
   bundles, artifacts and derived Flow copies. `use_until` must be in the future
   and no later than the original capture deadline.
2. `POST /signed-export` supplies the current `expected_revision`,
   `expected_episode_sha256` and `expected_grant_sha256`. It returns the complete
   `{body, signature}` bundle. An identical retry recovers the persisted issuance;
   it does not extend the grant or repeat business tools.
3. `POST /withdraw` supplies the current `expected_revision`,
   `expected_episode_sha256`, `expected_review_sha256`, `withdraw: true` and a
   rationale. Withdrawal retains the original acceptance as history and blocks
   current governed reuse. Refresh metadata after state transitions to obtain
   current revisions and commitments.

The run page's **Learning example** card provides the withdrawal form without
requiring copied commitments or edited JSON. **Stop using this example** requires
an explicit reason and confirmation. Its dedicated `GET /withdrawal` preparation
route returns restricted metadata and `withdrawal_available`; it does not expose
the example, its business inputs/results, or a signed bundle. This preparation
and the restrictive withdrawal remain available when workflows, capture or
lineage are disabled, or the learning emergency stop is active. They retain
current human, workspace, owner, source, retention, revision and audit checks;
they are not an unconditional emergency-revocation channel.

A stale request requires refreshed metadata and another deliberate confirmation.
Uncertain network or audit outcomes require readback before another attempt;
pending recording is not reported as success. Withdrawal prevents current
governed reuse but does not undo completed work or erase exported copies. Other
learning operations keep their existing feature gates. This card completes only
withdrawal, not setup, enrollment, review, consent, export or Copilot operation.

The withdrawal rationale is retained inside encrypted evidence; normal metadata
and audit carry its commitment. Authorized detail access to an unexpired
withdrawn record can return `withdrawal_detail.rationale` without exposing the
episode or signed bundle. Source evidence expiry removes that encrypted content
on access, leaving the minimal status/commitment tombstone.

These routes require a currently authenticated human, workspace access and
source ownership/access. Body fields cannot supply an actor, owner, tenant or
trusted reviewer. Pending audit delivery returns metadata only or an audit-pending
error, with no signed bundle. Responses use `Cache-Control: no-store`.

The service signs the exact episode, native source/run/call commitments,
authenticated review, capture contract and bounded training grant using the
existing domain-separated Ed25519 audit signing primitive. This is a **service
attestation of its recorded review**, not the reviewer's personal signature,
independent proof of an external business outcome or protection from an
administrator who can use the process's signing key. Injected/KMS-unwrapped keys
still sign locally in process memory. Signing does not encrypt exported JSON.

For offline verification, obtain the public-key trust policy independently of
the bundle. Its exact fields are `schema: "lightwork.action-evidence-trust.v1"`,
`issuer`, `tenant`, `purpose: "action_recipe_training_evidence"`, `keys` (a mapping
from 16-hex key IDs to 64-hex raw Ed25519 public keys) and `revoked_keys` (a list
of key IDs). Key IDs must match their full public-key fingerprints. The bundle
cannot enroll its own key. Rotation can retain old public keys for verification;
the supplied/current revocation policy determines whether a key is accepted.

```powershell
maverick flow recipe verify-bundle --bundle signed-episode.json --trust trust.json --tenant exact-tenant
maverick flow recipe learn-verified --bundles signed-episodes.json --trust trust.json --tenant exact-tenant --allow-tool customer_lookup --allow-tool order_create --output lineage.json
maverick flow recipe refine-verified --package lineage.json --bundles more-signed-episodes.json --trust trust.json --tenant exact-tenant --output refined-lineage.json
maverick flow recipe draft-verified --package refined-lineage.json --trust trust.json --tenant exact-tenant --flow-id inspection-draft --name "Inspection draft" --output inspection-flow.json
```

`--bundles` is an array of complete signed bundles. `learn-verified` also accepts
`--domain`, `--max-operations`, `--operators` and `--constants` for v2; providing
a domain explicitly selects transformed learning. Add `--choices` with the
complete prefix/branches domain to select choice learning instead:

```console
maverick flow recipe learn-verified --choices --domain choice-domain.json --bundles signed-choices.json --trust trust.json --tenant exact-tenant --allow-tool case_open --allow-tool case_approve --allow-tool case_queue_review --output choice-lineage.json
```

The same `refine-verified` and `draft-verified` commands dispatch by the package's
artifact schema; governed admission and draft routes also accept choice packages.
Every artifact episode must
have a verified bundle from the same issuer, tenant and owner. A mixed unsigned
batch is refused. Refinement retains earlier bundles and the original composed seed
literal policy. Packages bind the complete artifact, source manifest and
refinement ancestry; no raw training episode can silently acquire verified status.

Offline verification reports `signature_status`, `commitments_status`,
`time_status` and **`live_status: "not_checked"`**. It cannot discover a later
review withdrawal, source deletion/reassignment or a revocation absent from the
provided trust file. Local verified learning does not create a governed admission.
`draft-verified` creates an unadmitted inspection draft without a trusted record
reference; retain the original package and use the authenticated service for
governed deployment.

`POST /api/v1/flows/recipe-lineage` with `{ "package": ... }` admits a package
under current same-tenant, same-owner source authority and the deployment's
protected key registry. `GET /{admission_id}` returns metadata; `GET
/{admission_id}/detail` returns the package only when authorized and eligible;
`POST /{admission_id}/draft` with `flow_id` and `name` returns an unsaved Flow
carrying the exact governed reference. All these suffixes are relative to
`/api/v1/flows/recipe-lineage`. The API derives its owner from the authenticated
principal; administrative access does not let the body impersonate another owner.
Existing destination ownership is checked. Draft export grants no authority to
save, publish or execute. Pending admission audit withholds package and draft
content, and a fresh authorized retry recovers the same committed admission.

The customer-facing **Build a flow from reviewed runs** path on the Teach page
uses these signed checks too: it obtains current signed copies only from
accepted runs with a separate, unexpired training grant; learns a verified
package; and admits that exact package when the person confirms the new draft.
Refinement keeps the signed ancestry. The page then offers the normal save and
publish controls. A withdrawn or expired source blocks later admission and
native action eligibility; it does not undo an action already dispatched.
The older unsigned local learner remains available for compatibility outside
this customer route. Its artifacts cannot be saved, published or run while
workflow example capture or signed lineage is enabled. If an administrator
turns both of those features and the explicit require setting off, unsigned
recipes can run again and do not gain the signed path's revocation guarantee.
An older unsigned flow must be rebuilt from currently accepted, separately
granted runs on the Teach page before it can run under customer learning policy.

Saved definitions and snapshots check the structural lineage binding and the
effective require-lineage policy. The governed draft service and native recipe proposal/
dispatch paths perform current source, tenant, owner, review, key and grant checks.
Each action still requires the ordinary native tool authority, budget and
execution approval. Decision receipts identify the artifact, lineage admission,
package, Flow, run and step plus the eligibility check time. These are checks at
that time, not a distributed revocation fence or cancellation of an already
dispatched effect. A failure after an earlier action preserves the completed
prefix and stops further work without replay.

The earliest source grant limits the admitted workflow. Capture is bounded to
seven days, grants cannot exceed that deadline, and there is no grant renewal
route. Expiry or withdrawal stops later action proposals/dispatches; it
does not undo completed work. Source capture expiry also does **not** erase
downloaded bundles, CLI artifacts or derived Flow/history copies. Their retention
requires the explicit copied-data consent and the owner's data-handling policy.
This is bounded reuse of reviewed work, not indefinite autonomous learning.

### Resource and data limits

Ordinary recipe artifacts and CLI JSON files are limited to 262,144 bytes;
workflow-memory artifacts have the separate 1 MiB bound described above and are
carried inside bounded lineage packages. The v1 binding search
has a two-million-comparison cap; v2 and choice learning have the complete-expression limits above.
Partial searches never produce a usable artifact.
Signed single-episode bundles retain the 262,144-byte limit. Lineage packages and
CLI arrays of signed bundles have a separate 2 MiB limit; their embedded recipe
still obeys its original artifact bound. CLI outputs never replace existing files.
Capture uses smaller per-value/episode limits. Fixed shapes deliberately reject
extra/missing response fields and changed array cardinality. Formatted prose,
paginated/incomplete connector replies and transformations outside the declared
composed grammar remain outside the supported recipe contract.

Raw examples and captured arguments/results can contain confidential business
data. They belong inside the corresponding access boundary. New recipe decision
events contain identifiers and commitments instead of raw values. Existing native
tool audit events also retain bounded, redacted input/output summaries. Signed local receipts
do not provide independent witnessing or protection from an administrator who
controls both storage and signing keys. Local fixture tests establish implemented
behavior within their scope, not live customer acceptance.
