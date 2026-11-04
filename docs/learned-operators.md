# Bounded learned pure operators

An agent flow node can carry a pure expression learned from examples you supply
and review. The learner enumerates a fixed, bounded grammar and retains **every**
expression that matches the examples. At execution, it uses the learned result
only when the declared inputs are in bounds and all retained expressions agree.
Otherwise the original agent node runs through its normal controls and budget.
The attachment keeps that node's brief and output; it does not replace the flow
with generated code or learn tool actions.

This is useful for small repeated scalar transformations. Agreement means the
remaining expressions agree, not that the result is correct. Bad examples,
missing inputs, or an unsuitable grammar can still produce a wrong result. You
are responsible for reviewing the examples, input domain, and affected workflow.
The learner and the commands below make no model calls. A flow's fallback agent
can still make model calls and use tools.

The default `learn` grammar includes declared fields and constants; one string trim/case
operation or boolean negation; one integer addition, subtraction,
multiplication, minimum or maximum; equality or integer ordering comparisons;
and a single conditional with field/constant arms. That grammar does not freely compose
these operations. Constant-only arithmetic/comparisons and identical conditional
arms are excluded. Search-limit or candidate-limit exhaustion fails without
emitting a partial candidate set.

## Enable execution

The installer asks about learned pure operators when you enable flows. The
separate setting defaults to false and requires a real TOML boolean:

```toml
[flows]
enable = true
learned_operators = true
```

This does not enable autonomous flow publication. Local learning and evaluation
can be performed without enabling learned execution. Attachments are explicitly
added to drafts and must go through your normal review and publication controls.

## Choose the inputs and review examples

Use a minimal set of raw scalar input fields. Do not include unrelated customer
data or secrets. Each input has an explicit type and a finite declared bound.
For example, save this as `increment-spec.json`:

```json
{
  "inputs": {"x": {"type": "integer", "min": 0, "max": 100}},
  "output_type": "integer",
  "constants": [1]
}
```

Save examples you have reviewed as `increment-examples.json`:

```json
[
  {"inputs": {"x": 2}, "output": 3},
  {"inputs": {"x": 7}, "output": 8}
]
```

Supported input and output types are `integer`, `string`, and `boolean`.
Integers require `min` and `max`; strings require `max_length`; booleans need
only their type. The current limits are six input fields, eight constants, 64
examples, 1,024 retained candidates for `learn`, string bounds of at most 1,024 characters,
and integer bounds within ±10¹². At least two distinct example input records are
required. Every example must contain exactly the declared input fields and one
scalar output. These are operator-supplied examples, not independently verified
observations of the agent's behavior.

```console
maverick flow operator learn --spec increment-spec.json --examples increment-examples.json --reviewed --output increment-operator.json
```

The explicit `--reviewed` flag states your assertion that you reviewed the
examples; it does not verify that assertion or certify their labels. Learning
fails if the bounded grammar cannot represent the supplied examples.

Artifacts contain the normalized specification, the **raw examples**, the full
candidate set, example count, and SHA-256 digests. Keep artifact files within
the source data's tenant and access boundaries. Validation regenerates the
complete candidate set from those examples; deleting candidates and recomputing
a digest does not create a valid more-certain artifact. The digest detects
content changes relative to an expected digest; it does not authenticate the
author or prove the examples true.

## Learn a composed transformation

`learn-composed` learns expressions containing several operations from reviewed
end-to-end examples. Intermediate results do not need labels. This can represent
calculations such as `quantity * (unit_price - discount) + shipping` with integer
minor units, or normalization such as `upper(strip(code))`. It still learns one
pure scalar result, not a sequence of agent actions or a table transformation.

For a code-normalization example, save `code-spec.json`:

```json
{"inputs":{"code":{"type":"string","max_length":30}},"output_type":"string"}
```

Save the reviewed end-to-end pairs as `code-examples.json`:

```json
[
  {"inputs":{"code":" ac-17 "},"output":"AC-17"},
  {"inputs":{"code":" vx-92 "},"output":"VX-92"}
]
```

```console
maverick flow operator learn-composed --spec code-spec.json --examples code-examples.json --max-operations 2 --operators strip,upper --reviewed --output code-operator.json
```

`--max-operations` ranges from 1 to 4 and defaults to 3. It bounds operator
applications in each expression tree. `--operators` chooses a nonempty set from
`strip,lower,upper,not,add,sub,mul,min,max,eq,lt,le,if`; omitting it uses all of
them. Field and constant references are leaves. The declared scalar types and
bounds still apply. A smaller appropriate grammar can reduce search cost, but
choosing it is part of your specification, not evidence that excluded rules are
wrong.

The `lightwork.composed-operator.v1` artifact stores a packed graph of every
matching expression in the chosen bounded grammar. Expressions agreeing on the
training examples share graph states, but every alternative remains represented.
An unseen input is evaluated across those alternatives; sharing a training
result never establishes agreement on a new input. Candidate counts count
syntactic expression trees, including distinct trees with equivalent behavior.
Validation reconstructs the complete packed graph from its grammar and examples.
The original `lightwork.learned-operator.v1` files keep their original schema.

The same `evaluate`, `refine`, `question`, `answer`, `attach`, and `remove`
commands accept either schema. Refinement retains the artifact's chosen grammar.
Authenticated question review and draft export also accept composed artifacts.
No source flow is saved or published by these authoring commands.

Composed runtime execution requires both explicit settings:

```toml
[flows]
enable = true
learned_operators = true
composed_operators = true
```

The installer offers the separate default-off composed choice in both flow
configuration paths. File authoring remains available without enabling runtime
execution. The existing question-review setting is independent of both execution
settings.

Search and evaluation have fixed resource limits. Synthesis refuses an incomplete
search instead of returning a truncated candidate set. Packed artifacts retain
the 262,144-byte file bound; the explicit `learn` limit of 1,024 candidates does
not apply to represented composed trees. Prediction limits include 100,000
distribution insertions and 4,096 distinct values per state. If those resource
limits prevent a complete prediction, `evaluate` returns `applied:false` with
`reason:"evaluation_limit"`; flow execution uses the original agent. A resource
limit is neither agreement nor evidence that the intended function is absent.

## Inspect a decision

Save `{"x":12}` to `input.json`, then run:

```console
maverick flow operator evaluate --artifact increment-operator.json --input input.json
```

The command prints JSON with `applied`, `value`, `reason`, `artifact_digest`,
and `candidate_count`. It does not run the fallback agent. A valid artifact with
an out-of-domain input or disagreeing candidates returns `applied: false`.
The command exits successfully for that decision; automation should inspect
`applied`. Malformed files or invalid artifacts produce a nonzero exit.
Additional runtime fields are ignored; every named input must satisfy its
strict declared type and bounds. Booleans do not stand in for integers.

## Add distinguishing examples

When candidates disagree, review additional inputs and outputs and save them in
the same example-array format. Refine creates a new artifact from the combined
old and new examples:

```console
maverick flow operator refine --artifact increment-operator.json --examples additional-examples.json --reviewed --output increment-operator-v2.json
```

It preserves the original artifact and refuses contradictory labels for an
already supplied input. If a previous label was wrong, review and deliberately
replace the source example set with a fresh `learn` command. A refinement does
not change an existing flow attachment; attach the new artifact to a new draft
and review it through the same publication controls.

## Ask for a useful example

The question finder searches for an input that separates the retained candidate
expressions. Among inputs examined, it minimizes the largest candidate group
that would survive one predicted answer. Candidate counts are syntactic program
counts, not probabilities or a guarantee of real-world information gain.

For a threshold example, use this specification and initial examples:

```json
{"inputs":{"x":{"type":"integer","min":0,"max":10}},"output_type":"boolean","constants":[5]}
```

```json
[{"inputs":{"x":0},"output":false},{"inputs":{"x":10},"output":true}]
```

Save these as `threshold-spec.json` and `threshold-examples.json`, then:

```console
maverick flow operator learn --spec threshold-spec.json --examples threshold-examples.json --reviewed --output threshold.json
maverick flow operator question --artifact threshold.json --max-probes 256 --output threshold-question.json
```

The question identifies `x = 5`, where the initial examples do not distinguish
strict from inclusive comparison. Inspect its `inputs`, grouped `predictions`,
`candidate_count`, `worst_case_candidates`, and `coverage`. Review the correct
label against the intended rule; if it is false, save the JSON scalar `false`
to `threshold-answer.json`:

```console
maverick flow operator answer --artifact threshold.json --question threshold-question.json --answer threshold-answer.json --reviewed --output threshold-refined.json
```

Answer validates the exact question against its original artifact and search
coverage, then refines without altering either source file. The local CLI flag
does not authenticate a reviewer, certify their label, or create a server review
record. A changed question, mismatched artifact or unsupported answer is refused.

The proposal's `status` has three distinct meanings:

| Status | Meaning |
| --- | --- |
| `found` | An examined input splits candidate predictions; it still needs a reviewed label. |
| `equivalent` | A complete supported integer/boolean domain census found every candidate agrees on every declared input. This does not prove the agreed result is correct. |
| `search_exhausted` | No usable disagreement was found in the bounded search; equivalence was not established. |

Probe budgets range from 1 to 4,096, defaulting to 256. The question finder also
budgets one million evaluation work units: candidate evaluations for the default
grammar, or a conservative bound on distribution insertions for composed
artifacts. It does not charge a packed graph once per represented expression.
This bound can reduce the effective probe budget. An incomplete prediction is
an invalid probe and prevents an equivalence claim. `coverage` reports
requested/effective budgets, examined inputs, invalid
probes and whether the census was complete. String domains and larger mixed
domains receive bounded search, so failure to find a witness is not proof of
equivalence. Local question/answer authoring needs no server opt-in.

## Use authenticated review records

To retain questions, attributed answers and unpublished drafts in the server's
tenant-scoped governed store, opt in separately:

```toml
[flows]
enable = true
learned_operator_questions = true
```

The installer offers this default-off choice in both flow configuration paths.
It does not enable learned execution or publication. The dashboard API requires
an authenticated user principal, `operate` permission, an active named tenant,
and access to the current owned flow. A shared static bearer alone has no user
identity and cannot supply an attributed review. Owner access and the existing
dashboard-admin exception follow the normal flow-edit policy.

First attach an artifact to a draft and save that flow through the existing
flow editor/API. Request a question with the version and revision you reviewed:

```http
POST /api/v1/flows/{flow_id}/operator-questions
Content-Type: application/json

{"node_id":"compute","version":1,"revision":"<loaded flow revision>","max_probes":256}
```

The response contains the persisted review `id`, `revision`, `question` and
`status`. Use that ID and record revision to answer:

```http
POST /api/v1/flows/{flow_id}/operator-questions/{review_id}/answer
Content-Type: application/json

{"expected_revision":1,"output":false,"reviewed":true,"rationale":"Reviewed the strict threshold boundary against the intended rule."}
```

The service derives the reviewer from authentication, never a request-body
identity. The label remains an assertion by that reviewer; authentication does
not make it objectively correct. A successful answer retains the base flow,
original artifact, exact question, reviewer/label/rationale, refined artifact,
unpublished draft and hash-linked lineage in one revision-controlled record.
Changed source flow generations and conflicting answers return HTTP 409.
The service rechecks role, flow ownership, active tenant status and, for a
selected workspace, current membership and selection generation before
sensitive transitions. A membership revocation or workspace switch during
question computation cannot inherit the earlier authorization.

Read the record with `GET .../{review_id}` and retrieve its draft with
`GET .../{review_id}/draft` under the same `/operator-questions` path. Draft
export returns `{flow, saved:false, published:false}`. Saving and publishing
remain separate operations under the existing flow controls.
If the source flow has since changed, the current authorized owner can still
read the historical review with `source_current:false`; it withholds the draft
and refined artifact. Answering or exporting against that stale source returns
HTTP 409. Request a new question for the current flow revision.

If the state transition commits but its audit receipt is still pending, the API
returns HTTP 503 with `status: "audit_pending"`, its record ID/revision and
`committed_status`. It withholds the refined artifact and draft. Read the record
to retry the existing audit outbox; do not assume the answer was rolled back or
submit a different label. Export remains blocked until the receipt is delivered.
The governed record contains raw review evidence; the audit projection records
identifiers, status and digests rather than raw example/answer content.

## Attach to a flow draft

Start from a reviewed flow JSON file with an agent node that has a nonempty
brief and output, such as:

```json
{
  "id": "increment",
  "name": "Increment",
  "start": "compute",
  "nodes": [
    {"id": "compute", "kind": "agent", "brief": "Compute x plus one", "output": "answer"}
  ]
}
```

```console
maverick flow operator attach flow.json compute --artifact increment-operator.json --output flow-with-operator.json
maverick flow operator remove flow-with-operator.json compute --output flow-without-operator.json
```

Both commands write a new draft file. They do not update the flow store, publish,
schedule, or execute a flow. Attach binds the artifact to the original node's
work definition. Review the resulting draft through the normal flow controls.
Remove restores use of the original agent path. At runtime, a disabled learned
operator setting, stale or invalid attachment, out-of-domain input, or
disagreement selects the original agent path. Normal flow validation can reject
an invalid attachment before execution; repair or remove it in a new draft.
The runtime requires a durable decision audit receipt before either path and
honors learning/execution stops: an audit refusal or active stop halts the step
instead of bypassing it through fallback. Receipts contain digests, identifiers,
candidate count and decision reason, not raw example or input values. Existing
approval and action controls still apply; candidate agreement grants no new
authority and is not a grounded success score.

All CLI JSON files must be UTF-8 regular files at most 262,144 bytes, with unique
object keys, finite numbers, and at most 40 nesting levels. Writes require an
explicit `--output` path and refuse to overwrite existing files, including the
source flow. Choose a new filename for each revision. These limits keep local
authoring bounded; this feature does not learn arbitrary workflows, unrestricted
programs, side effects, or external policy truth.
