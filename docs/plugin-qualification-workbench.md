# Plugin qualification workbench

Enable **Plugin qualification workbench** in Settings or the installer, then open
Plugins. Follow **Choose a practice environment** to Settings and choose **Load
installed environments**. Select a named, already installed local Linux environment,
review the change and save it. Copilot can open the same protected setting. Loading
the list does not start a container or download anything. Saving verifies the exact
selected environment again; missing or changed choices remain unavailable.
The installation administrator supplies a reviewed environment containing the
exact distribution and `maverick-agent[plugin-workbench]`.
Channel checks also require `maverick-channels`; local gRPC checks require the `[grpc]` extra and generated plugin stubs already in the read-only image. Node checks require Node and the
reviewed dependencies already in the image. Nothing pulls an image, installs a
plugin, inherits provider credentials, mounts host work, or falls back to host
execution. The strict research runner verifies container policy and cleanup and
uses its explicit Budget. Missing image dependencies fail the check.

The workbench inspects entry-point metadata without importing targets on the
host. Missing/malformed manifests, incompatible API versions, denied permissions,
uninspectable bytes or ambiguous names cannot qualify. Its negative admission
control verifies the same runtime gate rejects a denied entry before import.
For Node commands, current explicit configuration is the admission boundary;
removing that exact command denies it before startup. These controls do not claim
that arbitrary code obeys advisory permissions outside the restricted container.

The Plugins page supplies a sample shape for each real interface:

- **Python tools:** validate the actual declared object schema, including formats
  and rejection of external schema references, then invoke the actual tool.
- **Channels:** instantiate the actual Channel subclass with a synthetic handler,
  run start, normalized dispatch, send, and stop. The image must contain synthetic
  local configuration. A channel that requires real credentials or network access
  cannot pass this offline check; no mocked provider acceptance is substituted.
- **Skills:** validate the actual Skill fields, select using the native lexical
  retriever with a synthetic goal, and render the native bounded prompt.
- **Personas:** invoke the actual zero-argument renderer and require nonempty text.
- **Node tools:** use the configured bundled `.js`, `.mjs` or `.cjs` source through
  the actual NDJSON host. The supported qualification launch is `node <file>` with
  no extra arguments or command-line secrets. Source is copied into the restricted
  container, verified by hash, and run with its image's Node. Other launch forms
  must be converted to a reviewed bundled entry. The actual manifest and selected
  schema are checked before invocation; transport errors never qualify as a result.
- **gRPC tools:** run an exact configured local bundled Python or Node server in
  the container, validate its real Describe schemas, and call its selected tool
  once with a deadline. Connection-only servers have no inspectable version and
  cannot qualify until an exact local server entry is configured. Unsupported
  launch forms must be bundled for the image; no live endpoint is substituted.
  The host owns its child process tree, bounds RPC messages and process output,
  polls cancellation/deadlines, and never repeats a Call after a transport failure.
  Typed unknown outcomes prevent outer tool retries, including read-looking names.

For a supported inspected tool, choose **Open guided practice check**. Ordinary
questions handle required and optional values, lists, nested objects, numbers and
yes/no choices; the expected answer uses the same guided controls. Review every
input and expected value before confirming. A changed inspection or input schema
requires a fresh review. Advanced interfaces retain their original sample controls.
A persona's result is a
JSON string. Skill results contain selected names and the rendered prompt. Channel
results contain the structured reply, synthetic handler messages and send completion.
Node and gRPC results preserve their hosts' string result contract. Inputs and outputs remain
in the one execution; durable receipts retain their hashes, not their bodies.

Run sample, timeout and cancellation checks. A deliberately slow input can exercise
actual interruption. A fast exact completion is recorded as **completed before
interruption**, with `interruption_observed=false`; it never becomes evidence that
an interruption occurred. Termination before observed plugin dispatch cannot pass.
All passing records require verified whole-container cleanup. A crash after possible
dispatch remains unknown. An operation ID is reserved durably before any execution
and cannot replay, including after a lost response. Refresh the ledger to recover it.
The 1000-check account ledger fails closed at capacity rather than forgetting IDs.

Publishing requires passing current sample and both deadline/cancellation attempts,
plus an affected-work review and concrete rollback plan. Published records retain
what each attempt actually observed. Scope is always restricted-container behavior,
never live read/write capability or service acceptance. Installed bytes, admission
policy, immutable image or harness changes invalidate qualification. Python image
comparison normalizes path separators without changing existing deployment lock
hashes; platform-specific bytes still must match exactly. No package is installed
or rolled back by publication.

While enabled, task registries and direct workflow actions retain durable plugin
pins across restarts. Python, Node and gRPC pins are checked before plugin import/construction where a
work identity exists and again before dispatch. Cached Python modules with different
or untracked bytes require an explicit reload after affected work is stopped; they
cannot be relabeled as a newer installed version. Skills retain a private copied
binding; persona renderers and channel dispatch/send methods check current policy.
Channel cleanup remains available after revocation. These guards refuse drift;
they do not install side-by-side old packages.

The affected-work inventory shows only authorized tasks and owned workflow runs,
with up to 2000 records per inventory. Review their history before migrating a pin
to a currently published version. A workflow migration uses the same run lock as
execution, requires exact owner and definition revision, and refuses running or
indeterminate work. Task migration requires a stopped owned task. Migration retains
prior fingerprints, never resumes work, and never replays historical effects.

Copilot uses the same typed native workbench handlers for status, sample checks,
cancellation, publication and pin migration. Administrators must enable the
**Plugins** Copilot action family in Settings or the installer. Every mutation
requires a fresh review and explicit confirmation; durable operation receipts
recover uncertain responses without redispatch. Turning Copilot off leaves the
native Plugins journey available.

A native browser journey has been run against an actual restricted Python-tool
container: inspected schema, ordinary input form, complete review, execution,
lost-response recovery and the original single saved result. Changed schemas and
accounts were refused; cleanup was verified. This qualifies that bounded local
journey, not arbitrary third-party plugins, live services, Node/gRPC images or
production outcomes. Each installation still needs its own approved environment.
