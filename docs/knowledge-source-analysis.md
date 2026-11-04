# Selected-source analysis tasks

Enable **Tasks that analyze selected approved sources** in Settings > Memory & learning,
with governed Knowledge enabled. The installer asks the same question (off by default).
A named current workspace member opens exact source details, selects up to five versions
for one permitted use, writes the analysis question and reviews the configured spending
and time ceilings. This is a tool-free AI analysis, not an external-action agent.
Copilot offers the same native operation with a named source picker; the Knowledge
composer supports multiple sources and continued source browsing.

The ordinary idempotent goal admission atomically records the source-analysis mode.
An interrupted admission cannot turn into an unrestricted agent. Source references,
owner, tenant and task brief are immutable. Source checks run at selection, worker
start, actual provider dispatch, publication and every private result read. Current
membership, policy, purpose, exact source/provenance hashes, freshness, consent and
parent lineage use the existing Knowledge service. A changed source requires a new
reviewed selection; task copy or ownership transfer does not copy the source binding.

The existing runtime provides Budget, quotas, provider admission, execution authority,
kill switch and episode accounting. The configured writer route is pinned. There is
one physical model attempt, no tools, no automatic retry and no provider fallback.
An interrupted attempt after model admission stays blocked for explicit review. Time
limits are checked at runtime boundaries; a provider request already sent cannot be
recalled when an employee cancels or permission is subsequently revoked.

Actual analysis is stored in the private tenant-local binding record, using configured
at-rest encryption. Ordinary goal result, episode, task exports, public sharing and
local learning receive only a status/link. The result page rechecks every source and
links its exact versions. Permission to read that page grants no bulk export, training
or external action. Access loss clears displayed private results. The task is excluded
from automatic local learning before it may start. This does not claim deletion of
already-transmitted provider content or erasure from model weights.

The browser keeps only an opaque pending operation identity in session storage, not
source text or the request brief. Unknown acknowledgement requires read reconciliation;
it never starts another paid attempt automatically. A saved unstarted request may be
explicitly cancelled before replacing its selection. If the page was closed before a
receipt appeared, the app reports that uncertainty instead of claiming the work failed.

Native contract: `POST /api/v1/goals` with original `Idempotency-Key` and
`knowledge_context={context,purpose,references}`; no template, specialist domain or
director profile. `context` is the current authenticated draft workspace context.
`GET /api/v1/knowledge-access/analyses/{goal_id}` releases a result only to its exact
owner after fresh source checks. `has_binding(goal_id, world)` also detects an atomic
admission whose source sidecar was never completed.

Real browser rendering, PostgreSQL concurrency and configured-provider execution
are not qualified; check them in your installation.
