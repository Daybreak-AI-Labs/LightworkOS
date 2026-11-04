# Compaction execution and feature reuse

The agent's ordinary heuristic compaction makes no model request. Model-assisted
compaction is selected through the existing `MAVERICK_COMPACTION_STRATEGY` or
`[context] compaction_strategy` setting (`learned`, `multimodal`, `streaming`, or
`graph`), or through the optional hybrid picker. Explicit strategy selection still
overrides the hybrid picker.

## Optional model-assisted strategies

The synchronous public entry points and their `*_async` counterparts drive the
same generator algorithm. A request step is executed through `llm.complete` for
an explicit synchronous caller or awaited through `llm.complete_async` for the
agent. No paid synchronous request is moved to a detached thread. The existing
LLM interface continues to own provider routing, usage accounting and budget
reservations; each request receives the caller's original budget and configured
summarizer or vision role model.

The agent guards the complete compaction operation with its existing wall-time
and halt polling mechanism. Budget, usage-accounting and halt errors propagate;
cancellation closes the suspended algorithm and awaits cancellation of the
provider coroutine. It does not retry a paid operation as a heuristic request.
Ordinary provider failures retain the strategy's deterministic local fallback.
A halt between media descriptions prevents the next description request, and a
halt or exhausted budget after compaction prevents the main model request.

Plugins retain their synchronous `compact` registration contract. To participate
in the async agent path, a plugin must also expose an async `compact_async` method.
A sync-only plugin or provider seam receives local heuristic fallback in the
async path; its synchronous method is not executed there.

Digest strategies preserve the first message and expand the recent tail when a
tool call/result exchange crosses its boundary. They decline a middle digest
when an exchange involving the preserved first message makes that unsafe. The
ordinary structural pass still enforces its existing size ceiling. Streaming
folds retain prefix fingerprints and cross-process sidecar locking; the final
write compares the original entry so an older completion cannot overwrite a
concurrent fold or reset. A lost write race returns this caller's computed result
without another model request; a later call can refold uncached source.

## Conversation-history feature cache

This is a separate orchestrator path. It requires both `[context] compact = true`
and `[context] async_compaction = true`, or their existing environment overrides
`MAVERICK_COMPACT_HISTORY=1` and `MAVERICK_ASYNC_COMPACTION=1`. Both remain off by
default. These settings do not enable a model-assisted strategy.

The former worker compacted an older prefix after the foreground had already
compacted the full history. That prefix did not match advancing histories, and
reusing its lossy output could remove evidence needed by a changed query or
larger budget. That worker has been removed deliberately. There is no queued job,
background thread, lossy prefix result, or cached query-dependent selection.

`BackgroundCompactor`, `compact_with_precompute`, the optional constructor
`executor` argument, and the `cached_keys`/`pending` stats remain compatible.
The executor is accepted but never scheduled; `pending` is always zero. `close()`
releases retained history, is idempotent, and leaves subsequent calls correct but
uncached. The helper still passes the complete source to `context_compactor` on
every call.

Only exact immutable text, token counts, and lexical token sets are retained.
Role/order/query selection and trimming always run against current source and
budget. Tokenizer and feature implementation identities invalidate reusable work;
changed source is prepared again, including nested content rewrites and sliding
windows. A temporary tokenizer failure never caches a fallback token count.
Entries are tenant-scoped, capped at 256 keys and 8 MiB of conservative feature
storage accounting, with a 1 MiB per-window cap. Oversized windows use uncached
compaction. These limits describe retained features, not total process memory.

## Local evidence and limits

An isolated counting probe compares actual full-source recomputation with feature
reuse, using a deterministic local token-counting seam. Exact output equality is
checked for every row:

| Source change | Full token-counter calls | With reuse | Full lexical scans | With reuse |
|---|---:|---:|---:|---:|
| Initial 8 messages | 20 | 11 | 5 | 8 |
| Advance to 10 | 24 | 5 | 7 | 2 |
| Advance to 12, changed budget | 30 | 5 | 9 | 2 |
| Rewrite old evidence | 30 | 4 | 9 | 1 |
| Sliding window rollover | 28 | 5 | 9 | 2 |
| Changed query and budget | 30 | 2 | 9 | 0 |

One full selection pass remains per call; no background pass remains. Initial
feature preparation can perform more lexical scans and retain more memory than
uncached compaction. Source flattening and relevance scoring remain linear in the
current history; this is not a constant-time compactor. These are operation-count
results, not measured BPE speedups or customer latency promises. Tests use local
fake providers and do not establish live-provider cancellation behavior.
