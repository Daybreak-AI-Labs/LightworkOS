# Tool cache generations

Tool output caching remains opt-in. Local caches and warm snapshots carry a
workspace generation. Each lookup checks the current generation; a write
attempt rotates it even when its effect is unknown. A read started before that
rotation cannot publish into the new generation. Snapshot rows without a
matching generation are ignored, including snapshots from older versions.

For Redis deployments, workers use a shared Redis generation and include it in
the entry scope. An unavailable generation coordinator causes a cache miss.
The generation key is retained during purges so old entries cannot become
current again. Deleting obsolete entries is housekeeping, not the freshness
boundary. Local-only deployments coordinate through an atomically replaced
workspace file; snapshots also use unique temporary files for concurrent saves.

These guarantees cover writes dispatched through the registry while the
coordinator is available. External changes and failed generation updates cannot
be inferred from cached data; disable caching or reconcile the coordinator
before relying on cached reads in those cases. This cache is not an authority
store and must never replace an authorization or current-state check.
