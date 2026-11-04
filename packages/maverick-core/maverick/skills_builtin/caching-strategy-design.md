---
name: caching-strategy-design
triggers:
  - caching strategy
  - cache design
  - cache invalidation
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a caching strategy for a given workload and produces a layered plan specifying what to cache, where (client/CDN/app/distributed/DB), each layer's TTL, and the invalidation mechanism. Output is a concrete design with read/write pattern justification, consistency guarantees, and named failure handling — not a generic "add a cache" suggestion.

# Steps

1. Establish the workload from real inputs: read/write ratio, access frequency and skew (hot keys), data volatility, staleness tolerance, and consistency requirements. Use `knowledge_search` to pull the system's documented access patterns and SLAs; mark any value you had to assume rather than confirm.
2. Choose layers and population strategy per data class: client/browser, CDN/edge, in-process, distributed (Redis/Memcached), and read-through vs. write-through vs. write-behind vs. cache-aside — matching each to its volatility and consistency need.
3. Set TTLs and invalidation per layer: justify each TTL against staleness tolerance, define the invalidation trigger (TTL expiry, event/write-driven, versioned keys, explicit purge), and address stampede protection (jitter, locks, request coalescing) and the cold-start/miss path.
4. Report the design as a layer table (data class → layer → TTL → invalidation → consistency) with the cache-miss and failure-mode behavior. State assumptions explicitly and flag where eventual consistency is introduced so a human owner accepts the staleness tradeoff.

# Notes

The output is wrong if it ignores invalidation (the hard part) or caches data whose staleness violates a correctness requirement — never cache data that must be strongly consistent without saying so. Cache-aside without stampede protection collapses under a hot-key miss; always specify it. Cite the source for stated access patterns/SLAs via `knowledge_search`; if unavailable, mark assumptions and do not fabricate traffic numbers. This is a design deliverable — provisioning real cache infrastructure or changing eviction in production is a human decision.
