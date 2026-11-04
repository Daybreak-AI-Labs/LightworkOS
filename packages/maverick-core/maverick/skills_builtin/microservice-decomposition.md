---
name: microservice-decomposition
triggers:
  - microservices
  - service boundaries
  - decomposition
tools_needed:
  - knowledge_search
---
# What this skill does

Decomposes a monolith (or an over-coupled system) into candidate services along domain boundaries. Produces a decomposition: bounded contexts, the seams to cut, owned data per service, the synchronous/asynchronous interactions between them, and a staged extraction order — so each service owns a coherent capability and its data, not a layer.

# Steps

1. Inventory the real system from the inputs: the capabilities/modules it exposes, the shared data stores, and the known pain (deploy coupling, scaling hotspots, team ownership). Use the actual module and table names given; do not invent a domain.
2. Identify bounded contexts by business capability and language boundaries (where the same word means different things), not by technical layer. Group the capabilities into candidate contexts and name what each owns.
3. Find the seams: for each candidate boundary, trace the data and call coupling across it, and assign each table/aggregate to exactly one owning context (shared-database access across a seam is the cut to break). Use `knowledge_search` to pull the team's DDD/decomposition conventions and any prior architecture decisions; mark unverified couplings to confirm with code/owners.
4. Define interactions: which calls become synchronous APIs vs async events, where eventual consistency replaces a former transaction, and which boundaries are too chatty/transactional to split yet (keep them together).
5. Report the decomposition as a context map (services, owned data, interactions) plus a low-risk extraction order — typically a leaf, low-coupling, high-pain context first via strangler-fig — with assumptions and the couplings still needing verification.

# Notes

The output is wrong if services are split by technical layer instead of capability, if two services share a database (no real boundary), if a split breaks a transaction that the design doesn't replace with a saga/eventual-consistency plan, or if the resulting chatter creates a distributed monolith. Coupling claims must be grounded in real code/schema or marked unverified — never assert a clean seam you haven't traced. This is a recommendation: actually extracting a service is irreversible-ish and staged for human review and incremental rollout. Not for systems whose pain is solvable by modularizing the monolith.
