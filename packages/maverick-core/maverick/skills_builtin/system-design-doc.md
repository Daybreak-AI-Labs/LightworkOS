---
name: system-design-doc
triggers:
  - system design
  - design doc
  - architecture doc
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a system-design document for a proposed service or feature: the problem statement, component breakdown, data flow, and the trade-offs behind each major choice. The output is a reviewable artifact a team can critique and sign off on before implementation, grounded in the actual requirements and any existing internal architecture, never a generic template.

# Steps

1. Pull the real inputs: the feature/service goal, expected scale (RPS, data volume, latency targets), consistency and availability needs, and hard constraints (budget, deadline, compliance). If any are unstated, list them as open questions rather than inventing numbers.
2. Run `knowledge_search` for existing services, platform conventions, and prior design docs that this system must integrate with or resemble; reuse established patterns and cite the doc/source for each borrowed decision.
3. Decompose into components (clients, APIs, services, stores, queues, external deps). For each, state its responsibility and the interfaces it exposes. Draw the data flow as a numbered request/write path showing where data is read, written, cached, and where failures are handled.
4. For each significant decision (datastore choice, sync vs async, consistency model, partitioning), record the alternatives considered and the trade-off (cost, latency, operational burden, blast radius). Note failure modes, scaling limits, and rollout/back-out plan.
5. Hand off the doc with assumptions and open questions called out explicitly, flagging any decision that needs a human owner to ratify before build.

# Notes

The output is wrong if it asserts scale or SLAs that were never given — mark those as assumptions, not facts. A design with components but no failure handling or data-flow path is incomplete. Cite internal sources for every reused pattern; mark anything unverified. This is a recommendation: it does not authorize building or provisioning infrastructure — a human approves the design and any irreversible commitments (vendor lock-in, schema-on-write choices). Do not use for a pure code review or a one-file change; this is for net-new or substantially-reworked systems.
