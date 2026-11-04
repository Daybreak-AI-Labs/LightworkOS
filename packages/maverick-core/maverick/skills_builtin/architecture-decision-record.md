---
name: architecture-decision-record
triggers:
  - adr
  - architecture decision
  - decision record
  - document this technical decision
tools_needed:
  - knowledge_search
---
# What this skill does

Captures a single significant technical decision as an Architecture Decision Record (ADR) so the reasoning is durable and reviewable. Produces a structured record: context and forces, the decision taken, its consequences (positive and negative), and the alternatives considered and rejected with the reason for rejection. One ADR documents one decision.

# Steps

1. Identify the exact decision being recorded and its status (proposed/accepted/superseded). Gather the driving context from real inputs — requirements, constraints, prior ADRs, and existing system docs via `knowledge_search`. Do not invent constraints; if a force is assumed, label it.
2. State the decision in one or two unambiguous sentences (what we will do), then list the forces that made it necessary so a future reader understands the pressure behind it.
3. Record consequences honestly: what gets easier, what gets harder, new obligations, and risks introduced. Then list the alternatives considered, each with why it was rejected — an ADR with no rejected options is incomplete.
4. Assemble the ADR (title, status, date, context, decision, consequences, alternatives) and report it. State which forces are documented vs. assumed, and mark the record as `proposed` for human ratification rather than `accepted` unless the decision owner has signed off.

# Notes

The record is wrong if it bundles several decisions or omits the rejected alternatives — both destroy its future value. Keep it factual about trade-offs; an ADR that lists only upsides isn't trustworthy. This skill drafts and proposes; it does not authorize the decision — moving status to `accepted` and acting on it is the decision owner's call. Don't use it to relitigate a settled decision (write a new ADR that supersedes the old one instead) or for routine, reversible choices that don't warrant a permanent record.
