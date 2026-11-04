---
name: workflow-bpmn-design
triggers:
  - design a bpmn workflow
  - workflow design
  - orchestration design
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a workflow or BPMN orchestration for a business process: actors as swimlanes, ordered tasks, decision gateways, and exception/compensation paths, expressed so it can be drawn in BPMN and handed to an orchestration engine. Produces a structured BPMN design (lanes, flow, gateways, exceptions) ready for review.

# Steps

1. Establish scope and participants from real inputs — the process owner's description, an SOP, or a PDD via knowledge_search. Identify the start event(s), end state(s), and every actor/system that performs work; each becomes a swimlane. Mark unconfirmed actors or steps as UNVERIFIED.
2. Lay out the main flow per lane: tasks in order with their type (user, service/automated, manual), the message/data passed between lanes, and the handoffs. Keep the happy path explicit before branching.
3. Add decision gateways with named, mutually-exclusive conditions grounded in stated business rules (exclusive vs parallel vs event-based); ensure every gateway branch has a defined destination and no dangling paths. Define exception and compensation flows: timeouts, escalations, rejections, and rollback/compensating tasks for anything already committed upstream.
4. Report the design — lanes, task list, gateway conditions, exception paths, and start/end events — with assumptions and open questions for the process owner. Recommend validation against real case data before implementation; the design is a draft, not a deployed process.

# Notes

The design is wrong when gateway conditions overlap or leave a case with no path (deadlock/black-hole tokens) — every branch must be exhaustive and mutually exclusive. A model that omits compensation for already-committed steps will leave inconsistent state on failure; always pair an irreversible upstream task with a defined rollback. Do not over-model: collapse trivial steps so the diagram stays reviewable. Skip this skill for ad-hoc, case-by-case work that resists a fixed flow — a case-management pattern fits better. The orchestration is staged for human review and validation against real cases before any engine deployment.
