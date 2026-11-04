---
name: project-charter
triggers:
  - draft a project charter
  - we need a kickoff doc to scope the project
  - authorize and scope this project
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Produces a project charter that formally authorizes a project and aligns stakeholders before work starts. Captures objectives, in/out-of-scope boundaries, milestones, success criteria, named roles, high-level budget/timeline, and the key risks and assumptions — the single reference that prevents scope drift and "I thought we were also doing X."

# Steps

1. Gather inputs: the sponsor's intent, any prior proposal/business case, and related project history via `knowledge_search` and `read_file`. Where a fact (budget, deadline, sponsor) is missing, list it as an open item rather than inventing it.
2. State the objectives as measurable outcomes and define scope explicitly — a concrete in-scope list and an equally concrete out-of-scope list, since the exclusions prevent the most disputes.
3. Name roles (sponsor, project lead, key stakeholders) and lay out milestones with target dates and the dependencies/assumptions each rests on.
4. Define success criteria — the conditions under which the project is "done and successful" — plus headline budget/timeline and the top risks with owners.
5. Hand off the charter for sponsor sign-off, calling out every open item and assumption; mark dates and budget as provisional until the sponsor confirms.

# Notes

A charter is wrong if scope is vague, success is unmeasurable, or it commits to dates/budget the sponsor never approved — keep unconfirmed numbers clearly provisional. Do not fabricate stakeholders, deadlines, or funding; surface them as gaps for the sponsor to fill. The charter authorizes nothing until a human sponsor signs it — this skill drafts, it does not approve. Skip it for routine BAU work or tasks small enough that a ticket suffices.
