---
name: sales-onboarding-plan
triggers:
  - sales onboarding
  - ramp plan
  - new rep
tools_needed:
  - knowledge_search
---
# What this skill does

Designs a structured onboarding and ramp plan for a new sales rep: a
week-by-week schedule with milestones, certifications, and ramp targets tied to
the role and segment. Produces an onboarding plan a manager can assign on day
one, grounded in the org's actual enablement materials and quota expectations.

# Steps

1. Confirm the role, segment, and ramp period from the request (e.g. 90 days for
   an SMB AE). Use `knowledge_search` to retrieve existing onboarding tracks,
   product certifications, sales methodology, and the segment's ramp-to-quota norm.
2. Lay out the timeline in phases (e.g. weeks 1-2 foundations, 3-6 product and
   pitch, 7-12 live deals). Assign each phase concrete activities, owners, and
   the resources to use, citing the source material for each.
3. Define exit criteria per phase: certifications to pass, a mock pitch or
   demo to deliver, and measurable ramp targets (calls, pipeline, first close).
   Do not invent quota numbers — pull them from the retrieved targets or mark TBD.
4. Assemble the plan with a clear day-one start and hand it off, stating which
   targets are sourced vs assumed and flagging that the hiring manager owns
   final quota and timeline commitments.

# Notes

Output is wrong if certifications or ramp targets are fabricated rather than
drawn from real enablement docs, or if the plan lacks measurable exit criteria
per phase ("learn the product" is not a milestone). Ramp norms vary by segment;
an enterprise plan is not an SMB plan. This is a recommended plan the manager
adapts and commits; quota and timeline are the manager's call. Do not use when no
enablement material or quota framework exists — that gap is the real first task.
