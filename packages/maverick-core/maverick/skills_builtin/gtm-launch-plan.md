---
name: gtm-launch-plan
triggers:
  - gtm launch
  - launch plan
  - product launch
  - how should we launch this
tools_needed:
  - knowledge_search
---
# What this skill does

Plans a go-to-market launch for a product or feature: sizes the launch tier, selects the
channels and audiences, sequences the timeline, and defines the readiness gates that must
be green before going live. Produces a launch plan grounded in the product's actual scope
and the org's available channels, with explicit go/no-go criteria.

# Steps

1. Gather inputs with `knowledge_search`: what is shipping and its true scope, target
   segments, positioning/messaging, available channels (sales, PMM, web, lifecycle,
   partners, PR), prior launch results, and any hard date or dependency. Mark gaps as
   unverified.
2. Set the launch tier from impact and audience breadth (e.g., Tier 1 major / Tier 2
   notable / Tier 3 minor); the tier sizes the investment, channel mix, and approvals.
   Justify the tier against the evidence rather than ambition.
3. Select channels and audiences per tier and sequence the timeline backward from the
   live date: enablement, asset creation, internal launch, soft launch, GA. Name an owner
   for each workstream and call out cross-team dependencies.
4. Define readiness gates — the conditions that must be true to ship (docs live, sales
   enabled, pricing/packaging approved, support trained, telemetry in place) — and report
   the plan with a go/no-go checklist, stating assumptions and unresolved gaps. Hand off
   to the launch owner; the go decision is theirs.

# Notes

The plan is wrong if the tier is inflated (burns channel goodwill and team capacity on a
minor release) or if readiness gates are decorative — a gate with no owner or no pass/fail
criterion will be skipped under deadline pressure. Do not assume channels or dates that
were not confirmed; mark them unverified. This drafts a plan and a go/no-go checklist for a
human launch owner — it does not send announcements, schedule press, or trigger the live
launch. Do not use for the positioning/messaging itself (use the positioning procedure) or
for pricing decisions (use the pricing-and-packaging procedure); this assumes those are set.
