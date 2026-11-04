---
name: api-versioning-plan
triggers:
  - api versioning
  - deprecation plan
  - breaking change
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a versioning and deprecation plan for an API that must ship a breaking change without stranding existing consumers. The output is a phased timeline (introduce new version, dual-run, deprecate, sunset) plus per-consumer migration guidance, grounded in the actual change and the real consumer list, not a generic policy.

# Steps

1. Identify the specific breaking change(s): which fields, endpoints, or semantics change, and why a compatible alternative isn't possible. If the change could be made additive/backward-compatible, recommend that first and stop.
2. Run `knowledge_search` for the org's versioning policy, deprecation notice periods, and the list of known consumers/clients of the affected endpoints; cite these. If the consumer list is unknown, flag that telemetry must be checked before any sunset date is set.
3. Lay out the timeline with dated phases: ship new version alongside old, dual-support window, deprecation announcement (with headers/changelog), and sunset. Tie each phase to the policy's required notice period rather than arbitrary dates.
4. Write migration guidance per consumer or consumer-class: the exact old→new mapping (endpoint, field, payload), code-level before/after, and how to verify they migrated. Define the rollback if the new version regresses.
5. Hand off the plan, stating assumptions about consumer inventory and flagging the sunset cutover as an irreversible step requiring human sign-off and confirmed-zero traffic on the old version.

# Notes

The plan is wrong if it sets a sunset date without verified knowledge of who still calls the old version — never sunset on assumption. Cite the deprecation policy for all notice periods; mark unverified consumer data as such. Removing/disabling the old version is irreversible and must be staged for a human to approve after traffic confirms zero usage. Don't use this for additive, backward-compatible changes — those need no version bump.
