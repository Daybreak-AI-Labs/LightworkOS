---
name: disaster-recovery-plan
triggers:
  - write a DR plan
  - plan disaster recovery for our systems
  - define RTO and RPO for our infrastructure
tools_needed:
  - knowledge_search
---
# What this skill does

Plans IT disaster recovery for a defined set of systems or services: a DR plan with per-system recovery runbooks, a mapped dependency graph, and a validation/test plan. Produces a draft that links each in-scope system to its recovery tier, recovery steps, and the tests that prove the plan works.

# Steps

1. Fix scope from the request: which applications, data stores, and infrastructure, and which failure scenarios (single-system, AZ/region loss, data corruption, ransomware). Use `knowledge_search` to retrieve the system inventory, architecture diagrams, existing runbooks, and backup configuration — cite each; treat any system not found as out of scope and say so.
2. Map dependencies: for each system, record upstream/downstream services, data stores, network, identity, and third parties; identify the recovery ordering implied by the graph. Flag circular or undocumented dependencies as risks rather than resolving them by assumption.
3. Set per-system RTO/RPO from the business tiers (reuse the BCP/BIA if available), then write recovery runbooks: failover/restore steps, backup source and integrity check, data-loss window, rollback, and the owner who executes each. Note where current backup cadence or replication cannot meet the stated RPO.
4. Build the test plan: tabletop, restore-from-backup, and failover drills per tier with pass criteria and cadence. Report the DR plan with assumptions, unmet RTO/RPO, and untested runbooks called out; hand to the platform/DR owner — do not assert recovery capability that has not been tested.

# Notes

Output is wrong if runbooks reference systems or backups not confirmed in the searched inventory, if RPO is stated without verifying actual backup/replication frequency, or if recovery ordering ignores a real dependency. Untested runbooks are recommendations, not proven recovery — never present them as verified. This skill drafts plans and proposes drills; executing a failover, deleting/repointing data, or changing production backup config is irreversible and must be done by a human under change control. Not for process-level continuity (use the business-continuity plan) or live incident command (use the crisis-management playbook).
