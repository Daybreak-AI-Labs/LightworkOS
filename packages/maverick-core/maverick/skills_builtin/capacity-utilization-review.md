---
name: capacity-utilization-review
triggers:
  - capacity utilization
  - utilization review
  - resource utilization
tools_needed:
  - sql_query
  - spreadsheet
---

# What this skill does

Reviews resource utilization against capacity to find bottlenecks and idle slack: where demand exceeds supply, where it's wasted, and what to rebalance.

# Steps

1. Define capacity and the utilization metric for each resource and pull actuals with `sql_query`. Distinguish theoretical from effective capacity.
2. Compute utilization by resource and period in `spreadsheet`, separating productive use from idle and from blocked/unavailable.
3. Identify the binding bottleneck and the slack; model the impact of rebalancing or adding capacity at the constraint.
4. Recommend the highest-leverage rebalance and flag where utilization is unhealthily high (no buffer) or low. State assumptions and hand off.

# Notes

Utilization reviews mislead when theoretical capacity is used as the base or 100% is treated as the goal — no slack means no resilience. Optimize the bottleneck, not every resource. Staffing changes are management's call.
