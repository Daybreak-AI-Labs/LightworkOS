---
name: sla-terms-review
triggers:
  - sla review
  - review the service levels
  - uptime commitment review
tools_needed:
  - knowledge_search
---
# What this skill does

Reviews the service-level commitments in a contract or SLA exhibit against the organization's SLA playbook: the metrics and targets (uptime, response/resolution times), how they are measured, the service credits, the exclusions that erode them, and the remedy structure. Produces a review that surfaces where the SLA is weaker than it appears and what the real exposure is. Output is a draft review for a human to action.

# Steps

1. Read the SLA terms and extract the actual commitments with knowledge_search support where definitions are referenced elsewhere: each metric, its target, the measurement window and method, and the credit schedule. Do not normalize "99.9%" without checking what it is measured against (calendar month vs. excluding maintenance).
2. Pull the SLA playbook benchmarks and approved minimums with knowledge_search; cite the standard for each metric.
3. Assess: (a) targets vs. benchmark and the real downtime budget they imply; (b) measurement — who measures, exclusions for scheduled maintenance, force majeure, and customer-caused issues, and whether exclusions are broad enough to gut the metric; (c) credits — cap, whether credits are the sole/exclusive remedy, and the claim process burden (customer must request within N days); (d) chronic-failure / termination-for-repeated-breach rights. Flag each as adequate or weak.
4. Produce the review: per metric, state the commitment, the effective protection after exclusions, the gap vs. playbook, and a risk rating; quantify the credit ceiling so the reviewer sees that credits rarely match business impact. End by handing off must-fix items and stating any assumption where a referenced definition could not be located (mark unverified).

# Notes

Output is wrong if it reads the headline uptime number without subtracting maintenance/exclusion windows, or treats service credits as real compensation when they are capped and sole-remedy. The exclusions clause, not the target, usually determines the actual commitment — read it first. Sole-remedy + low credit cap means the SLA is largely cosmetic; say so plainly. This skill recommends only; accepting the SLA or waiving a remedy is a human decision. Not a substitute for the broader MSA liability review — service credits often sit under, and are limited by, the master liability cap.
