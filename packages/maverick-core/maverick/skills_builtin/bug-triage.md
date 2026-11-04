---
name: bug-triage
triggers:
  - bug triage
  - defect triage
  - backlog grooming
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Triages an unsorted bug/defect backlog into an actionable, ranked list. For each
open defect it assigns a severity, computes a priority, and routes it to an owner
or team. Produces a triage table that a lead can work top-down without re-reading
every ticket.

# Steps

1. Pull the open backlog with `sql_query` (filter to `status in ('open','new',
   'reopened')`). Capture id, title, reported_at, affected component, repro count,
   and any customer/SLA tags. Do not invent tickets that are not in the result set.
2. Assign severity per defect from observed impact: S1 data-loss/outage, S2 major
   feature broken no workaround, S3 degraded with workaround, S4 cosmetic/minor.
   Base it on the ticket's stated impact and repro count, not guesswork — flag
   tickets with no impact evidence as `severity: unverified`.
3. Compute priority as a function of severity, blast radius (users/customers
   affected, SLA tag), and frequency (repro/duplicate count). Use
   `knowledge_search` to check for known duplicates, prior incidents, or an
   existing fix before ranking; dedupe and link instead of double-counting.
4. Route each item to the owning component/team using the component-to-owner map
   (look it up; do not assume). Output the triage table sorted by priority and
   hand off, stating assumptions (severity heuristics used, any unverified impact)
   and listing tickets that need more info before they can be ranked.

# Notes

Output is wrong if severity is inflated from anecdote rather than impact, if
duplicates are counted as distinct demand, or if an SLA-bound ticket is buried by
raw frequency. Severity/priority are recommendations — closing, deprioritizing,
or auto-assigning tickets is a human decision; stage routing as suggested owners,
do not reassign in the tracker. Mark any field derived without ticket evidence as
unverified. Do not use for a single incident in flight (use incident response) or
for feature requests, which are not defects.
