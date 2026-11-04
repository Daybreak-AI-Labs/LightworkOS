---
name: regulatory-horizon-scan
triggers:
  - horizon scan
  - upcoming regulation
  - regulatory change tracker
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Tracks proposed, pending, and recently finalized regulatory changes relevant to a defined topic or jurisdiction, and produces a horizon scan listing each rule with its status, expected effective date, likely impact, and required action window. Used to give compliance and risk owners advance warning so they can prepare before a rule bites.

# Steps

1. Fix the scan scope from real inputs: subject domain, jurisdictions, and the lookahead window (e.g. next 18 months). If the user gives no window, default to 12 months and say so.
2. web_search regulator publication feeds, consultation/NPRM trackers, and official gazettes for proposed and finalized changes in scope; knowledge_search the internal library for items already logged. Record for each: rule name, regulator, lifecycle stage (proposed/consultation/finalized/in-force), publication date, expected effective date, and source URL.
3. For each item assess impact (which obligations/systems/processes change) and urgency (effective date minus today minus typical implementation lead time). Flag anything whose lead time exceeds the runway to effective date as "at risk".
4. Report the horizon scan sorted by effective date, distinguish confirmed dates from estimates, and hand off the "at risk" items for owner assignment. State the as-of date of the scan.

# Notes

Output is wrong if it presents a proposed rule as final, or quotes an effective date that is actually a comment-period deadline — label the lifecycle stage explicitly. Never invent dates; mark "date TBD" when the source gives none. A scan is a snapshot — note that items move and the scan must be re-run; do not treat it as a standing source of truth. Do NOT use this to advise that a future rule can be ignored — deprioritization is a human risk-owner decision.
