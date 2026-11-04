---
name: current-state-assessment
triggers:
  - assess the current state
  - as-is assessment
  - baseline assessment of this process
tools_needed:
  - knowledge_search
  - sql_query
---
# What this skill does

Produces an evidence-based as-is assessment of a process, system, or capability: how it works today, where it breaks, and what the data says. It separates documented design from observed reality and surfaces pain points with supporting evidence. Output is a baseline that later target-state and roadmap work builds on.

# Steps

1. Establish what "current state" means here: the specific process/capability, its boundaries, and the stakeholders. Pull existing documentation, prior assessments, and process maps via knowledge_search, citing each source.
2. Quantify the baseline with real data where available — run sql_query against operational tables for volumes, cycle times, error rates, throughput, and backlog. Distinguish what the data shows from what stakeholders assert; label unverified claims.
3. Map findings to themes (people, process, technology, data, controls) and rank pain points by frequency x impact, anchoring each to its evidence (a metric, a cited doc, or a flagged anecdote).
4. Report the assessment with: scope, as-is description, quantified baseline metrics, ranked pain points with evidence, and data gaps you could not close. State assumptions and hand off; do not recommend fixes here unless asked — this is diagnosis.

# Notes

The assessment is wrong if it reports the documented process as if it were the actual one — always reconcile design vs. observed data, and call out divergence. A pain point without evidence is an opinion; mark it as such. Watch for sampling bias in sql_query (date window, excluded statuses) that misstates the baseline. Cite every source; never fabricate metrics to fill a gap — report the gap. This is a read-only diagnostic; it recommends nothing irreversible. Do not use when no baseline data or documentation exists — gather inputs first.
