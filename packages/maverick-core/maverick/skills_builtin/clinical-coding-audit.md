---
name: clinical-coding-audit
triggers:
  - audit clinical coding
  - run a drg audit
  - check coding compliance
tools_needed:
  - knowledge_search
  - sql_query
---
# What this skill does

Audits a sample of clinical encounters for coding accuracy against documentation and coding rules (ICD-10, CPT/HCPCS, MS-DRG assignment). Produces an audit with per-case findings, corrected codes, the DRG/reimbursement impact, and error patterns by coder/service line. It recommends corrections; it does not rebill or alter the medical record.

# Steps

1. Define the audit scope: date range, service line/DRG family, sampling method (random vs. targeted high-risk), and the rule set/version (current ICD-10-CM/PCS, CPT, MS-DRG grouper). Confirm the documentation source of truth.
2. Pull the sample with `sql_query` from the encounter/claims tables — diagnosis and procedure codes, DRG, charges, coder ID; use `knowledge_search` for the applicable coding guidelines, payer policies, and CDI documentation. Cite the rule behind every finding.
3. For each case compare assigned codes to the documentation: flag unsupported, missed, or miscoded items, and re-derive the DRG. Quantify impact (over/under-coding, dollars, DRG shift) and aggregate error rates by coder, code, and root cause.
4. Summarize findings, corrected-code recommendations, financial and compliance exposure, and re-education targets; hand off to HIM/coding leadership and compliance. Mark any case where documentation was ambiguous as "query provider," not as an error.

# Notes

Wrong output looks like: calling a code wrong without citing the guideline, confusing under-documentation with miscoding, or recomputing a DRG with the wrong grouper version. Distinguish a coding error from a documentation gap — the latter is a provider query, not a correction. Safety boundary: this is an audit and recommendation; a certified coder/compliance officer approves any code change, and rebilling/refunds are human-decided and may carry payer/legal obligations. Do not use to auto-correct production claims.
