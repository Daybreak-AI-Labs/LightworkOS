---
name: contract-risk-scoring
triggers:
  - score contracts by risk
  - contract review triage
  - prioritize contract review queue
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Scores a set of contracts by risk so reviewers tackle the highest-exposure agreements first. Produces a prioritized review queue: each contract ranked with its risk score, the factors driving it, and a suggested review tier.

# Steps

1. Pull the contract inventory via sql_query (counterparty, value, term, renewal/auto-renew, jurisdiction, status). Confirm the row count matches the expected population before scoring; if the table or fields are missing, stop and report.
2. Retrieve the scoring rubric and risk-clause definitions from knowledge_search (e.g., indemnity, liability cap, termination, data/privacy, auto-renewal). Use the org's rubric — do not invent weights; if none exists, propose one and mark it unverified.
3. Compute a risk score per contract by applying the rubric factors (value, expiry proximity, missing/unfavorable clauses, jurisdiction). Show the per-factor contribution so the score is auditable, not a black box.
4. Rank descending into a review queue with tiers (e.g., high/medium/low), and hand off the queue stating the rubric version, any contracts skipped for missing data, and assumptions.

# Notes

Output is wrong if scores rest on incomplete metadata (a missing liability cap scored as "present" understates risk) — flag records with null factors rather than scoring them as safe. Scores prioritize human review; they do not approve, renew, or terminate any contract. This skill recommends a review order only; all contract actions remain a human decision. Do not use it as a substitute for legal review or where the contract inventory lacks the clause-level fields the rubric needs.
