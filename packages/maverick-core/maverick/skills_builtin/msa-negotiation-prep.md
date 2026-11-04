---
name: msa-negotiation-prep
triggers:
  - msa negotiation
  - prep for a service agreement
  - contract negotiation prep
tools_needed:
  - knowledge_search
---
# What this skill does

Prepares a negotiator to walk into a master service agreement discussion with a clause-by-clause fallback ladder: the opening (preferred) position, one or two acceptable fallbacks, and the walk-away line for each contested term. Covers the standard MSA risk clauses — limitation of liability, indemnification, IP ownership/license, warranties, termination, payment, and order of precedence. Output is a prep brief for a human to negotiate from.

# Steps

1. Identify the deal context with knowledge_search: which party we are (customer or vendor), deal size/tier, prior agreements with this counterparty, and any standing approvals or exceptions. Do not guess the posture — if unknown, flag it as an input needed.
2. Pull the MSA playbook and approved fallback positions with knowledge_search for each standard clause; cite the source for every tier of the ladder.
3. For each clause, build the ladder: preferred position, acceptable fallback(s), and the walk-away/escalation trigger (e.g. liability cap: 12-month fees preferred, 24-month acceptable, uncapped a walk-away requiring VP sign-off). Note any clause where playbook coverage is missing and mark it unverified.
4. Assemble the prep brief grouped by clause, with a priority ranking (must-win vs. tradeable) and a short list of concessions we can offer to win the must-wins. End by stating assumptions (party role, deal tier) and naming which positions need approval above the negotiator's authority before they can be conceded.

# Notes

Output is wrong if a fallback exceeds the negotiator's actual approval authority without flagging it, or if a walk-away line is presented as merely "acceptable." Limitation of liability and indemnity interact (a carve-out from the cap can swallow it) — model them together, not in isolation. This skill recommends positions only; agreeing to terms, signing, or conceding a walk-away item is a human decision, and items above authority are explicitly staged for approval. Not for one-off SOWs or NDAs — use the appropriate narrower skill.
