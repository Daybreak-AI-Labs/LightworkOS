---
name: contract-redline-playbook
triggers:
  - redline this contract against our playbook
  - mark up the MSA with our fallback positions
  - review this agreement and flag off-policy terms
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Redlines a third-party or draft contract against the organization's negotiation playbook. It maps each material clause to the playbook's preferred and fallback positions, flags terms outside the walk-away line, and proposes redlines with rationale. Output is a marked-up contract plus a position table tying every change to a playbook entry a reviewing attorney can approve.

# Steps

1. Load the contract with `read_file` and segment it by clause (term, liability cap, indemnity, IP, data/privacy, termination, governing law, payment, etc.). Note the contract type and counterparty so the right playbook applies.
2. Retrieve the governing playbook via `knowledge_search` for each clause type — preferred position, acceptable fallback(s), and walk-away. Cite the playbook entry (section/version) for each; if no playbook entry exists for a clause, mark it unverified rather than inventing a standard.
3. Compare each clause to its playbook target and classify: on-policy (accept), within fallback (accept with note), or off-policy/walk-away (must change). Quote the contract's actual language — do not paraphrase the operative terms.
4. For each off-policy or fallback clause, draft a redline (proposed replacement text) and a one-line rationale citing the playbook position. Flag anything with no playbook coverage or genuine ambiguity for attorney judgment rather than auto-redlining.
5. Produce the redlined contract and a position table (clause, current term, playbook target, classification, proposed redline, source). State assumptions (playbook version, contract type) and hand off to counsel; recommend changes only — do not represent this as executed or legally cleared.

# Notes

Output is wrong if a clause is classified against the wrong playbook (consumer vs enterprise, vendor vs customer paper) or if proposed language is asserted as "standard" without a cited playbook entry — every redline must trace to a source or be flagged unverified. Cross-clause interactions (e.g. a liability cap carved out by an uncapped indemnity) must be surfaced, not just per-clause checks. This skill drafts and recommends; it is not legal advice and does not approve, sign, or send terms — a qualified attorney owns the final position. Do not use it where no playbook exists for the contract type (escalate to counsel instead).
