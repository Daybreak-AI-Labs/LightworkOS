---
name: lease-abstract
triggers:
  - lease abstract
  - lease summary
  - pull the critical dates
  - summarize this lease
tools_needed:
  - knowledge_search
  - read_file
---
# What this skill does

Abstracts a commercial lease into a structured summary a non-lawyer can act on. Produces a one-page abstract capturing parties, premises, term and critical dates, base rent and escalations, recoveries (CAM/NNN), renewal/expansion/termination options, and notable clauses (assignment, exclusivity, co-tenancy), each pinned to its source section.

# Steps

1. Read the lease document with read_file; if it references a master lease, exhibits, or amendments, use knowledge_search to locate them and abstract the controlling terms (an amendment overrides the original — note which governs).
2. Extract the core economics and dates: commencement/expiration, rent commencement, base rent schedule, escalation mechanism (fixed %, CPI, stepped), and expense recovery structure (gross, NNN, base-year stop). Cite the section/page for each value.
3. Extract optionality and obligations with their trigger dates and notice windows: renewal options, termination/break rights, expansion/ROFR, assignment/sublet consent, and any exclusivity or co-tenancy. List each critical date (e.g., "renewal notice due 9-12 months before expiry") explicitly.
4. Compile the abstract with a source citation per field. Mark any term that is ambiguous, blank, or conflicts across documents as UNVERIFIED — needs legal review. Hand off the abstract and list the unresolved items.

# Notes

Output is wrong if it states a figure with no section citation, silently resolves a conflict between the base lease and an amendment, or misses a notice window (a missed renewal-notice date can forfeit an option — these are the highest-stakes fields). Never paraphrase a legal term in a way that changes its meaning; quote the operative language for options and termination. This is a reading aid, not legal advice — it stages dates and terms for a human; a qualified reviewer confirms anything binding or contested. Do not use for residential leases or non-lease agreements without adjusting the field set.
