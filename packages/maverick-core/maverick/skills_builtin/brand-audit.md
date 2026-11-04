---
name: brand-audit
triggers:
  - brand audit
  - brand review
  - brand health
tools_needed:
  - web_search
  - knowledge_search
---
# What this skill does

Audits how consistently a brand presents itself across touchpoints and how it is perceived externally. Produces a brand audit that flags consistency gaps (naming, voice, visual identity, messaging) against the canonical brand guidelines and summarizes external perception with cited evidence.

# Steps

1. Pull the canonical brand reference via knowledge_search: official brand guidelines, approved messaging/positioning, logo usage, and tone-of-voice rules. If no guideline exists, mark the audit as baseline-only and say so — do not invent standards.
2. Inventory real touchpoints with web_search: website, social profiles, press, app stores, partner listings. Capture exact naming, tagline, value-prop wording, and visual treatment as observed; record source URLs.
3. Compare each touchpoint to the canonical reference and log consistency gaps — divergent taglines, off-voice copy, outdated logos, conflicting positioning. Rate each gap severity (high/med/low).
4. Sample external perception via web_search (reviews, press, social sentiment); quote representative mentions with sources, separating verified sentiment from anecdote.
5. Report: a gap table (touchpoint, issue, severity, source), a perception summary, and prioritized recommendations. State assumptions and flag any inference not backed by a cited source.

# Notes

The audit is wrong if gaps are asserted without the canonical guideline to measure against, or if perception is generalized from a handful of mentions presented as consensus. Mark unverified claims explicitly; never fabricate sentiment scores. Recommendations are advisory — rebrands, takedowns, or messaging changes are staged for a human owner. Do not use for legal trademark disputes (route to counsel) or when no public footprint exists to audit.
