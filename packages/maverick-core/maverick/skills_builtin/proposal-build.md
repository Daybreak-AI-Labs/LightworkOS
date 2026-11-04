---
name: proposal-build
triggers:
  - sales proposal
  - proposal build
  - quote proposal
tools_needed:
  - knowledge_search
---
# What this skill does

Assembles a sales proposal for a qualified opportunity: scope of work, the value/business case tied to the prospect's goals, pricing, and commercial terms. The output is a structured draft a rep can review and route for approval, not a binding quote.

# Steps

1. Retrieve the deal specifics from `knowledge_search` over discovery notes and CRM: confirmed needs, success criteria, stakeholders, contract drivers, and any verbal pricing/term agreements. Retrieve the approved pricing model, SKUs/packages, standard terms, and proposal template from the knowledge base. Flag every figure whose source you cannot confirm.
2. Define scope from confirmed needs only — what is included, explicitly what is out of scope, deliverables, and timeline/milestones. Do not infer scope the prospect never agreed to.
3. Build the value section by tying each scope item to a quantified outcome or success criterion the prospect stated, then construct pricing strictly from the approved model (list price, any agreed discount with its justification, total, and payment schedule). Pull terms (term length, SLA, renewal, legal boilerplate) from the standard template.
4. Assemble the proposal (summary, scope, value/business case, pricing, terms, next steps) and report it. State assumptions explicitly, mark any pricing or term that needs Finance/Legal/deal-desk approval, and hand off for human review before sending — never present it as final.

# Notes

The proposal is wrong if pricing deviates from the approved model without a cited approval, if scope includes uncommitted items, or if any number/term is fabricated rather than drawn from a source. Pricing, discounts, and contractual terms are irreversible commitments: they are staged for human approval (deal desk, Finance, Legal) and never auto-sent. Cite the source for every price and term; mark unverified figures clearly. Do not use this for an unqualified or early-stage deal where scope and budget are not yet confirmed.
