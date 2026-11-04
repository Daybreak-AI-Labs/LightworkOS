---
name: export-control-classification
triggers:
  - export control classification
  - eccn determination
  - is this item itar or ear controlled
tools_needed:
  - knowledge_search
---
# What this skill does

Classifies a specific item, technology, software, or technical data for export control under the relevant regime (US EAR/ECCN, US ITAR/USML, EU dual-use, or applicable local regime) and produces a draft jurisdiction-and-classification determination with a country/end-use license-requirement matrix. Output is a recommendation a trade-compliance officer signs off on, not a self-executing decision.

# Steps

1. Capture the item's exact technical specifications from the requester: function, performance parameters, form (hardware/software/source code/technical data), and whether it is developed/produced for or modified from a military application. Record what is known vs. assumed — do not infer specs that were not stated.
2. Use `knowledge_search` to identify the governing regime and candidate classification: search the controlling regulation (e.g., EAR Commerce Control List categories/product groups, USML categories, EU Annex I) for entries matching the item's function and parameters. Cite the specific category, ECCN/USML paragraph, and the reason-for-control codes; flag any "specially designed" or threshold language that hinges on a spec you marked as assumed.
3. Determine jurisdiction first (ITAR/USML vs. EAR vs. not-subject), then the precise classification within that regime, then the controls that attach: reasons for control, applicable license exceptions/exemptions, and de minimis or foreign-product-rule considerations if re-export is in scope.
4. Build the license matrix: rows = destination countries / end-use / end-user categories the requester named; columns = license required (Y/N), governing exception/exemption, and screening triggers (denied-party, embargo, end-use red flags). Report the draft determination, list every assumption and unresolved spec, mark any item as "tentative — confirm spec X," and hand off to the trade-compliance owner for sign-off.

# Notes

The determination is only as good as the technical inputs: a single unstated performance threshold can flip an ECCN or move an item from EAR to ITAR, so unverified specs must be surfaced, never silently resolved. "Specially designed," "required," and "in development" have regulation-specific definitions — apply the regulatory definition, not the plain-English one. Embargo, denied-party, and end-use determinations are point-in-time; cite the regulation version/date searched. This skill drafts and recommends only; actual export, license filing, or a "no license required" release decision is an irreversible compliance action reserved for a human officer. Do not use for sanctions/OFAC blocking determinations (different regime) or for classifying an entire product line in one pass — classify discrete items.
