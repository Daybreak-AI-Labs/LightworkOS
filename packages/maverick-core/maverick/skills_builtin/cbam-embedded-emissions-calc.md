---
name: cbam-embedded-emissions-calc
triggers:
  - calculate cbam emissions
  - embedded carbon
  - cbam report
  - embedded emissions calculation
tools_needed:
  - read_file
  - spreadsheet
  - knowledge_search
---
# What this skill does

This skill computes the embedded emissions of in-scope goods under the EU Carbon Border Adjustment Mechanism (CBAM) methodology — direct (process) emissions plus, where applicable, indirect emissions from electricity consumed in production — using cited emission factors and the prescribed system boundaries, and assembles the quarterly CBAM report draft. It applies the actual-data hierarchy (installation-specific actual values preferred, default values only where permitted) and keeps every factor sourced. The output is a calculation workbook and a report draft staged for the CBAM declarant/regulatory owner; it does not submit to the CBAM registry or purchase certificates.

# Steps

1. Use knowledge_search to load the current CBAM methodology for the goods in scope (the relevant sector rules, system boundaries, the direct + electricity-indirect treatment, and when default values are allowed vs actual installation data), and confirm the reporting period and the CN codes of the products.
2. Use read_file to gather the activity data: production volumes per good, direct fuel/process emissions, electricity consumed, and any precursor (embedded upstream) emissions, along with the installation's actual emission data where available.
3. Use spreadsheet to compute embedded emissions per tonne of good: direct emissions (process + fuel) and electricity-related indirect emissions, attributed to product output, including precursors per the methodology. Cite the emission factor and its source for every number, and flag any line that falls back to a default value (noting defaults are only permitted within limits).
4. Assemble the CBAM report draft in the required structure (per good: quantity, direct and indirect specific embedded emissions, methodology/data basis, emission-factor sources) plus a methodology note, and stage it for the declarant/regulatory owner. Mark it DRAFT — registry submission and any certificate decisions are human actions.

# Notes

Use the actual-data hierarchy: CBAM prefers installation-specific actual emissions and limits reliance on default values — flag every default you fall back to rather than defaulting silently, because over-using defaults is a compliance and cost problem. Direct and electricity-indirect emissions are computed and reported separately with different rules; don't merge them. Cite the emission factor and source for each figure so an auditor can reproduce it; an unsourced factor is a defect. Precursor (upstream embedded) emissions are part of the boundary for many goods — don't stop at the final process step. This skill computes and drafts the report; it does not submit to the CBAM registry, surrender or buy certificates — the deliverable stops at a staged draft for the declarant. Confirm the methodology version, since CBAM rules phase in over time.
