---
name: privacy-ropa-build
triggers:
  - build our ropa
  - record of processing activities
  - we need an article 30 record
tools_needed:
  - knowledge_search
  - sql_query
---
# What this skill does

Builds a Record of Processing Activities (Article 30 GDPR-style) for a given scope of systems or business units. For each processing activity it captures the purpose, categories of data and data subjects, legal basis, recipients and onward transfers, retention period, and applicable safeguards. Output is a structured ROPA table that is review-ready for the DPO — it documents the current state, it does not certify lawfulness.

# Steps

1. Scope the request precisely: which entity/business unit, which systems or processing activities, and whether this is a fresh build or an update to an existing record. State the scope assumption explicitly if the request is broad ("all of marketing").
2. Pull existing facts before inventing any. Use `knowledge_search` for prior ROPAs, data maps, DPIAs, processor contracts, and retention schedules; use `sql_query` against the data-inventory/asset catalog to enumerate systems, the personal-data fields they hold, and configured retention where it exists. Cite each source per row.
3. For each processing activity, fill the ROPA columns: purpose, data-subject categories, personal-data categories (flag special categories separately), legal basis, controller/processor role, recipients, third-country transfers + transfer mechanism, retention period, and technical/organizational safeguards. Where a value cannot be sourced from a system or document, mark it "TO CONFIRM — owner" rather than asserting a basis or retention you cannot evidence.
4. Output the ROPA as a table plus a short gap list (rows with unconfirmed legal basis, missing retention, or undocumented transfers). Report the source for every populated cell and hand off to the DPO/privacy counsel to validate bases and sign off; flag any high-risk processing that may need a DPIA.

# Notes

The record is wrong if a legal basis is invented to fill a blank, if special-category data is buried in a generic field, or if international transfers are recorded without their safeguard (SCCs/adequacy). Common failure modes: stale retention copied from policy rather than actual system config, processors omitted because they're "just a tool", and treating consent as the default basis. Never decide that a processing activity is lawful or that a basis is valid — that is the DPO/counsel's call; this skill documents and surfaces gaps. Do not use it to authorize a new processing activity or to replace a DPIA for high-risk processing.
