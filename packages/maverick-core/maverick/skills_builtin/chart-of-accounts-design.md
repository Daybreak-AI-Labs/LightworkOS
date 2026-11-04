---
name: chart-of-accounts-design
triggers:
  - chart of accounts
  - coa design
  - account structure
  - rationalize our accounts
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Designs a new chart of accounts (COA) or rationalizes an existing one for an entity, producing a hierarchical account structure (segments, ranges, natural accounts) plus a mapping table from old accounts to new. Output is a spreadsheet the controller can review before any ledger reconfiguration.

# Steps

1. Pull the existing COA (trial balance export or ledger dump) and the entity's reporting requirements via `knowledge_search` (GAAP/IFRS basis, statutory needs, segment/dimension model, parent rollups). Do not assume an industry template — confirm the basis with the source.
2. Classify every existing account into the five statement categories and identify defects: duplicates, dormant accounts (no activity N periods), overloaded accounts, and missing dimensions. Mark each unverified inference explicitly.
3. Draft the target structure in `spreadsheet`: segment/range scheme (e.g. 1000s assets, 2000s liabilities), natural-account list with descriptions, and dimension definitions (cost center, department) kept out of the natural account.
4. Build an old-to-new mapping row per existing account (old number, new number, action: keep/merge/retire, rollup parent). Flag every merge/retire as requiring sign-off, report open questions, and hand off the workbook — state which mappings are inferred vs. source-confirmed.

# Notes

Wrong if accounts are mapped many-to-one without preserving prior-period comparability, or if dimensions are baked into account numbers (defeats reporting flexibility). Retiring or merging accounts is irreversible in a live ledger — stage the mapping for a human; never reconfigure the GL directly. Do not use for a single new account request (that's a simple add, not a redesign). Confirm the accounting basis from a cited source; never fabricate statutory requirements.
