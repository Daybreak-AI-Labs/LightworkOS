---
name: indirect-tax-determination
triggers:
  - indirect tax
  - vat treatment
  - tax determination
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Determines the indirect-tax treatment (VAT/GST/sales-and-use) of a defined set of transaction types: taxable, zero-rated, exempt, or out-of-scope, with the applicable rate and place-of-supply/sourcing rule. Produces a tax-determination matrix mapping each transaction type to its treatment, rate, and the rule citation. Output is a draft determination for indirect-tax review and system configuration.

# Steps

1. Enumerate the transaction types in scope from the engagement record: product/service category, supplier and customer jurisdictions, B2B vs B2C, and any registration footprint. Use the real transaction list — do not invent flows; flag categories with insufficient facts to determine.
2. Use knowledge_search against the applicable indirect-tax authority (local VAT/GST act, sales-and-use nexus and rate rules, prior rulings on file) to resolve the place of supply/sourcing and the treatment for each type. Cite each rule by jurisdiction and section.
3. Build the determination matrix in a spreadsheet: one row per transaction type with columns for jurisdiction, place-of-supply rule, treatment (taxable/zero/exempt/out-of-scope), rate, and citation. Mark any rate or treatment not confirmed against a source as unverified.
4. Hand off the matrix to the indirect-tax lead for review and tax-engine configuration, stating assumptions (registration status, customer status evidence) and listing every row left as unverified or fact-dependent.

# Notes

The matrix is wrong if place-of-supply is skipped (it drives which jurisdiction's rate applies) or if a rate is asserted without a cited source — mark unconfirmed rates unverified, never guess. B2B vs B2C and the customer's registration/exemption status change the answer; do not collapse them. This is a draft determination: live tax-engine changes and any customer-facing rate decision are approved by the indirect-tax owner. Do not use for income/direct taxes, or where the registration footprint is unknown and would change nexus.
