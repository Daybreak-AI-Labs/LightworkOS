---
name: sales-tax-nexus-determination
triggers:
  - nexus
  - sales tax obligation
  - where do we owe tax
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Assesses where a business has a sales/use-tax or VAT collection obligation by testing each jurisdiction for physical and economic nexus against its specific thresholds. Produces a nexus matrix by jurisdiction showing the triggering activity, the threshold, the company's measured activity, and a registered/monitor/register-now status.

# Steps

1. Pull the company's by-jurisdiction activity from sales and operations data via `spreadsheet`: revenue and transaction counts per state/country, plus physical footprint signals (employees, inventory/3PL or FBA locations, offices, traveling reps, affiliates). Confirm taxability of the product/service category.
2. Retrieve current nexus rules per jurisdiction via `knowledge_search`: physical-presence triggers and economic-nexus thresholds (e.g., post-Wayfair U.S. state revenue/transaction limits, marketplace-facilitator rules, VAT/OSS registration thresholds abroad). Record the source and effective date; mark any threshold you cannot confirm as unverified.
3. For each jurisdiction, compare measured activity to the threshold over the relevant lookback period. Determine whether economic nexus, physical nexus, or neither applies, and whether marketplace-facilitator rules already shift the collection duty off the seller.
4. Build the matrix: jurisdiction, nexus type, threshold, measured activity, trigger date, and status (already registered / approaching / obligation triggered). Flag jurisdictions with crossed thresholds but no registration as exposure with an estimated back-tax window. Report findings and recommend registration order; stage registrations and voluntary-disclosure agreements for a human, never auto-file.

# Notes

Output is wrong if transaction-count and revenue tests are conflated (many states use either/or), if marketplace-facilitated sales are double-counted against the seller's own threshold, or if stale thresholds are used (states change them; cite effective dates). Physical presence (inventory in a fulfillment warehouse) creates nexus even below economic thresholds — do not omit it. Registering creates a permanent filing obligation and can surface prior exposure: treat registration and VDA decisions as irreversible and route to a tax professional. Do not use for income-tax nexus (different standard) or for exempt/resale-only sellers without confirming exemption certificates.
