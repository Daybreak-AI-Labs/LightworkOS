---
name: spend-cube-analysis
triggers:
  - spend cube
  - spend analysis
  - addressable spend
  - analyze spend by category and supplier
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a spend cube from transactional AP/PO data, slicing total spend across the three primary dimensions — category, supplier, and business unit — to expose concentration, fragmentation, and tail spend. Produces a multi-view spend breakdown with quantified savings opportunities (consolidation, maverick-spend leakage, tail rationalization). Findings are analysis for a sourcing team, not committed savings.

# Steps

1. Pull line-level spend via sql_query for the agreed period: amount, supplier (normalized), category, business unit, PO vs. non-PO flag, and contract reference. Reconcile the grand total to a known control figure (GL or AP total); report any unmapped or "uncategorized" spend as a data-quality caveat rather than dropping it.
2. In the spreadsheet, pivot spend by each dimension and the key cross-tabs (category x supplier, category x unit). Compute concentration (top-N supplier share per category), supplier-count-per-category (fragmentation), and tail spend (suppliers below a materiality threshold).
3. Quantify opportunities grounded in the data: consolidation potential where many suppliers serve one category; off-contract / non-PO ("maverick") spend that bypasses negotiated rates; tail-supplier rationalization; and price variance for the same item across units. Size each as a range, stating the assumed savings rate and labeling it estimated, not realized.
4. Report the cube views plus a ranked opportunity list with addressable spend, estimated savings range, and data caveats — handing prioritization and sourcing decisions to the category owner.

# Notes

The analysis is only as good as supplier normalization and category mapping: un-deduplicated supplier names inflate fragmentation, and a large "uncategorized" bucket invalidates category cuts — surface both rather than hiding them. Never present estimated savings as committed or guaranteed; mark the assumed rate. Do not use when the underlying data lacks category/unit tags (the cube collapses to a flat supplier list) or for a single-supplier negotiation where a spend cube adds no signal.
