---
name: merchandising-assortment-plan
triggers:
  - assortment plan
  - merchandising plan
  - sku rationalization
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a category assortment plan for a retail merchant: sets breadth (how many distinct items/subcategories), depth (units/facings per item), and a role for each SKU (traffic-driver, profit, image, fill-in), and recommends keep/cut/add decisions. Output is a SKU-level plan grounded in sales, margin, and inventory performance.

# Steps

1. Pull the category's SKU-level performance via sql_query: units, revenue, margin, sell-through, weeks-of-supply, and store coverage over a stated period; confirm the date range and store set, and flag SKUs with sparse or partial-period data as unreliable.
2. Rank and segment SKUs (e.g., ABC by margin-weighted velocity) in spreadsheet, assign each a role (traffic-driver, profit, image, fill-in), and identify duplication, dead stock (low sell-through + high WOS), and gaps vs. demand or competitive benchmarks.
3. Set breadth and depth targets per subcategory consistent with shelf/space and inventory constraints, then translate into keep / cut / add recommendations — tie each cut to its performance evidence and each add to the gap it fills.
4. Assemble the SKU-level plan with projected impact (sales, margin, inventory turns) and hand off, stating the data window, role definitions, space assumptions, and which adds are unverified (no sales history) and require buyer judgment.

# Notes

Wrong if cuts ignore basket/halo effects (a low-margin SKU that drives the trip), seasonality is averaged away, or supplier terms and space constraints are omitted — the plan then optimizes a line item while hurting the category. This plan recommends; final keep/cut/add, buy quantities, and supplier commitments are buyer/merchant decisions, and delists are operationally hard to reverse, so stage them for human sign-off. Do not use for new-store or pure new-brand assortments where there is no sales history to rationalize against — that is a clean-sheet exercise.
