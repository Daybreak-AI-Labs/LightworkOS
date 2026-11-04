---
name: rfm-segmentation
triggers:
  - rfm
  - customer segmentation
  - who are our best customers
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Segments customers by Recency (time since last purchase), Frequency (purchase count), and Monetary value (total or average spend) over a defined window. Produces a scored RFM map: each customer assigned R/F/M scores and a named segment (e.g. Champions, At-Risk, Hibernating), with a recommended treatment per segment and segment-level size and value totals.

# Steps

1. Fix the window and the analysis "as-of" date with the requester (recency is measured against it), the transaction grain, and how monetary is defined (gross, net, or margin). Confirm whether to score all customers or only those active in the window.
2. With `sql_query`, compute per customer: days since last order (recency), order count (frequency), and summed monetary value over the window. Validate against known totals (customer count, total revenue) before scoring.
3. In `spreadsheet`, score each dimension into quantiles (typically 1-5; quintiles, not fixed thresholds, so the split adapts to the data — note that ties at bucket edges can skew small populations). Lower recency-days = higher R score. Concatenate to an RFM code and map codes to named segments using an explicit, documented rule table.
4. Summarize segment counts, share of customers, and share of revenue, and attach a recommended treatment per segment (e.g. win-back for At-Risk, VIP/retain for Champions). Report the map and the scoring rules used; state assumptions (window, as-of date, quantile method) and hand off. Treatments are recommendations — a human approves any spend, discount, or contact action.

# Notes

Output is wrong if recency is measured against the wrong as-of date, if monetary mixes refunds in or out inconsistently, or if quantile cuts are applied to a population too small to split into 5 stable bins (collapse to 3 then). One-time buyers and outlier whales distort M — consider log or capping and disclose it. Segment names are a convention, not a label in the data; keep the code→name table visible so the mapping is auditable. Do not auto-execute campaigns, suppressions, or discounts from this output; it stages segments and suggested treatments for human decision.
