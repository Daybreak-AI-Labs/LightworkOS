---
name: customer-profitability
triggers:
  - customer profitability
  - cost to serve
  - segment margin
  - which customers actually make us money
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Measures true profitability by customer (and segment) after allocating cost-to-serve — not just gross margin. Produces a customer-profitability analysis that attributes revenue, product margin, and service costs (orders, returns, support, freight, payment terms, discounts) to each account, ranks accounts, and surfaces unprofitable customers with the drivers behind them.

# Steps

1. Pull per-customer revenue, units, and product-level COGS from the transaction source via sql_query for the period. Separately pull cost-to-serve drivers: order/line counts, returns, support tickets or service hours, freight, payment-terms days, and discounts/rebates. Confirm a stable customer key joins all sources; flag any cost pool you cannot attribute.
2. Compute gross margin per customer (revenue - COGS - discounts). Then allocate each service cost pool using a defensible driver (e.g. fulfillment cost per order x order count; support cost per ticket x tickets; freight actual; cost of terms = AR balance x cost of capital). State each allocation basis explicitly.
3. In the spreadsheet, build the bridge from gross margin to net customer profit and rank accounts. Identify negative-margin and thin-margin accounts, and decompose why (high service intensity, deep discounts, high returns, long terms). Roll up to segment to compare cost-to-serve patterns.
4. Report the profitability ranking, the unprofitable tail with root-cause drivers, and recommended actions (re-pricing, minimum order quantities, terms tightening, channel shift). State allocation assumptions and data gaps. Recommend only — account-level commercial changes are decided by a human owner.

# Notes

Output is wrong if cost-to-serve is allocated by revenue alone (it just re-scales gross margin and hides the service-intensive accounts the analysis exists to find) — use activity drivers. Unattributable overhead should be left out or shown as a separate "below the line" layer, not smeared. Returns and credit notes must net against the right customer/period. Do not use when only revenue (no COGS or service-driver data) exists, or for one-off deal economics. Repricing or firing a customer is irreversible commercially; stage as a recommendation for human decision.
