---
name: nrr-bridge-build
triggers:
  - build nrr bridge
  - net revenue retention waterfall
  - grr decomposition
tools_needed:
  - sql_query
  - spreadsheet
  - read_file
---
# What this skill does

This skill constructs a net revenue retention (NRR) waterfall that decomposes period-over-period recurring revenue into starting ARR, new, expansion, contraction, and churn, and derives both NRR and gross revenue retention (GRR). It pulls from billing and CRM, reconciles the result back to the finance system of record, and explicitly labels every cohort definition and assumption so the numbers are auditable. It builds a staged model for review; it does not alter billing data or post figures to a board deck unattended.

# Steps

1. Use read_file to load the agreed metric definitions (cohort window, what counts as recurring, how to treat one-time fees, currency, downgrade vs churn boundary) so the bridge matches finance's conventions, not ad-hoc ones.
2. Use sql_query to extract starting-of-period and end-of-period recurring revenue per account from billing, plus expansion/contraction/churn events from CRM, joining on a stable account key and excluding non-recurring line items.
3. Build the waterfall in spreadsheet: Starting ARR + New + Expansion - Contraction - Churn = Ending ARR; compute GRR (excludes new and expansion) and NRR (includes expansion) on the retained base, and label each bucket with its exact rule.
4. Reconcile Ending ARR and total recurring revenue against the finance system of record; surface any variance over a set materiality threshold as a flagged reconciliation line, and stage the bridge with an assumptions tab for review — do not finalize until the variance is explained.

# Notes

NRR is notoriously definition-sensitive: the same data yields different NRR depending on cohort timing, whether expansion is capped at churn, and gross-vs-net of currency — so the assumptions tab is mandatory, not optional. Never silently net churn against expansion to flatter the number. If billing and the system of record disagree beyond materiality, report the gap as a finding rather than forcing a tie-out. Keep New separate from Expansion: folding new logos into expansion inflates NRR and is a common, misleading error.
