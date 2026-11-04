---
name: bottoms-up-revenue-forecast
triggers:
  - bottoms up forecast
  - revenue build
  - driver forecast
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Builds a bottoms-up revenue forecast by decomposing revenue into operational drivers (units, customers, ARPU, churn, conversion, price) rather than a top-line growth rate. Grounds each driver in historical actuals, projects it forward, and recombines into a monthly revenue build with explicit, auditable assumptions.

# Steps

1. Pull historical actuals via sql_query: revenue by month plus the underlying drivers (new customers, churn, active accounts, average price, units sold, conversion rate) for at least the trailing 12-24 months. Cite the table/source; if a driver isn't recorded, mark it as an assumption rather than fabricating a trend.
2. Derive each driver's recent run-rate and trend (e.g. monthly new logos, gross/net churn %, ARPU) and pick a forward path per driver — flat, trended, or stepped — stating the rationale for each. Distinguish observed history from forecast assumption.
3. In the spreadsheet, rebuild revenue from the drivers: active base = prior base + new - churned; revenue = active base x ARPU (plus any usage/expansion line). Phase monthly across the forecast horizon and reconcile the first forecast month against the last actual for continuity.
4. Roll up to quarterly/annual totals, add a scenario toggle (base / conservative / upside via driver overrides), and hand off. List every driver assumption and its source, and flag which drivers move the forecast most.

# Notes

The forecast is wrong if drivers are double-counted (e.g. expansion baked into both ARPU and a separate upsell line) or if the active-base recursion silently lets churn exceed the base. Reconcile to actuals before trusting it — an unreconciled build that doesn't tie to the last real month is unreliable. Driver projections are estimates, not commitments; revenue recognition and bookings-vs-revenue timing are decided by Finance. Don't use for a quick top-down sanity check (use a growth-rate model) or when no driver-level history exists to ground the build.
