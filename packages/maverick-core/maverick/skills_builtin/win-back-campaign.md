---
name: win-back-campaign
triggers:
  - win back lapsed customers
  - reactivation campaign
  - re-engage churned customers
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Designs a win-back campaign for lapsed/churned customers: defines lapse segments from real account data, matches each to an offer and message, and lays out cadence and success metrics. Produces a runnable campaign plan plus the segment queries, not a generic email blast.

# Steps

1. Define "lapsed" precisely (e.g. no purchase/login in N days, subscription expired) and confirm the window with the requester. Pull the population via `sql_query` against the customer/orders tables; report counts per candidate segment. Never estimate segment sizes — query them.
2. Segment by churn driver and value: lapse recency, prior spend/tier, and known reason if captured. Use `knowledge_search` for prior win-back results, brand/offer guardrails, and discounting policy. Exclude do-not-contact, recent unsubscribes, and active accounts.
3. Match each segment to an offer (incentive vs reactivation feature/value reminder) sized to expected margin, and draft a short message per segment with a clear CTA. Define cadence (touch count, spacing, stop conditions) and the control/holdout.
4. Specify success metrics (reactivation rate, incremental revenue vs holdout, unsubscribe rate) and report the plan with segment SQL, offer rationale, and assumptions. Stage send/offer approval for a human.

# Notes

Output is wrong if segments are guessed instead of queried, offers breach discount policy or exceed margin, or suppression lists (unsubscribes, do-not-contact) are ignored — that risks compliance and brand damage. Cite the query and data date; mark any unsourced assumption. Sending, applying discounts, and final audience selection are irreversible and require human sign-off. Don't use this for still-active customers (use retention/upsell instead).
