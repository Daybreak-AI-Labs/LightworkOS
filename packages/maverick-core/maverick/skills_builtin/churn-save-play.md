---
name: churn-save-play
triggers:
  - churn save
  - at-risk account
  - retention play
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Builds a churn-save playbook for a specific at-risk account: the evidenced churn drivers, a fitted retention offer, and an outreach script the CSM can run. Produces one playbook document that diagnoses WHY the account is at risk and stages the intervention. It recommends an offer; it does not approve discounts or send the outreach.

# Steps

1. Quantify the risk with `sql_query`: pull usage trend, login/activity decline, support ticket volume and sentiment, NPS/CSAT history, payment/renewal status, and seats active vs. licensed for the named account. Record the query window and as-of date.
2. Identify the churn DRIVERS from the data plus `knowledge_search` over notes/tickets/QBRs — rank them (e.g., low adoption, unresolved escalation, champion departed, budget/price, competitor) and cite the signal behind each. Distinguish measured drivers from inferred ones.
3. Fit a retention offer to the dominant driver (enablement/training for adoption gaps; escalation + exec sponsor for service failures; right-sizing or term/discount for price — flagged as requiring approval). State the cost/concession and that any discount or commercial change needs human sign-off.
4. Draft the outreach script: opener acknowledging the specific signal, the offer, and a clear next step (call booked). Report the playbook with drivers, offer, and script, stating assumptions and which drivers are inferred; hand off — do not send or commit the offer.

# Notes

Wrong if drivers are asserted without the underlying metric or note, or if it offers a discount as if pre-approved — concessions are always staged for a human. A save play built on stale data misfires; always state the data window. Don't use for healthy accounts (no risk signal) or for involuntary churn (failed payment / hard contract end) where the play is billing remediation, not retention. Never auto-send the script or modify the subscription.
