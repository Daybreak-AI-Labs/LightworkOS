---
name: impairment-trigger-review
triggers:
  - check assets for impairment
  - was there a triggering event
  - asset writedown screen
tools_needed:
  - knowledge_search
  - spreadsheet
---
# What this skill does

Screens a defined asset population (long-lived assets, goodwill, intangibles, or a reporting unit) for the existence of impairment indicators under the applicable framework (ASC 360/350 or IAS 36). Produces an indicator-by-indicator review concluding whether a triggering event exists and whether a recoverability/quantitative test is required. It does NOT measure the impairment loss — it gates whether testing is owed.

# Steps

1. Confirm scope and framework: which assets/units, the reporting date, and US GAAP vs IFRS (drives the indicator list and whether goodwill is annual-plus-trigger or one-step). Pull the carrying amounts and asset register from the spreadsheet — never assume balances.
2. Use knowledge_search to retrieve the governing standard's indicator list (external: market cap below book value, adverse market/rate/legal/competitive changes; internal: physical damage, obsolescence, plans to dispose, worse-than-projected cash flows, current-period operating loss combined with a history of losses). Cite the standard paragraph for each indicator pulled.
3. For each indicator, gather evidence from the period (budgets-vs-actuals, market data, restructuring plans, customer losses) and mark present / absent / unknown. In the spreadsheet, flag any asset where market cap or recent cash flows fall below carrying amount.
4. Conclude per asset/unit: trigger present (test required), no trigger (document negative assurance), or unknown (data gap). Report the indicator matrix, list assets routed to quantitative testing, and state every assumption and unverified input; recommend the next step — do not record any writedown.

# Notes

Output is wrong if you conflate a trigger with the loss measurement, apply the wrong framework, or treat a single soft indicator as dispositive — indicators are weighed in aggregate. Mark any market or forecast input you could not source as unverified rather than inferring it. Goodwill and indefinite-life intangibles still require their annual test even with no trigger; don't let a clean trigger review suppress that. This is a screening/recommendation; the impairment conclusion and any journal entry are decided and booked by a qualified human (accounting/controller), never by the agent.
