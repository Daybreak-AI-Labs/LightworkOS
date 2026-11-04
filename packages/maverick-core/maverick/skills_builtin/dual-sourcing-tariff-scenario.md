---
name: dual-sourcing-tariff-scenario
triggers:
  - model dual sourcing
  - tariff exposure scenario
  - reshoring analysis
  - landed cost scenario
tools_needed:
  - read_file
  - spreadsheet
  - knowledge_search
---
# What this skill does

This skill models the landed cost and supply risk of sourcing options — single-source vs dual-source vs reshore/nearshore — under tariff and disruption scenarios, so procurement can weigh resilience against cost. It builds a full landed-cost stack per option (unit cost, freight, duties/tariffs, lead-time carrying cost) and overlays scenarios (tariff increase, port/route disruption, supplier failure, FX swing), then ranks the options on a cost-vs-resilience tradeoff with the assumptions made explicit. The output is a scenario model and ranked tradeoff staged for the sourcing decision-maker; it does not place orders, award business, or commit to a supplier.

# Steps

1. Use read_file and knowledge_search to gather the inputs per candidate source: unit price, country of origin, applicable HS-code duty/tariff rate, freight and logistics cost, typical and worst-case lead time, MOQ, and any qualification cost to add a second source or reshore. Confirm the current tariff rates and any pending changes, citing the source.
2. Use spreadsheet to build the landed-cost stack for each option: unit cost + inbound freight + duties/tariffs + tariff surcharges + inventory carrying cost driven by lead time, yielding a true landed unit cost (not just FOB price) per sourcing strategy.
3. Layer the scenarios: a baseline plus stress cases (tariff +X%, lead-time disruption, single-source supplier outage, FX move). For each option × scenario, recompute landed cost and capture the resilience dimension — does the strategy keep supply flowing when one node fails? Dual-source and reshore typically cost more at baseline but degrade less under stress; quantify that.
4. Rank the options on the cost-vs-resilience tradeoff with a clear table (baseline landed cost, stressed landed cost, supply-continuity under each scenario, qualification cost, assumptions), and stage it for the sourcing decision-maker. Mark that supplier award and order commitments are human decisions; this is a decision-support model.

# Notes

Model landed cost, not unit price: a cheaper FOB source can be the more expensive landed option once tariffs, freight, and lead-time carrying cost are in — comparing sticker prices is the classic error this skill exists to prevent. Resilience is the second axis and usually trades against baseline cost: dual-sourcing/reshoring costs more when nothing goes wrong and far less when something does, so present both the baseline and the stressed numbers rather than a single figure. Tariff rates change and depend on HS classification and origin rules — cite the rate's source and date, and flag pending changes, since a stale rate invalidates the whole stack. Don't omit qualification/switching cost for adding a source. This skill models and ranks; it does not award business, place orders, or commit to a supplier — those are human decisions on the analysis.
