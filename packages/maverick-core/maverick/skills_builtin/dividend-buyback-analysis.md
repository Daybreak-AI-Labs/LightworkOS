---
name: dividend-buyback-analysis
triggers:
  - analyze our dividend vs buyback options
  - return of capital scenarios
  - how much can we afford to pay out
tools_needed:
  - spreadsheet
---
# What this skill does

Analyzes return-of-capital choices (initiate/raise a dividend, special dividend, or share repurchase) against the firm's actual capacity. Produces a payout analysis: capacity ceiling derived from free cash flow and liquidity, a side-by-side of dividend vs buyback under base/downside/upside scenarios, and the resulting per-share and balance-sheet effects.

# Steps

1. Pull the real inputs into the spreadsheet: trailing and projected FCF, cash and revolver availability, net leverage and any covenant headroom, current shares outstanding, share price, and existing dividend run-rate. Cite the source statement/period for each; mark any forecast figure as unverified.
2. Compute payout capacity: distributable FCF after committed capex/debt amortization, minimum-cash buffer, and covenant-implied max leverage. State the binding constraint (liquidity, leverage, or policy) explicitly.
3. Model the options under base/downside/upside scenarios — for buybacks, accretion to EPS at a range of execution prices; for dividends, yield, payout ratio, and the implied multi-year commitment (dividends are sticky, buybacks are flexible). Show pro-forma leverage and cash after each.
4. Report a recommendation matrix with the capacity ceiling, scenario outcomes, and the trade-off (flexibility vs signaling). State assumptions and flag that capital-return authorization is a board decision — stage, do not execute.

# Notes

Wrong if FCF is overstated (gross vs after committed capex/amortization) or if the minimum-cash and covenant constraints are omitted — that inflates capacity. Buyback accretion is sensitive to execution price; always show a range, never a point estimate. Treating a special dividend as repeatable, or a buyback as a permanent commitment, misframes the choice. This is decision support only: actual authorization, sizing, and timing are board/Treasury decisions. Do not use for tax-structuring advice or for issuers under a blackout or material-nonpublic-information restriction.
