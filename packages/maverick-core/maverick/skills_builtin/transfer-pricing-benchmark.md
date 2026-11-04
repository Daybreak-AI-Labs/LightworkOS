---
name: transfer-pricing-benchmark
triggers:
  - transfer pricing
  - intercompany pricing
  - arm's length
tools_needed:
  - web_search
  - spreadsheet
---
# What this skill does

Defends an intercompany transaction (goods, services, royalties, or intra-group financing) by selecting an arm's-length pricing method and building a comparables benchmark. Produces a transfer-pricing analysis: tested party, chosen method, comparable set, and the resulting arm's-length range with the company's position located inside it.

# Steps

1. Characterize the controlled transaction from the intercompany agreement and functional facts via `spreadsheet`: identify the tested party (least complex entity), the functions/assets/risks each side bears, and the transaction type and flow. State the relevant guidance (OECD Guidelines / U.S. 482) and tax years.
2. Select the most appropriate method (CUP, resale price, cost plus, TNMM/CPM, or profit split) given the transaction type and data availability; record why rejected methods do not fit. Define the profit-level indicator if using TNMM (e.g., operating margin, Berry ratio, full-cost markup).
3. Build the comparable set: search public company databases and filings via `web_search` for independent companies with similar functions and geography; apply quantitative and qualitative screens and document rejections. Pull 3 years of financials and compute the PLI for each comparable in `spreadsheet`.
4. Calculate the arm's-length range (interquartile range when reliability requires it) and locate the tested party's actual result against it. If outside the range, quantify the adjustment to the median. Report method, comparables with screening trail, the range, and the conclusion; mark any unsourced comparable as unverified and flag adjustments for tax-advisor sign-off before any filing or true-up.

# Notes

Output is wrong if the most-complex entity is tested, if comparables are not truly independent or differ in functions/risk, or if the search criteria are not reproducible (regulators reject black-box comparable sets). Multi-year data smooths cyclicality; a single year overstates precision. This is documentation/defense support, not a binding determination — staging an actual price change or year-end adjustment is an irreversible tax position requiring a qualified advisor and proper agreements. Do not use where an APA or local file already fixes the method, or for jurisdictions whose rules diverge from OECD without noting the difference.
