---
name: sg-and-a-benchmarking
triggers:
  - sga benchmark
  - cost benchmark
  - opex ratio
tools_needed:
  - web_search
  - spreadsheet
---
# What this skill does

Benchmarks a company's SG&A (and its sub-lines: sales, marketing, G&A) against peer companies and its own history, expressed as a percent of revenue and other normalized ratios. Produces a comparison table that surfaces where spend is above or below peer median and where the gaps are, to guide cost-efficiency decisions.

# Steps

1. Assemble the subject company's SG&A: total and by sub-line, as a % of revenue, for the trailing periods the user provides or that you can source. Cite the source (filing, internal P&L); if sub-line splits aren't available, benchmark at the level you actually have and say so.
2. Identify a defensible peer set (similar industry, scale, business model) and pull each peer's SG&A and revenue via web_search from public filings or reputable financial data. Record the source URL and period for every peer figure; mark any estimate or non-comparable basis as unverified.
3. In the spreadsheet, normalize all companies to the same ratios (SG&A %, S&M %, G&A % of revenue; optionally per-employee or per-customer) and compute peer median and quartiles. Build the subject-vs-peer-vs-own-history comparison.
4. Highlight the largest gaps (lines materially above peer median), quantify the revenue-equivalent of closing each gap to median, and hand off. State the peer set, periods, and any apples-to-oranges caveats explicitly.

# Notes

The benchmark is misleading if periods or accounting bases differ (one peer capitalizes commissions, another expenses them; fiscal years misaligned) or if the peer set is cherry-picked to flatter or punish — disclose peer-selection criteria. A gap to median is a question, not a verdict: structural differences (channel mix, growth stage) can justify higher spend. This is a recommendation/diagnostic; actual cost cuts and headcount actions are decided by leadership. Don't use as a substitute for a zero-based budget when the goal is to rebuild spend from scratch, and never present unsourced peer numbers as fact.
