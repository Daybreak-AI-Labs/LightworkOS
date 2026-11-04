---
name: non-gaap-reconciliation
triggers:
  - reconcile GAAP to non-GAAP
  - build the adjusted EBITDA bridge
  - Reg G reconciliation table
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Builds a GAAP-to-non-GAAP reconciliation for a reporting period: starts from the most directly comparable GAAP measure, itemizes each adjustment, and lands on the non-GAAP measure (Adjusted EBITDA, adjusted EPS, free cash flow). Produces a Reg-G-compliant bridge table plus a documented rationale for every add-back. Handles the goal class of "show how we get from reported to adjusted, defensibly."

# Steps

1. In the spreadsheet, anchor each non-GAAP measure to its most directly comparable GAAP line (e.g. Adjusted EBITDA -> GAAP net income). Pull the GAAP figures from the reported financials and cite the source statement and period.
2. Itemize every adjustment on its own row with sign, amount, and a one-line basis (stock-based comp, restructuring, amortization of intangibles, impairment, one-time items). Use knowledge_search to confirm each add-back matches prior-period treatment and the company's disclosed non-GAAP policy — consistency is the integrity check.
3. Verify the bridge foots: GAAP measure + adjustments = stated non-GAAP measure, every period and segment. Flag any adjustment that recurs (Reg G disfavors labeling recurring costs "one-time") or that nets a normal cash operating cost out of the picture.
4. Output the reconciliation table with the GAAP measure presented with equal-or-greater prominence, the rationale column, and a flagged list of judgment calls. Report and state assumptions; controller/auditor and disclosure counsel sign off before publication.

# Notes

Wrong if the bridge doesn't foot, if the comparable GAAP measure is missing or buried (Reg G requires equal prominence), or if recurring costs are dressed up as non-recurring. Never invent an adjustment or change prior-period methodology silently — inconsistency across periods is the classic finding. This is a draft for review: SEC non-GAAP rules are interpretive and the auditor/legal sign-off is the gate. Not for tailoring adjustments to hit a target number — that inverts the purpose.
