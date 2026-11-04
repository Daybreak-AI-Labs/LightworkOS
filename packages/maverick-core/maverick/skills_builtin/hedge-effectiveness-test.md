---
name: hedge-effectiveness-test
triggers:
  - hedge effectiveness test
  - hedge accounting documentation
  - ASC 815 effectiveness
tools_needed:
  - spreadsheet
  - knowledge_search
---
# What this skill does

Tests whether a designated hedging relationship qualifies for hedge accounting and documents the result. Produces a hedge-effectiveness test (prospective and/or retrospective) with the quantitative measure, the pass/fail conclusion against the standard's threshold, and the supporting designation documentation.

# Steps

1. Retrieve the hedge designation memo and instrument terms: hedged item, hedging instrument (notional, rate/strike, maturity), risk being hedged, hedge type (fair value / cash flow / net investment), and the documented effectiveness method. Use knowledge_search to pull the applicable standard's criteria (e.g. ASC 815 / IFRS 9) and cite the specific guidance; mark any term you inferred as `ASSUMED`.
2. Confirm the qualifying conditions are documented at inception (formal designation, risk management objective, identified hedged item and instrument, stated method). Flag any missing element — without it the relationship fails regardless of the numbers.
3. In the spreadsheet, run the effectiveness measure per the documented method: compare changes in fair value / cash flows of the hedging instrument against the hedged item (e.g. dollar-offset ratio or regression R-squared/slope), and compute any ineffectiveness to record in P&L.
4. Conclude pass/fail against the threshold (e.g. highly effective), document the inputs, method, and result, and report the workbook path, the conclusion, the cited standard, and all `ASSUMED` terms for accounting review.

# Notes

Wrong if the method tested differs from the method documented at designation (you cannot switch methods retroactively), if the critical-terms-match shortcut is claimed when terms don't actually match, or if ineffectiveness is computed but not carried to P&L. Effectiveness conclusions are accounting judgments — cite the standard, never assert a threshold from memory; if designation documentation is incomplete, report that as a disqualifier rather than passing the test. This skill drafts the test and conclusion; de-designation, re-designation, or booking ineffectiveness are irreversible accounting actions a qualified human must approve. Do not use to value the derivative itself or for undesignated/economic hedges (those go straight to P&L with no effectiveness test).
