---
name: unclaimed-property-review
triggers:
  - unclaimed property
  - escheat
  - dormancy
tools_needed:
  - knowledge_search
  - sql_query
---
# What this skill does

Assesses a company's unclaimed-property (escheat) exposure across property types (uncashed checks, AP/AR credits, payroll, gift cards) and holder jurisdictions. Produces an escheatment review that ages items against each state's dormancy period, estimates the reportable liability, and lays out a filing/due-diligence plan. Output is a draft exposure assessment for tax/legal review.

# Steps

1. Query the source ledgers via sql_query for candidate items: outstanding/uncashed checks, unapplied credits, and stale liabilities, with their issue/last-activity date, amount, owner address (state of last known address), and property type. Use the actual records — do not synthesize balances; flag any item missing a date or owner state.
2. Use knowledge_search against the applicable state unclaimed-property statutes to pull the dormancy period and reporting due date by property type and jurisdiction (and the priority rules: state of owner's last-known address first, holder's state of incorporation second). Cite each state's statute.
3. Age each item against its jurisdiction's dormancy period using sql_query, flagging items that have reached or passed dormancy, and total the estimated reportable liability by state and property type. Mark items with no last-known address (defaulting to state of incorporation) distinctly.
4. Hand off the review with a filing plan: states triggered, report due dates, required owner due-diligence (notice) steps, and any voluntary-disclosure consideration. State assumptions (records cutoff, address completeness) and list items needing manual research.

# Notes

The review is wrong if dormancy is applied from issue date when the statute keys off last-activity date, or if priority rules are ignored (owner-address state first, then incorporation state) — both misroute the liability. Missing last-known addresses materially shift exposure to the incorporation state; do not silently default them without flagging. Cite each state statute; periods differ by property type and year. This is a draft assessment: actual escheat filings, due-diligence mailings, and any voluntary-disclosure agreement are irreversible and decided by tax/legal. Do not use as a substitute for a formal VDA scoping where audit risk is already active.
