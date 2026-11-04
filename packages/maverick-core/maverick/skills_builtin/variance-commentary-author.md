---
name: variance-commentary-author
triggers:
  - variance commentary
  - management commentary
  - board narrative
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Authors management variance commentary for a reporting period: a concise narrative that explains each material budget-vs-actual (or prior-period) variance in terms of its real drivers and the actions being taken. Produces board- or exec-ready prose tied to numbers pulled from the ledger, not invented color.

# Steps

1. Pull actuals, budget/forecast, and prior-period figures per account or cost center via `sql_query`; compute absolute and percent variance and rank by magnitude.
2. Apply a materiality threshold (dollar floor AND percent floor) to select the lines worth commenting on; everything below the threshold rolls into an "other, immaterial" line.
3. For each material variance, identify the driver from underlying data (volume vs rate, timing, one-offs, FX) and pull stated mitigations or context via `knowledge_search` over prior commentary, board notes, and ops updates. Mark any driver you cannot source as "unverified — confirm with owner."
4. Draft commentary per line (variance, driver, action/outlook), reconcile the sum of explained variances back to the total, and hand off the draft noting the materiality threshold used and any unverified drivers flagged for owner sign-off.

# Notes

Output is wrong if explained variances don't sum to the reported total, if a driver is asserted without a data or source basis, or if "favorable/unfavorable" sign is flipped (watch contra accounts and cost vs revenue). Never fabricate a cause to fill a gap — flag it. This is a draft for a controller/CFO to approve; do not publish to a board deck unattended. Not for ad-hoc one-line variance questions where full commentary is overkill.
