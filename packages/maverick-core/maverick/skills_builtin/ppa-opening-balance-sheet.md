---
name: ppa-opening-balance-sheet
triggers:
  - purchase price allocation
  - asc 805
  - acquisition accounting
  - business combination accounting
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

Walks a business combination through purchase price allocation under ASC 805: measure the consideration transferred, identify and fair-value the acquired identifiable assets (including intangibles) and assumed liabilities with step-ups, and back into residual goodwill, then track measurement-period adjustments. The goal class is "build the opening balance sheet for an acquisition" with the earn-out remeasurement called out as the audit hot spot.

# Steps

1. Read the deal documents and target financials with read_file and confirm the acquirer, the acquisition date, and the total consideration transferred (cash, equity at fair value, and contingent consideration / earn-out at acquisition-date fair value).
2. Identify the acquired identifiable assets and assumed liabilities, fair-valuing each: recognize identifiable intangibles separately (customer relationships, technology, trademarks, non-competes) and apply step-ups to tangible assets; search knowledge_search for the ASC 805 recognition criteria when an item's separability is unclear.
3. Compute goodwill as the residual: consideration plus non-controlling interest and any previously held equity interest, less the net identifiable assets acquired. Confirm goodwill is positive (a negative residual is a bargain purchase requiring a reassessment, then a gain).
4. Track measurement-period adjustments (up to one year) as new facts about acquisition-date conditions emerge, and remeasure the contingent consideration each reporting period through earnings — flagging the earn-out remeasurement for explicit review.

# Notes

Earn-out / contingent-consideration remeasurement is the audit hot spot: it is fixed at fair value on the acquisition date but re-marked through P&L afterward, and confusing measurement-period adjustments (which adjust goodwill) with post-acquisition remeasurement (which hits earnings) is a frequent error. Do not forget to recognize identifiable intangibles separately — sweeping them into goodwill is a classic miss. A bargain purchase (negative goodwill) is a red flag to recheck the fair values before booking a gain. This skill drafts the allocation for accounting/valuation review and audit; it does not finalize the financial statements or post entries.
