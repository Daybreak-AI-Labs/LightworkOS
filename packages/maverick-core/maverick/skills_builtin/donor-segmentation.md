---
name: donor-segmentation
triggers:
  - segment our donors
  - donor analysis
  - identify major gift prospects
tools_needed:
  - sql_query
  - spreadsheet
---
# What this skill does

Segments a donor base into actionable cohorts for cultivation, then attaches a fit-for-purpose strategy to each. Produces a segment table (recency/frequency/monetary plus capacity signals) and a per-segment cultivation plan the development team can run. Handles donor retention, upgrade, and major-gift prospecting goals.

# Steps

1. Pull the gift history from `sql_query` (donor id, gift date, amount, channel, campaign) and confirm the date range and that recurring/in-kind gifts are flagged. Reconcile the total against a known giving report before trusting the extract.
2. Compute per-donor recency, frequency, and total/largest gift; derive RFM scores or tiers. Layer in available capacity/affinity signals (multi-year consistency, employer match, board/volunteer ties) where data exists — do not impute wealth you cannot source.
3. Define segments (e.g., new, active recurring, lapsing, lapsed, mid-level upgrade candidates, major-gift prospects) with explicit thresholds, and place each donor in exactly one. Size each segment.
4. Attach a cultivation strategy per segment (touch cadence, channel, ask range anchored to giving history, owner) and call out the highest-ROI moves.
5. Report the segment table and strategies in a `spreadsheet`, stating thresholds used, data-quality caveats, and which prospects need human wealth-screening before any major-gift ask.

# Notes

Output is wrong if segments overlap or leave donors unassigned, if ask amounts ignore actual giving history, or if "major gift prospect" rests on imputed wealth rather than evidenced capacity. Cite the query and report you reconciled against; mark inferred capacity as unverified. This is a recommendation — individual solicitation, major-gift asks, and any donor contact are staged for a gift officer to approve; never auto-send. Do not use for grant/foundation pipelines (different cultivation logic) or for compliance reporting.
