---
name: compensation-band-design
triggers:
  - design comp bands
  - build salary bands
  - create a pay structure
tools_needed:
  - spreadsheet
  - web_search
---
# What this skill does

Designs compensation bands for a set of roles by anchoring each role to external market data and deriving internal pay ranges (min/mid/max). Produces a banded pay structure spreadsheet with market anchors, range spreads, and overlap between adjacent bands, ready for compensation-committee review.

# Steps

1. Pull the in-scope roles, levels, and locations from the requester or the HRIS export; confirm the target market positioning (e.g. 50th percentile) and pay philosophy before pricing anything.
2. Source market data per role/level/geo via web_search (published surveys, BLS, Levels.fyi, Radford summaries) — record the source, percentile, and date for every anchor; mark any role with no credible source as UNPRICED rather than guessing.
3. In spreadsheet, set each band's midpoint to the chosen percentile anchor, apply a defensible range spread (commonly 40-50% min-to-max for ICs, narrower at senior levels), and check that adjacent bands overlap ~20-40% with monotonically rising midpoints — flag inversions.
4. Hand off the spreadsheet with a per-role source table, the assumptions (positioning, spread, geo differentials), and an explicit list of UNPRICED roles needing more data; recommend, do not finalize — band sign-off is a human comp decision.

# Notes

Output is wrong if anchors blend mismatched scopes (title-matching instead of job-content matching), mix survey dates/effective periods, or ignore geo and currency normalization. Stale survey data (>12 months) understates ranges in a moving market — date every source. Do not use for individual offer decisions or equity/bonus design (cash bands only). Bands are a recommendation; pricing live offers against them is a human call.
