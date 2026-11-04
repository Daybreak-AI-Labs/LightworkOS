---
name: sensitivity-tornado
triggers:
  - tornado chart
  - sensitivity analysis
  - what drives the result the most
tools_needed:
  - spreadsheet
  - pandas_query
---
# What this skill does

Ranks the inputs of a model by how much an outcome moves when each is swung one at a time across a defined low/high range, holding all others at base. Produces a tornado chart and the underlying table showing each input's downside and upside impact on the outcome, sorted by total swing.

# Steps

1. Fix the outcome cell/formula and its base-case value. Enumerate candidate input variables and get a low/high bound for each from a sourced range (historical min/max, +/- a stated %, or scenario inputs) — never invent ranges; mark assumed bounds as unverified.
2. For each input, set it to its low then its high while all others stay at base, recording the resulting outcome for both. One variable moves per run — confirm no co-movement leaks in.
3. Compute each input's downside delta, upside delta, and total swing (|high - low| impact). Sort descending by total swing.
4. Render the tornado (widest bar on top) and return the ranked table with base value, low/high outcomes, and deltas. Report the top drivers and state the swing ranges and which were assumed.

# Notes

The result misleads if ranges are inconsistent across inputs (e.g. +/-10% on one, +/-50% on another) — normalize the swing basis or disclose it. One-at-a-time analysis ignores interactions; flag known correlated inputs rather than implying independence. This is descriptive, not a decision — it shows leverage, not recommended action. Do not use for highly nonlinear or path-dependent models where single-point swings misrepresent behavior; use scenario or Monte Carlo instead.
