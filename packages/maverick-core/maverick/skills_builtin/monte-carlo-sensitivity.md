---
name: monte-carlo-sensitivity
triggers:
  - sensitivity analysis
  - monte carlo
  - whats the range
  - tornado chart
tools_needed:
  - pandas_query
  - spreadsheet
---
# What this skill does

Runs a sandboxed parameter sweep or Monte-Carlo simulation over a model and returns the outcome distribution plus a tornado sensitivity ranking of which inputs drive the result. The goal class is "quantify uncertainty in a model": replace a single point estimate with a distribution and a ranked view of what matters most.

# Steps

1. Load the model and identify the uncertain inputs with their plausible ranges/distributions (read the assumptions; do not invent distributions). Set up the calculation with pandas_query or a spreadsheet model.
2. Run a Monte-Carlo draw (or a structured grid sweep) with enough iterations for the tails to stabilize, recording the output distribution (mean, median, P10/P50/P90, and the shape).
3. Build a tornado/sensitivity ranking by varying one input at a time across its range and measuring the swing in the output, so the highest-leverage inputs are obvious.
4. Report the distribution and the sensitivity ranking together, stating the assumed input ranges explicitly so a reviewer can challenge them; flag inputs whose assumed range is itself a guess.

# Notes

Garbage in, garbage out applies hard here — a precise-looking distribution built on invented input ranges is false precision; the input assumptions ARE the analysis and must be stated and sourced. Too few iterations make the tails unreliable; check convergence. Correlated inputs treated as independent understate the spread; note correlations you are ignoring. Run the simulation in the sandbox, never against live data or systems. This skill computes and reports; it does not make the decision the model informs.
