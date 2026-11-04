---
name: ab-test-readout
triggers:
  - ab test
  - experiment readout
  - is it significant
tools_needed:
  - pandas_query
  - spreadsheet
---
# What this skill does

Interprets a completed A/B experiment to support a ship/no-ship decision. Produces a readout: observed lift on the primary metric, a confidence interval, a significance test result, sample sizes and power context, guardrail-metric checks, and an explicit recommendation framed against the pre-registered decision rule.

# Steps

1. Establish the experiment design before touching numbers: primary metric and its type (proportion vs continuous), randomization unit, pre-registered hypothesis and significance level (default two-sided alpha 0.05), minimum detectable effect, and the planned stop date. Refuse to read out if the test is still running or was peeked-and-stopped early — note that as a validity caveat.
2. With `pandas_query`, compute per-variant: sample size, the metric, and its variance. Run the appropriate test (two-proportion z-test for rates, Welch's t-test for means) and compute absolute and relative lift with a confidence interval. Verify the randomization split matches intended allocation (a sample-ratio mismatch invalidates the test).
3. Check guardrail metrics (latency, error rate, revenue, unsubscribes) for unintended harm, and confirm the test reached planned sample/duration. In `spreadsheet`, lay out variant rows with metric, lift, CI, p-value, and guardrail status side by side.
4. Report the lift with its CI and p-value, state whether it clears the pre-registered bar, and give a recommendation: ship, do not ship, or extend/inconclusive. State every assumption (test chosen, alpha, one vs two-sided) and hand off. The ship decision is the human's; this skill recommends.

# Notes

Output is wrong if you test the wrong metric type, peek and stop early (inflates false positives), ignore a sample-ratio mismatch, or report relative lift without a CI. "Not significant" is not "no effect" — report the CI so the reader sees the range of effects the data cannot rule out. Multiple metrics need multiple-comparison awareness; a win on a secondary metric is not the primary result. Do not declare a winner on a stat-sig primary while a guardrail regressed — surface the tradeoff for human judgment. Not for sequential/bandit designs or still-running tests.
