---
name: ab-test-analysis
triggers:
  - ab test analysis
  - experiment analysis
  - is this result significant
tools_needed:
  - pandas_query
  - spreadsheet
---
# What this skill does

Analyzes a completed A/B test to support a ship/hold/iterate decision. Takes the raw per-unit assignment and outcome data, computes the lift on the primary metric with a confidence interval and significance test, checks for the usual validity threats, and produces a written recommendation. Output is an analysis memo: effect size, CI, p-value (or posterior), guardrail checks, and a clear call.

# Steps

1. Load the experiment data (`pandas_query` or `spreadsheet`) and confirm the schema: one row per randomization unit, a variant column, and the primary metric. Verify the unit of analysis matches the unit of randomization — never analyze per-event when randomization was per-user.
2. Run a sample-ratio mismatch check: compare observed variant counts against the intended split with a chi-square test. If SRM fails (p < 0.001), STOP — the assignment or logging is broken and any lift is untrustworthy; report this and do not proceed to a recommendation.
3. Compute the per-variant metric, the absolute and relative lift, and a confidence interval (two-proportion z / Welch's t for the metric type; cluster or bootstrap if the unit is aggregated). Report the pre-registered alpha and whether the test had power for the observed effect; flag any peeking or unstated multiple comparisons.
4. Check guardrail/counter metrics (latency, error rate, revenue) for regressions, then write the recommendation: ship / hold / iterate. State assumptions (test duration covered a full business cycle, no novelty effect, metric is the agreed decision metric) and mark any unverified data-quality assumption explicitly.

# Notes

The output is wrong if the analysis unit differs from the randomization unit (variance underestimated, false significance), if SRM is ignored, or if a p-value is read after repeated peeking without a sequential correction. A non-significant result is not "no effect" — report the CI so the reader sees what was ruled out. Recommend only; the human decides whether to ship. Do NOT use for observational/non-randomized comparisons — there is no causal claim there, and this skill assumes valid randomization.
