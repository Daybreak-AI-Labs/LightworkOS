---
name: slo-error-budget-policy
triggers:
  - define slo
  - error budget policy
  - set burn rate alerts
  - service level objective
tools_needed:
  - read_file
  - knowledge_search
---
# What this skill does

This skill derives Service Level Indicators (SLIs) from a service's golden signals (latency, traffic, errors, saturation), proposes SLO targets and a measurement window, and writes a multi-window multi-burn-rate alerting policy plus the error-budget and release-freeze rule that governs what happens when the budget is spent. It produces a complete, reviewable SLO/error-budget policy document grounded in the service's actual behavior and the user-facing journeys that matter. The output is a staged policy draft and alert spec; it does not create alerts, page anyone, or enforce a freeze — those are applied by humans after review.

# Steps

1. Use read_file and knowledge_search to understand the service: its critical user journeys, existing dashboards/metrics, current latency and error baselines, and any dependency SLAs. Pick SLIs that reflect user experience (e.g. proportion of requests served < 300ms, proportion of non-5xx responses) rather than raw infrastructure counters.
2. Propose SLO targets and the compliance window (e.g. 99.9% availability over 28 days), justified by the baseline and the journey's importance; derive the resulting error budget (allowed bad events) from the target and expected traffic.
3. Design a multi-window, multi-burn-rate alert policy: a fast-burn alert (e.g. 14.4x over 1h) for urgent budget depletion and a slow-burn alert (e.g. 6x over 6h) for sustained erosion, each with the page/ticket severity. Write the error-budget policy: what happens at budget-exhausted (feature-freeze / reliability-focus) and how the budget resets.
4. Assemble the policy doc (SLIs, SLO targets + window, error budget, burn-rate alert table, freeze/exhaustion rule, owner) and stage it for SRE/service-owner review. Mark that alert creation and any release-freeze enforcement are applied by humans after sign-off.

# Notes

SLIs must be user-centric: a CPU or pod-count metric is not an SLI — measure the thing the user feels (success rate, latency at a percentile). Single-threshold error-rate alerts either page too late or flap; use multi-window multi-burn-rate so a fast catastrophic burn and a slow chronic burn each alert appropriately — that is the whole point of the policy. The error-budget policy only works if the freeze rule is agreed in advance and enforced by humans; this skill drafts that rule, it does not freeze releases or mute/create alerts. Don't set 100% as a target — that leaves no budget for change and is unachievable; flag any request for it. Tie the window and reset cadence explicitly so the budget math is reproducible.
