---
name: automation-roi-model
triggers:
  - automation roi
  - benefits case for automating a process
  - fte savings from automation
tools_needed:
  - spreadsheet
---
# What this skill does

Builds a defensible ROI model for a proposed automation (RPA, script, workflow, or agent). It quantifies build/run effort against recurring time-and-cost savings and produces a model showing net benefit, payback period, and the assumptions behind each. Output is a structured workbook a stakeholder can challenge line by line.

# Steps

1. Gather the real baseline from the requester or source data: process volume (runs/month), manual handling time per run, fully-loaded labor rate, and current error/rework rate. Mark any figure you could not source as an explicit assumption.
2. In the spreadsheet, model the cost side: one-time build effort (hours x rate) plus recurring run cost (license, infra, maintenance hours/month). Model the benefit side: time saved per run x volume x rate, plus avoided rework. Keep every input in its own labeled cell so it is auditable.
3. Compute monthly net savings, cumulative net benefit over 12-36 months, payback month (first month cumulative benefit > build cost), and FTE-equivalent freed (annual hours saved / 1,800). Add a low/base/high scenario by flexing volume and time-saved.
4. Report the model with a one-line headline (payback in N months, X FTE freed), a sensitivity note on the two inputs that move the answer most, and a list of unverified assumptions. State that figures are an estimate for decision support, not a guarantee.

# Notes

The model is wrong if savings double-count (e.g., counting both time saved and error rework on the same step) or if labor rate is not fully loaded (benefits/overhead omitted understates cost but also understates savings — be consistent). Volume and time-per-run dominate the result; never hard-code them, source them. Do not present a single point estimate as fact — always show the scenario range and flag assumptions. This is a recommendation; a human owns the funding decision. Do not use for projects where the benefit is strategic/non-quantifiable — ROI modeling will mislead.
