---
name: nps-program-design
triggers:
  - design an nps program
  - net promoter
  - loyalty measurement
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Designs an end-to-end NPS measurement program: survey cadence, sampling and segmentation, the scoring/transactional-vs-relational split, and a closed-loop follow-up workflow for detractors and promoters. Output is a program spec with cadence, segment cuts, calculation method, and routing rules ready for ops to implement.

# Steps

1. Establish the baseline and population: `sql_query` the customer base for size, segments (tier, industry, region, lifecycle stage), and any existing survey history/response rates. `knowledge_search` for the org's prior NPS practice and benchmarks. Note response-rate floors needed for the score to be statistically meaningful per segment.
2. Define cadence and type: relational NPS (e.g. quarterly/biannual to a sampled, fatigue-throttled population) vs transactional NPS (event-triggered after support/onboarding). Specify the sampling rule, suppression window (no double-surveying), and the verbatim follow-up question.
3. Specify scoring and segmentation: standard %promoters − %detractors, the cuts to report (by tier/segment/cohort), trend windows, and minimum-N thresholds below which a segment score is shown as "insufficient sample" not zero.
4. Design the closed loop: routing rules for detractor alerts (owner, SLA), promoter hand-off (to the reference/advocacy program), and a recurring review of themes. Hand off the spec, stating assumptions about volume and which thresholds need validation against real response rates.

# Notes

The program is wrong if it reports a score on a sample too small to mean anything, surveys the same customer across overlapping waves (fatigue and bias), or collects scores with no closed loop (measuring without acting erodes trust). Keep relational and transactional NPS separate — mixing them makes trends uninterpretable. This skill produces a design to implement; do not send live surveys or trigger customer alerts from here — that is the human/ops step. Do not use for a one-question ad-hoc pulse where a full program is overkill.
