---
name: ai-use-case-risk-assessment
triggers:
  - assess this AI use case for risk
  - run an AI governance review
  - responsible AI risk assessment
tools_needed:
  - knowledge_search
---
# What this skill does

Assesses a proposed or live AI/ML use case against a responsible-AI governance framework (e.g. NIST AI RMF, internal AI policy). Produces a use-case assessment that assigns a risk tier and enumerates required controls across fairness, transparency, privacy, security, human oversight, and accountability. Output is a draft governance record for an AI risk owner to review, not a deployment sign-off.

# Steps

1. Gather the use-case definition via knowledge_search: purpose, affected populations, data sources and sensitivity, model type, autonomy level, and decision impact (cite the intake/spec sources; mark unstated attributes as open questions rather than assuming low risk).
2. Classify potential harms across dimensions — bias/fairness, explainability, privacy/PII, security/misuse, safety, and reliability — grounding each in the actual data and decision described. Assign a risk tier (e.g. low/medium/high/prohibited) from the framework's criteria and cite the rule that drives the tier.
3. Map required controls to the tier and identified harms: human-in-the-loop checkpoints, bias testing, documentation/model cards, monitoring, access controls, and incident handling. Note which controls already exist (with evidence) versus gaps.
4. Compile the assessment with the tier, rationale, control checklist (present vs. missing), and open questions, then hand off to the AI risk owner. State assumptions and flag any prohibited or high-risk pattern for mandatory human escalation before launch.

# Notes

Output is wrong if the tier is asserted without citing the framework criterion, if missing intake information is treated as absence of risk, or if existing controls are claimed without evidence. The most common failure is under-tiering a use case that touches protected populations or consequential decisions — when impact is ambiguous, tier up and escalate. This skill drafts and recommends a tier and controls only; approving deployment of a high-risk or prohibited use case is an irreversible action reserved for a human risk owner. Do not use as a substitute for a legal/regulatory conformity check (e.g. EU AI Act) or for non-AI systems.
