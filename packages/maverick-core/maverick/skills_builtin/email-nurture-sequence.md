---
name: email-nurture-sequence
triggers:
  - nurture sequence
  - drip campaign
  - email flow
tools_needed:
  - knowledge_search
---
# What this skill does

Designs an automated email nurture sequence for a defined audience and goal (e.g. trial-to-paid, lead warming, onboarding). Produces an ordered set of emails, each with its entry/exit trigger, timing, content angle, and conversion goal, grounded in the actual product, ICP, and existing messaging.

# Steps

1. Use `knowledge_search` to gather the inputs: the target segment/ICP, the entry event that starts the flow, the desired end action, product value props, objections, and any existing email copy or performance data to reuse.
2. Define the flow logic: entry trigger, the exit/goal condition (so contacts who convert stop receiving the sequence), and any branch or suppression rules. State send timing/delays between steps.
3. Draft each email: a single primary goal, subject line angle, the value/proof it carries (cite the source asset or mark "[unverified claim]"), and one CTA. Order them from awareness to decision; avoid repeating the same ask every send.
4. Output the sequence as a table (step, delay, trigger, subject, body angle, CTA, goal) plus the exit condition. Report assumptions (timezone, send cadence, list hygiene) and hand off for marketing review before activation.

# Notes

Output is wrong if there's no exit condition (converted users keep getting nagged), if timing ignores the buyer's actual cycle, or if claims/stats are invented instead of sourced. This is a draft — a human enables the automation and owns deliverability/compliance (consent, unsubscribe). Don't use it for one-off broadcasts or transactional emails, which aren't trigger-based nurture.
