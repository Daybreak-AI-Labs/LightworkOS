---
name: demo-script-build
triggers:
  - demo script
  - product demo
  - tailored demo
tools_needed:
  - knowledge_search
---
# What this skill does

Builds a tailored product-demo script that follows a use-case-driven flow rather than a feature tour. The output sequences the demo around the prospect's stated pains, ties each step to a proof point (metric, customer story, or capability), and includes talk track, transitions, and the value statement to land at each beat.

# Steps

1. Retrieve the prospect's qualified pains, goals, and environment from `knowledge_search` over discovery notes and CRM; retrieve the matching product capabilities and proof assets (case studies, benchmarks, ROI data) from the knowledge base. Note which pains are confirmed vs assumed.
2. Select the 3-5 capabilities that map directly to confirmed pains. Discard features with no demonstrated relevance — a tailored demo shows fewer things, deeply.
3. Sequence a narrative: open with the prospect's world and the cost of the status quo, then walk each capability as "here is the pain -> here is what you do in the product -> here is the proof it works." Attach a real proof point to each step and a transition line to the next.
4. Assemble the script with talk track, click path, proof points, anticipated questions, and the closing value summary plus next step. Report it, citing the source for every proof point and flagging any claim you could not verify in the knowledge base.

# Notes

The script is wrong if it lists features the prospect never expressed need for, or if a proof point (metric, logo, quote) is fabricated or uncited — only use proof assets you can trace to a source. It is a draft talk track for a human presenter; it does not stand in for live qualification and does not commit to roadmap items. Do not use this before discovery is done — without confirmed pains you will build a generic feature tour. Mark any capability that depends on configuration or paid tier as such.
