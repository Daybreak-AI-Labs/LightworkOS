---
name: sox-narrative-author
triggers:
  - sox narrative
  - process narrative
  - control documentation
  - document this process for sox
tools_needed:
  - knowledge_search
---
# What this skill does

Documents a business process as a SOX-ready narrative, capturing the end-to-end flow with embedded risk points and the controls that address them. Output is a draft narrative (and control matrix stub) the process owner and internal audit validate before it enters the control framework.

# Steps

1. Gather the actual process via `knowledge_search`: existing narratives, walkthrough notes, system/role inventory, and the relevant assertions (e.g. completeness, accuracy, existence) for the cycle (order-to-cash, procure-to-pay, close). Confirm the as-is flow with a source; do not document an idealized process.
2. Write the narrative as an ordered flow — trigger, each step, the role/system performing it, inputs and outputs, and handoffs — in plain operational language. Mark any step that is unverified or assumed.
3. At each step identify the what-could-go-wrong (the risk point) and the control that mitigates it; record control attributes: type (preventive/detective), frequency, manual vs. automated, owner, and the assertion addressed. Note coverage gaps where a risk has no control.
4. Produce the narrative plus a control matrix stub (risk -> control -> assertion), report identified gaps and assumptions, and hand off for process-owner and internal-audit validation. Recommend; the control framework owner decides what is adopted.

# Notes

Wrong if the narrative describes intended rather than actual process (auditors test what happens, not what should), if controls are asserted without an identified risk, or if gaps are smoothed over instead of flagged. This is a draft for human validation — it does not establish or sign off controls, and control effectiveness is concluded by audit, not here. Cite the walkthrough/source for the as-is flow; never assert a control exists without evidence. Not for documenting a control's test of operating effectiveness — that's a testing workpaper, not a narrative.
