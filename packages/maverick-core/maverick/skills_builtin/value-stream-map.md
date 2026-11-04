---
name: value-stream-map
triggers:
  - create a value stream map
  - vsm for this process
  - where is the waste in our process
tools_needed:
  - knowledge_search
---
# What this skill does

Builds a current-state value stream map of an end-to-end process: each step with
its cycle time, wait/lead time, and inventory/queue, then computes process
efficiency and flags the largest sources of waste. Output is a VSM (steps,
cycle/lead times, %C&A where known) plus prioritized kaizen targets.

# Steps

1. Use `knowledge_search` to retrieve documented process steps, SOPs, throughput
   and timing data for the named value stream. Cite each source; where a step's
   timing is undocumented, mark it "unverified — estimate" rather than inventing
   a number.
2. Lay out the steps in sequence with, per step: process cycle time (touch
   time), wait/queue time before it, inventory between steps, and rework/%
   complete-and-accurate if known. Keep value-add and non-value-add time
   separate.
3. Sum the timeline: total lead time vs. total value-add time, and process cycle
   efficiency (value-add / lead time). Identify the top waste drivers (longest
   waits, biggest queues, highest rework) — the eight wastes are the lens.
4. Report the map, the efficiency number, and 3–5 prioritized kaizen targets
   tied to the biggest waste; mark every estimated value as unverified and state
   what data would confirm it. Hand off for the process owner to validate before
   any change.

# Notes

Wrong if estimated and measured times are mixed without labels, if lead time and
cycle time are conflated, or if the map reflects the documented "should-be"
rather than the actual current state — say which it is. A VSM from stale or
partial knowledge is a hypothesis, not a fact; flag confidence. Kaizen targets
are recommendations; the process owner decides what to change and no process is
altered from this output alone. Don't use it as a future-state design tool — this
maps current state only.
