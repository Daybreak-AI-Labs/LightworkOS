---
name: support-deflection-analysis
triggers:
  - find ticket deflection opportunities
  - ticket deflection
  - where can we add self service
tools_needed:
  - sql_query
---
# What this skill does

Identifies support-ticket deflection opportunities by ranking high-volume, low-complexity contact reasons that could be resolved through self-service content or automation. Produces a prioritized list of content targets (KB articles, help-center topics) and automation targets (bot flows, form/portal deflection) with the volume and effort each would offload.

# Steps

1. Query the ticket store for the trailing window (default 90 days). Aggregate by contact reason / category / intent: ticket count, % of total, median handle time, % single-touch (no back-and-forth), reopen rate, and deflection signals already present (e.g. tickets created after a KB view). Never invent reasons — use the taxonomy values actually present in the data; flag null/"Other" buckets rather than guessing.
2. Score each reason for deflection fit: high volume + high single-touch + low handle time + low reopen = strong candidate. Separate content-deflectable (answer is static/known) from automation-deflectable (needs an action: reset, refund, status lookup) by inspecting representative tickets and resolution notes.
3. For the top candidates, pull 5-10 sample tickets each via sql_query to confirm the pattern is real and uniform (not several distinct problems collapsed under one label). Quote ticket IDs so findings are traceable.
4. Report a ranked table: contact reason, monthly volume, deflection type (content vs automation), estimated tickets deflectable, and the specific asset to build. State assumptions (window, taxonomy completeness) and hand off; recommend only — a human prioritizes the backlog.

# Notes

Output is wrong if volume is conflated across mixed intents, if seasonal spikes are read as steady state (check the window length), or if "deflectable" is asserted without inspecting real tickets. Single-touch is a proxy, not proof of self-serviceability. Do not propose deflecting reasons with high reopen or escalation rates — those usually need a human. Do not implement bot flows or publish content here; this skill recommends targets. Not for outage/incident spikes or low-volume long-tail reasons where build cost exceeds savings.
