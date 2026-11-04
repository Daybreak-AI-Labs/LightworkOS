---
name: web-research
triggers:
  - research and summarize
  - compare alternatives
  - what are the options for
  - find information about
tools_needed:
  - shell
  - write_file
  - spawn_swarm
---

# What this skill does

Research a topic by spawning multiple parallel researchers, each
focused on one source or angle, then synthesize their findings into
a single coherent answer.

# Steps

1. Identify 3-5 distinct angles or sources for the topic.
2. Use `spawn_swarm` with a researcher per angle. Each researcher
   should fetch one URL or run one search and report its findings as
   FINAL.
3. After all researchers return, an analyst (or the orchestrator
   itself) synthesizes the findings into a comparative summary.
4. Write the summary to a file via `write_file` if the goal asks
   for a deliverable; otherwise just respond with FINAL.

# Notes

- Don't spawn more than 5 parallel researchers; tokens and rate limits
  bite hard at higher fan-out.
- If a researcher fails to fetch its source, don't retry blindly;
  pick a different source.
- Always cite URLs in the final synthesis so the user can verify.
