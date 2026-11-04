---
name: user-story-mapping
triggers:
  - story mapping
  - build a user story map
  - map the backlog to the journey
tools_needed:
  - knowledge_search
---
# What this skill does

Organizes a feature set into a user story map: a horizontal backbone of the activities a user moves through, with stories hung beneath each step and sliced into releases. It produces a two-dimensional view that exposes journey gaps and lets you carve a coherent walking-skeleton first release instead of a flat, sequence-blind backlog.

# Steps

1. Identify the user and the end-to-end goal, then lay out the backbone: the ordered high-level activities they perform (left to right in journey sequence). Source these from existing journey docs, research, or backlog via `knowledge_search`; don't invent steps the user doesn't actually take.
2. Under each backbone step, list the specific tasks/stories that accomplish it, ordered top-to-bottom by necessity. Map existing backlog items onto this grid and surface bare steps as gaps to flag.
3. Draw horizontal release slices: the top row across all steps that delivers a thin, end-to-end usable experience (the walking skeleton), then successive slices that deepen it. Each slice must span the whole backbone, not just one step.
4. Report the map (backbone, stories per step, release slices) and hand off. Call out identified gaps and assumptions, and recommend the team validate the journey sequence with real users before committing slices.

# Notes

The map is wrong if the backbone reflects the team's internal flow rather than the user's actual journey, or if a "release" slice covers only part of the backbone (it won't be usable end to end). Backbone sequence is a hypothesis — mark it unverified until research confirms it. This stages a plan for human prioritization, not a fixed commitment. Don't use it for a single isolated feature (use `feature-spec-author`) or when there's no multi-step user journey to map.
