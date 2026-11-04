---
name: trip-planning
triggers:
  - plan a trip
  - travel itinerary
  - vacation plan
  - weekend in
tools_needed:
  - write_file
  - ask_user
  - spawn_swarm
---

# What this skill does

Produce a personalized day-by-day travel itinerary, written to a file
the user can edit. Asks the user up front for the few details that
materially change the plan (dates, budget, vibe), then generates
in parallel.

# Steps

1. If not already known, `ask_user` for: dates, total budget,
   solo/couple/family, mobility constraints, food preferences. BATCH
   these into one question.
2. Spawn three parallel researchers via `spawn_swarm`:
   - one for accommodations
   - one for activities + day plan
   - one for restaurants
3. A writer synthesizes the three reports into a day-by-day itinerary.
4. Write to `trip-{destination}.md` via `write_file`.
5. End with FINAL: brief summary + filename.

# Notes

- Always check the user's facts (dietary, mobility) before recommending
  restaurants and activities. Skipping this is the #1 source of
  rework.
- Include both a paid and a free option for each day -- people often
  flex on budget.
- Don't book anything. The agent doesn't have access to real booking
  systems; the itinerary is a draft the user finalizes.
