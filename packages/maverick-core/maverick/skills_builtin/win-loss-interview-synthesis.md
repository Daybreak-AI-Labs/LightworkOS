---
name: win-loss-interview-synthesis
triggers:
  - synthesize win-loss
  - win loss themes
  - deal retro analysis
tools_needed:
  - knowledge_search
  - read_file
  - spreadsheet
---
# What this skill does

This skill aggregates a set of structured win/loss interviews into evidence-cited themes across price, product, competitor, and process, attaching sample sizes and confidence caveats so leaders do not over-read a handful of anecdotes. It produces a staged synthesis with quotes traced to source interviews; it never invents reasons a deal was lost or attributes a quote it cannot point to.

# Steps

1. Use read_file and knowledge_search to gather the interview transcripts or notes for the period and confirm metadata per deal: outcome (won/lost), segment, ARR band, competitor, and stage lost.
2. Code each interview into the standard reason taxonomy (price/packaging, product gaps, competitor strength, sales process, timing/no-decision), tagging the supporting quote and the interview ID for every code so each theme is traceable.
3. Use spreadsheet to tally code frequencies by segment and outcome, computing the sample size (n) behind every theme and separating "many independent mentions" from "one loud detractor."
4. Assemble the synthesis: rank themes by weighted frequency, attach 2-3 verbatim cited quotes each, and add an explicit confidence caveat per theme (sample size, segment skew, recency); stage it for the revenue team — do not present as statistically representative if n is small.

# Notes

Win/loss interviews are self-reported and biased toward what the buyer is willing to say (price is over-cited as a polite proxy for value or product gaps) — flag that interpretation risk rather than taking reasons at face value. Never fabricate or paraphrase a quote into something the interviewee did not say. Report n alongside every percentage; "60% cited price" on five interviews is three people. Keep won and lost themes separate; a reason can drive wins and losses simultaneously and averaging them hides the signal.
