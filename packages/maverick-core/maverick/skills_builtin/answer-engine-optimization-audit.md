---
name: answer-engine-optimization-audit
triggers:
  - aeo audit
  - geo check
  - are we cited by ai
  - answer engine visibility
tools_needed:
  - web_search
  - knowledge_search
  - http_fetch
---
# What this skill does

This skill measures how often a brand is cited by AI answer engines (ChatGPT, Perplexity, Google AI Overviews, Copilot) for a fixed set of buyer-intent prompts, scores citation share against named competitors, and emits a prioritized list of structured-data and content fixes. It is a read-and-recommend audit only: it never publishes pages, edits schema, or changes live content — it produces a ranked fix backlog for a human to act on.

# Steps

1. Build or load a fixed prompt-set of 20-40 buyer-intent and category questions (use knowledge_search to pull existing positioning, ICP, and competitor names so the prompts reflect real demand) and freeze it so runs are comparable over time.
2. Run each prompt against the target answer engines via web_search and capture, per prompt, whether the brand is cited, which competitors are cited, the cited URL, and the sentiment/accuracy of the mention.
3. For each cited or expected-to-be-cited page, use http_fetch to inspect the live HTML for crawlability, schema.org markup (Organization, Product, FAQ, HowTo), heading structure, and answer-shaped passages; record what is missing or malformed.
4. Score citation share (brand vs competitors) per prompt cluster, then assemble a prioritized fix list ranking each recommendation by expected visibility lift versus effort (e.g. add FAQ schema, restructure a comparison page, create a missing answer page); stage the report — do not publish.

# Notes

AI answers are non-deterministic and personalized: run each prompt several times and report a citation rate, not a single hit/miss, and note the date and engine versions since results drift. Do not change any page or schema; output is a recommendation backlog only. Distinguish "not cited" from "cited inaccurately" — the second is a correction priority, not just a visibility gap. Keep the prompt-set fixed across runs so trend deltas are meaningful, and never fabricate a citation you did not actually observe.
