# Recipe: Research deep-dive

Pick a paper / library / topic. The agent produces a 1-page brief
you can hand to a colleague.

## Goal text

```
Produce a 1-page research brief on: <topic>.

Specifically:
  1. Find the 3 most-cited recent papers (use arxiv tool, search
     <topic>).
  2. Read each abstract. If any introduces a concept I should know,
     fetch the full paper (arxiv fetch).
  3. Summarize: what's the state of the art? Who are the major
     contributors / labs? What's the consensus, and what's
     contested?
  4. Identify 3 follow-up questions a practitioner would want
     answered.

Output as markdown. ~500 words. Include citations (arXiv IDs +
URLs).
```

## Tools used

`arxiv` (search + fetch), `web_search` (for follow-ups arXiv
doesn't index, like blog posts / benchmarks), `recall_past_goals`
(in case we've researched the same topic before).

## Expected runtime

~5 minutes. $1-2 depending on how many papers it fetches.

## Tips

- Research is mostly text reasoning with little tool use, so a smaller
  model, or a self-hosted one through Ollama, keeps spend down (see
  [Configuration](../configuration.md)).
- After the brief, refine: *"Now write three concrete experiment
  designs based on the follow-up questions."*
