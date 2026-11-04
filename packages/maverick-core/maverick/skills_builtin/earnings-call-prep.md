---
name: earnings-call-prep
triggers:
  - prep us for the earnings call
  - earnings prep package
  - build the Q&A prep for the quarter
tools_needed:
  - knowledge_search
  - sql_query
---
# What this skill does

Assembles an earnings-call prep package for a reporting period: a tight set of talking points anchored to the quarter's actual results, plus an anticipated analyst Q&A with drafted responses. Handles the goal class of "get the CEO/CFO ready to speak to the numbers and defend the narrative" — produces talking points, a Q&A bank, and a list of likely sensitive topics.

# Steps

1. Pull the period's reported figures with sql_query (revenue, margin, segment results, guidance vs actual, key operating metrics) and the prior-quarter / prior-year comparatives. Note every number's source table and period so each claim is traceable.
2. Use knowledge_search to gather context: last quarter's prepared remarks, prior analyst questions, current guidance, recent sell-side notes, and any known overhangs (litigation, regulation, restructuring). Mark anything not found or stale as unverified.
3. Draft 6-10 talking points grounded in step-1 numbers — lead with the headline, name the drivers, and pre-empt the obvious "why" on each metric that moved. Keep claims to what the data supports.
4. Build the anticipated Q&A: for each likely question (margin trajectory, guidance bridge, segment softness, capital allocation), draft a response and flag where the answer touches non-public or legally sensitive ground. Report the package and state assumptions; spokespeople and counsel must review before the call.

# Notes

Wrong if numbers don't tie to the reported financials, or if forward statements slip past what guidance actually says — flag every forward-looking line for safe-harbor/Reg-FD review. Never fabricate a metric or a consensus figure; if consensus isn't retrievable, say so. Do not include selective disclosure of material non-public information — that is a human/legal gate, not something to draft around. Not for use after results are public if the goal is to spin; this stages preparation, it does not authorize what gets said.
