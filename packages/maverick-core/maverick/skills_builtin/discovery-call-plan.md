---
name: discovery-call-plan
triggers:
  - discovery call
  - discovery plan
  - sales discovery
tools_needed:
  - knowledge_search
---
# What this skill does

Produces a structured plan for a sales discovery call that maps every question to a qualification dimension (e.g. budget, authority, need, timeline, current state, success criteria). The output is a sequenced question set plus listening cues, so the rep uncovers fit and pain without pitching prematurely.

# Steps

1. Gather the account context that already exists: company, industry, role of the contact, prior touchpoints, and the qualification framework in use (BANT, MEDDIC, or the team's own). Pull this from `knowledge_search` over CRM notes, prior call logs, and the playbook; mark any field you cannot confirm as unverified rather than inventing it.
2. Identify the qualification dimensions to cover and the open hypotheses about this prospect's pain. For each dimension, draft 2-3 open-ended questions grounded in the real context (their stack, their stated goals), ordered from broad rapport to specific qualification.
3. Map each question to its dimension and to the signal it should surface (e.g. "What breaks today when X spikes?" -> Need + Pain severity), and note the follow-up/branch if the answer indicates strong or weak fit.
4. Assemble the plan: agenda, timeboxed sections, the mapped question table, disqualification triggers, and a clear next-step ask. Report it and state which context fields were assumed or unverified so the rep can confirm before the call.

# Notes

The plan is wrong if questions are leading, if they pitch instead of probe, or if they assume facts not in the source (fabricated headcount, budget, or tooling). Cite the CRM/playbook source for any claimed fact about the account; mark inferences explicitly. This is a draft to guide a human rep — it does not auto-send invites or commit pricing. Do not use this for an existing late-stage deal where discovery is already complete; use a proposal or negotiation skill instead.
