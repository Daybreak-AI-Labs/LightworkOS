---
name: macro-knowledge-article
triggers:
  - write a support macro
  - draft a kb article
  - create a help article
tools_needed:
  - knowledge_search
---
# What this skill does

Drafts a support macro (canned reply) or knowledge-base article for a recurring contact reason, grounded in existing verified product/policy documentation. Produces a structured article: problem statement, prerequisites, numbered resolution steps, and a prevention/avoid-recurrence note — written for the intended audience (agent macro vs customer-facing help).

# Steps

1. Run knowledge_search for the topic to find the authoritative source: existing KB articles, product docs, runbooks, policy. Cite the sources you draw from. If no source covers a step, mark that step UNVERIFIED rather than inventing the procedure or UI labels.
2. Confirm scope: the exact symptom/trigger, who the article serves (agent-internal macro vs public help center), and the prerequisites/permissions a reader needs before step 1. Reuse the real product terminology and screen names from the sources, not approximations.
3. Draft the article in the required shape: Problem (what the user sees), Before you start (prerequisites), Steps (numbered, imperative, one action each), Expected result, and Prevent recurrence. Keep tone matched to audience; for a macro, include placeholders for ticket-specific variables rather than fabricated specifics.
4. List every source cited and flag any UNVERIFIED step needing SME confirmation, then hand off as a draft. Do not publish — a content owner reviews and publishes.

# Notes

Output is wrong if steps reference UI/policy not found in the sources, if it overstates certainty on an unverified step, or if customer-facing copy leaks internal-only actions or credentials. Stale source docs propagate stale steps — note the source date when available. Do not include destructive actions (data deletion, account changes) as a customer self-serve step; route those to an agent path. This drafts and recommends; publishing is a human decision. Not for one-off issues with no recurring pattern.
