---
name: sales-enablement-asset
triggers:
  - enablement asset
  - one pager
  - sell sheet
tools_needed:
  - knowledge_search
---
# What this skill does

Creates a sales-enablement asset (one-pager, sell sheet, battlecard, or talk
track) for a specific product, persona, and sales stage. Produces a ready-to-use
asset with positioning, proof points, objection handling, and a rep talk track,
grounded in approved messaging rather than invented claims.

# Steps

1. Confirm the asset type, target persona, product, and sales stage from the
   request. Use `knowledge_search` to pull the approved positioning, value
   props, proof points, and any existing messaging guide for that product.
2. Draft the core positioning for the named persona: the problem, the
   differentiated value, and 2-3 proof points (metrics, customers, references).
   Use only claims you can cite to a source; mark anything unverified.
3. Add the sell layer for the stage: discovery questions or a talk track,
   the top objections with responses, and a clear call to action or next step.
   Keep it to the format's length norm (one-pager = one page).
4. Assemble the asset in the requested format and hand it off, listing which
   claims are sourced vs unverified and flagging that legal/brand review is
   required before external use.

# Notes

Output is wrong if it cites metrics or customer names not found in approved
material, or if positioning drifts from the messaging guide — sales assets that
overclaim create legal and trust risk. Match the persona's language, not internal
jargon. This is a draft for human review; published external collateral needs
brand/legal sign-off. Do not use to invent net-new positioning from scratch when
no approved messaging exists — escalate to product marketing first.
