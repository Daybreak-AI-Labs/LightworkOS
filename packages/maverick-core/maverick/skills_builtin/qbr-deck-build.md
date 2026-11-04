---
name: qbr-deck-build
triggers:
  - build the QBR deck
  - prep the quarterly business review
  - put together the customer review
tools_needed:
  - sql_query
  - knowledge_search
---
# What this skill does

Builds a Quarterly Business Review deck for a customer account. Produces a structured narrative — value delivered this period, account health, open items, and forward roadmap — backed by real usage and outcome data so the review reinforces ROI and sets up renewal/expansion.

# Steps

1. Confirm the account, the review period, and the customer's stated success metrics/goals. Pull period metrics via `sql_query`: adoption, key outcome KPIs vs. baseline, support summary, and any agreed success-plan milestones.
2. Run `knowledge_search` for the prior QBR, the success plan, open action items, and product roadmap items relevant to this customer.
3. Assemble the deck sections: executive summary, value delivered (metrics vs. goals with sources), account health, status of prior action items, roadmap/what's next, and proposed mutual next steps. Tie every claimed win to a cited number.
4. Hand off the draft to the account owner for review, flagging unverified metrics and any roadmap items that are unconfirmed/forward-looking. State assumptions; do not send to the customer directly.

# Notes

Wrong if ROI claims aren't backed by sourced metrics, if roadmap items are presented as committed when they're tentative, or if open action items are silently dropped. Period and baseline must be explicit. Roadmap and commercial asks are draft talking points for a human to approve. Not for ad-hoc check-ins or for accounts without enough tenure to show a trend.
