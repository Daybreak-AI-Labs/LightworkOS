---
name: change-comms-plan
triggers:
  - change communications
  - comms plan
  - rollout comms
tools_needed:
  - knowledge_search
---
# What this skill does

Plans the communications for an organizational or product change (a launch, policy shift, reorg, or migration). Produces a comms plan mapping each affected audience to a tailored message, a delivery channel, a timing, and a sender — so the right people hear the right thing before the change lands.

# Steps

1. Gather the change context with `knowledge_search`: what is changing, why, the go-live date, affected groups, and any prior comms or known sensitivities. Identify each distinct audience (e.g. impacted users, managers, support, leadership) and what each needs to know and do.
2. For each audience, draft the core message: what changes, why, what it means for them, and the action or date they must remember. Match tone and depth to the audience — leadership gets rationale and risk, end users get impact and steps.
3. Assign a channel and timing per message (email, all-hands, doc, Slack, manager cascade), sequenced so dependent audiences (managers before their teams) are briefed first. Name a sender for each so the message carries the right authority.
4. Add a feedback/Q&A path and a rollback or escalation note for the go-live window. Hand off the plan as an audience x message x channel x timing table, flagging any audience whose messaging is still `[draft]` and noting assumptions about dates.

# Notes

The plan is wrong if an affected audience is missing, if managers are scheduled to hear after their teams, or if a message states an action without a date. Do not send anything from this skill — it drafts messages and schedules; a human approves content and authorizes each send, especially for sensitive changes (layoffs, incidents). Mark any claim about the change you could not confirm as `[unverified]` rather than guessing. Not for crisis comms requiring legal/PR sign-off — escalate those.
