---
name: release-notes-author
triggers:
  - write release notes
  - draft a changelog
  - what's new for this release
tools_needed:
  - knowledge_search
---
# What this skill does

Turns a set of shipped changes (merged PRs, tickets, feature flags) into release notes segmented by audience (end users, admins, developers) and by impact (new, improved, fixed, breaking, deprecated). Produces a publishable draft plus an internal summary, not a raw commit dump.

# Steps

1. Establish the scope: confirm the version/tag and the date range or PR/ticket list. Pull the actual changes via `knowledge_search` over release tickets, merged PRs, and changelog fragments — do not invent entries. If scope is ambiguous, list candidate changes and ask which to include.
2. Classify each real change by audience (user / admin / developer) and impact (New / Improved / Fixed / Breaking / Deprecated). Drop internal-only refactors unless they alter behavior. Flag every breaking change and required migration step explicitly.
3. Rewrite each item in audience-appropriate language: outcome-first for users, action-required-first for admins/devs. Keep one line per item; link the source PR/ticket. Mark any claim you could not trace to a source as `[unverified]`.
4. Assemble the draft grouped by audience then impact, lead with breaking/action-required, and append an internal summary (counts per category, open follow-ups). Report the draft and state which version/range it covers and any items excluded.

# Notes

Output is wrong if it lists changes that did not ship, buries a breaking change, or uses internal jargon for an external audience. Never fabricate version numbers, dates, or fixes — every item traces to a PR/ticket or is marked unverified. This is a draft for human review; do not publish or tag a release yourself. Skip this skill for a single hotfix where a one-line note suffices, or when the change set is unmerged/speculative.
