# Recipe: Issue triage

Inbox zero for GitHub issues. Labels, groups, and surfaces the ones
that actually need human attention.

## Goal text

```
List the 20 most recent open issues from <gh-owner>/<gh-repo>. For each:

  1. Read the title and the first 1000 chars of the body.
  2. Classify:
       - kind: bug / feature / question / docs / duplicate / spam
       - priority: low / medium / high
       - status: needs-repro / clear-action / waiting-for-user /
                 waiting-for-maintainer
       - estimated effort: small (<1 day) / medium (1-3 days) /
                           large (>3 days)
  3. If it's a duplicate, identify the original.
  4. If it's "clear-action", write one sentence proposing what to do.

Output a markdown table. Don't apply labels or comment on issues.
```

## Tools used

`http_fetch` (or the GitHub MCP if configured), `web_search`
(for cross-referencing similar issues elsewhere).

## Expected runtime

~5 minutes for 20 issues. $0.50-1.50 depending on issue length.

## Tips

- The GitHub MCP server (if you have it wired up via
  `maverick init`) makes this MUCH faster than scraping HTML.
- After the table, ask: *"Now post the proposed labels to each
  issue."* (Requires giving the agent a GitHub token + write scope.)
