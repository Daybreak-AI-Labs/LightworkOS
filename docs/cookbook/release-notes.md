# Recipe: Release notes

Draft user-facing release notes from the merged PRs / commits since the last tag.

## Goal text

```
Draft release notes for the next version:
  1. `git log <last-tag>..HEAD --oneline` (and PR titles if available).
  2. Group by Added / Changed / Fixed / Security; drop pure-internal commits.
  3. Write each line for a USER ("X is now faster"), not for a developer
     ("refactored X"). Lead with the highlights.
Output markdown under a `## <next-version>` heading. Don't edit CHANGELOG.md.
```

## Tools used

`shell` (git log/tag), `read_file` (CHANGELOG tone).

## Expected runtime

~30-60s. Budget-cap $1.
