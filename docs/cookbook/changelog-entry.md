# Recipe: Changelog entry

Turn a merged PR (or a range of commits) into a single user-facing
CHANGELOG line. Sub-minute.

## Goal text

```
Summarize the commits between the last release tag and HEAD into one
CHANGELOG entry:

  1. Run `git log <last-tag>..HEAD --oneline` to see what shipped.
  2. Group the commits by user-visible impact (added / changed / fixed).
  3. Write at most 3 bullets, each a single sentence in the past tense,
     phrased for an end user — not "refactored X" but "X is now faster".
  4. Skip purely internal commits (CI tweaks, dependency bumps) unless
     they change behavior.

Output the markdown bullets only. Don't edit CHANGELOG.md.
```

## Tools used

`shell` (read-only `git log`, `git tag`), `read_file` (peek at an existing
CHANGELOG.md for tone).

## Expected runtime

~30-50 seconds on a normal release range. Under $0.50.

## Tips

- If you have no tags yet, swap step 1 for `git log -20 --oneline`.
- Follow up with: *"Now prepend these under a new ## version heading in
  CHANGELOG.md."*
