# Recipe: Explain an error

Paste a stack trace or error message and get a plain-language explanation
plus the single most likely fix. Sub-minute.

## Goal text

```
Here is an error I just hit:

<paste full stack trace / error message>

Do this:
  1. Identify the actual failure (not just the last line — find the line
     that is the root cause).
  2. Explain in two sentences what went wrong, in plain language.
  3. If the trace references files in this repo, read the relevant lines
     for context.
  4. Propose the single most likely fix. One paragraph.

Don't change any code. End with a confidence level: high / medium / low.
```

## Tools used

`read_file`, `repo_map` (only if the trace points at repo files).

## Expected runtime

~30-50 seconds. Under $0.50. Set `MAVERICK_BUDGET_DOLLARS=0.5`.

## Tips

- For a stdlib/third-party-only trace it never touches the repo and stays
  text-only — cheapest path.
- Follow up with: *"Now apply the fix and run the failing command again."*
