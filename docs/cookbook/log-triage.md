# Recipe: Log triage

Point Lightwork at a noisy log file and get the error spike, its first
occurrence, and the likely cause.

## Goal text

```
Triage the log at <PATH/TO/app.log>:
  1. Bucket lines by level (ERROR/WARN) and by normalized message (strip ids,
     timestamps, hex, UUIDs) so repeats collapse into one signature.
  2. Rank signatures by count; for the top 3, show the first + last timestamp
     and one raw sample each.
  3. For the #1 error, hypothesize a root cause from the surrounding lines.
Output a short triage table + the hypothesis. Don't modify the log.
```

## Tools used

`shell` (grep/awk over the log), `read_file`.

## Expected runtime

~30-60s. Budget-cap $1.

## Tips

- Huge file? Prepend: *"Work on the last 5000 lines first."*
