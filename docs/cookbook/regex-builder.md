# Recipe: Regex builder

Describe what you want to match in English; get a tested regex back. No
trial-and-error in a regex playground. Sub-minute.

## Goal text

```
Build a regular expression that matches: <describe the pattern in
English, e.g. "US phone numbers in (415) 555-2671 or 415-555-2671 form">.

  1. Write the regex (Python `re` flavor unless I say otherwise).
  2. Show 3 strings it SHOULD match and 3 it should NOT.
  3. Verify each example mentally against the regex; if any fails, fix the
     regex and re-check.

Output the final regex on its own line, then the example table.
```

## Tools used

None required (pure reasoning). `shell` only if you ask it to verify with
a throwaway `python -c`.

## Expected runtime

~20-40 seconds. Under $0.50. `MAVERICK_BUDGET_DOLLARS=0.5` is plenty.

## Tips

- Add *"verify with a one-line python -c"* to the goal if you want the
  agent to actually run the examples through `re.match` via the sandbox.
- There is little tool use here, so a smaller model, or a self-hosted one
  through Ollama, keeps spend low (see [Configuration](../configuration.md)).
