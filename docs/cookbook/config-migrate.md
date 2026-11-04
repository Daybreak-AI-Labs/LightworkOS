# Recipe: Config format migration

Migrate a config from one format to another, losslessly, with a verification.

## Goal text

```
Migrate the config at <PATH> from <e.g. .env / JSON> to <e.g. TOML>:
  1. Parse the source; preserve EVERY key + value (and comments where the target
     supports them).
  2. Write the target file; map types correctly (numbers/bools not strings).
  3. Verify: parse the target back and assert it round-trips to the same
     key/value set as the source. Report any key that didn't map.
Leave the original in place; write the new file alongside.
```

## Tools used

`read_file`, `write_file`, `shell` (round-trip check).

## Expected runtime

~1-2 min. Budget-cap $1.
