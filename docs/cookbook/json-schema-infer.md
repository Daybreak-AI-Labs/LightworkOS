# Recipe: Infer a JSON schema

Infer a JSON Schema from sample data and validate the rest of the samples.

## Goal text

```
From the JSON samples at <PATH (one object, an array, or JSONL)>:
  1. Infer a JSON Schema (draft 2020-12): types, required keys (present in all
     samples), enums for small closed string sets, nullable where some are null.
  2. Validate every sample against it; report any that fail (so the schema is
     neither too loose nor too tight).
  3. Write the schema to <PATH>.schema.json.
Output the schema + the validation summary.
```

## Tools used

`read_file`, `pandas_query`/`shell` (inspect), `write_file`.

## Expected runtime

~1-2 min. Budget-cap $1.
