# Recipe: CSV cleanup

Hand Lightwork a messy CSV and get a clean, well-typed one back — with a note
on every transformation it made.

## Goal text

```
Clean the CSV at <PATH/TO/data.csv>:

  1. Load it and profile each column: dtype, null count, distinct count, and a
     few sample values.
  2. Normalize: strip whitespace; coerce obvious numerics/dates to real types;
     unify casing on categorical columns; standardize the null representation
     (""/"NA"/"N/A" -> a true null).
  3. Flag (don't silently drop) suspicious rows: duplicates, out-of-range
     numbers, dates in the future, impossible values.
  4. Write the cleaned data to <PATH/TO/data.clean.csv> and a short
     CLEANING_NOTES.md describing every transformation and every flagged row.

Do not invent or impute values — flag, don't fabricate.
```

## Tools used

`pandas_query` (profile + transform), `read_file` / `fs` (read/write CSV),
`write_file` (the notes).

## Expected runtime

~1-3 minutes for a few-thousand-row file. Budget-cap at $1.

## Tips

- For big files, add: *"Work on a 1000-row sample first and show me the plan
  before applying it to the full file."*
- Keep the original; the recipe writes a `.clean.csv` so the input is never
  overwritten.
