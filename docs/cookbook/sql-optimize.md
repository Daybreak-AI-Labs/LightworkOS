# Recipe: Slow SQL explain + optimize

Hand over a slow query; get the plan read for you and an indexed rewrite.

## Goal text

```
This query is slow: <PASTE SQL>. Against the schema in <PATH or DDL>:
  1. Run EXPLAIN (QUERY PLAN) and read it: which tables full-scan, which joins
     have no index, where a sort/temp b-tree appears.
  2. Propose the smallest change that removes the worst step — usually one
     covering index or a predicate rewrite. Show the CREATE INDEX / new SQL.
  3. Re-run EXPLAIN to confirm the scan became a search.
Output: the bottleneck in one line, the fix, and the before/after plan.
```

## Tools used

`sql_query` / `shell` (EXPLAIN), `read_file` (schema).

## Expected runtime

~1-2 min. Budget-cap $1.

## Tips

- No live DB? Paste the DDL and ask for the index recommendation from the plan
  reasoning alone.
