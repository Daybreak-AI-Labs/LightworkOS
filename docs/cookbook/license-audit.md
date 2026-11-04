# Recipe: Dependency license audit

Check that your dependencies' licenses are compatible with how you ship.

## Goal text

```
Audit dependency licenses for this repo (we ship as <e.g. MIT open source>):
  1. List direct + transitive deps and each one's license (read metadata /
     `pip show` / the lockfile).
  2. Flag anything incompatible with our distribution: copyleft (GPL/AGPL) in a
     permissive product, "no commercial use", or missing/unknown licenses.
  3. For each flag, note the dep, its license, why it conflicts, and an option
     (replace / isolate / get legal sign-off).
Output a license table + the flagged rows. Don't change deps.
```

## Tools used

`shell` (`pip show`, lockfile), `read_file`, `http_fetch` (license text).

## Expected runtime

~1-2 min. Budget-cap $1.
