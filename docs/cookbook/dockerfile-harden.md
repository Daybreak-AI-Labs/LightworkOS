# Recipe: Dockerfile harden

Review a Dockerfile for size, cache, and security smells and apply the fixes.

## Goal text

```
Review the Dockerfile at <PATH> and harden it:
  1. Flag: running as root, no pinned base digest, secrets in layers, apt
     caches not cleaned, COPY . . before deps (cache-buster), no .dockerignore.
  2. Apply the safe fixes: non-root USER, pinned base, multi-stage if it cuts
     size, ordered layers (deps before source), --no-install-recommends + clean.
  3. Keep the build working — don't change the entrypoint behavior.
Output the diff + a one-line rationale per change.
```

## Tools used

`read_file`, `apply_patch`, `shell` (optional `docker build` if available).

## Expected runtime

~1-2 min. Budget-cap $1.

## Tips

- Add: *"Generate a matching .dockerignore."*
