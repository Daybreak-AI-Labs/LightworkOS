# Recipe: Profile a slow function

Find where the time goes in a slow path and propose the fix that matters.

## Goal text

```
<FUNCTION/SCRIPT> is slow. Profile it and fix the real bottleneck:
  1. Run it under cProfile (or time a representative call); rank by cumulative
     time. Identify the top 1-2 hotspots — not micro-optimizations.
  2. Diagnose: O(n^2) loop, repeated work that could be cached/hoisted, an N+1
     query, or needless allocation/serialization.
  3. Apply the smallest fix, re-profile, and report the before/after numbers.
     Keep behavior identical (run the tests).
Output: hotspot, fix, before/after timing.
```

## Tools used

`shell` (cProfile, tests), `read_file`, `apply_patch`.

## Expected runtime

~2-3 min. Budget-cap $1-2.
