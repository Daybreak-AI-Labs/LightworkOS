# Recipe: Type-annotation pass

Add type hints to an untyped module and prove them with the type checker.

## Goal text

```
Add type annotations to <PATH/TO/module.py>:
  1. Annotate public function signatures + return types first, then locals only
     where they aid readability. Infer from usage + call sites; don't guess.
  2. Use precise types (Sequence/Mapping over list/dict where read-only;
     Optional only when None is real). Add `from __future__ import annotations`.
  3. Run the project's type checker (mypy/pyright) on the file; fix what your
     changes surface; leave pre-existing unrelated errors alone.
Output the diff + the checker result.
```

## Tools used

`read_file`, `repo_map` (call sites), `apply_patch`, `shell` (type checker).

## Expected runtime

~2-3 min. Budget-cap $1.
