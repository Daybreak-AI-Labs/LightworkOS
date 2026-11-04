# Recipe: PR review

After you push a branch, get a second pair of eyes on it before asking
a human. Catches the obvious stuff (off-by-one, missing await, dropped
error path) so the human review can focus on architecture.

## Goal text

```
Review the diff between the current branch and `main`. For each
file changed:
  1. Read the changed lines + ~20 lines of surrounding context.
  2. Identify any logic bugs, missing edge cases, dropped error
     paths, or test gaps.
  3. For each finding, output a line of the form:
     <path>:<line>  <type>: <one-sentence description>
       where <type> is one of: bug, edge-case, test-gap, style.

Don't change any code. End with a "verdict" line: "looks good",
"minor concerns", or "needs work".
```

## Tools used

`shell`, `read_file`, `repo_map`, `dep_graph`, `preview_diff`.

## Expected runtime

~2-3 minutes on a 200-line diff. Sonnet 4.6 is the right tier.

## Tips

- Use `maverick monitor` in a second terminal to watch the agent
  navigate the diff.
- Choose an explicit $1 task cap with `MAVERICK_BUDGET_DOLLARS=1`
  (or set it in config.toml). Ordinary tasks have no generated dollar cap;
  existing configured limits are preserved. See [task limits](../task-limits.md).
- If you want the agent to apply suggested fixes, add to the goal:
  *"After reviewing, apply only the fixes you're highly confident
  in. Open a separate commit for them."*
