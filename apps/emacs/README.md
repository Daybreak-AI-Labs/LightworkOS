# maverick.el

Drive the [Lightwork](https://github.com/Daybreak-AI-Labs/LightworkOS) agent runtime
from Emacs — a dependency-free front end over the locally installed
`maverick` CLI (Emacs 27.1+).

## Install

Add to `load-path` and require:

```elisp
(add-to-list 'load-path "/path/to/LightworkOS/apps/emacs")
(require 'maverick)
(setq maverick-cli-path "maverick")           ; if not on PATH
(setq maverick-default-max-dollars nil)       ; optional per-run cap
```

## Commands

| Command | What it does |
|---|---|
| `M-x maverick-start` | prompt for a goal, run it (compilation buffer) |
| `M-x maverick-status` | runtime status + cost |
| `M-x maverick-monitor` | live plan-tree TUI (term buffer) |
| `M-x maverick-logs` | recent run logs |
| `M-x maverick-halt` | arm the killswitch (confirms first) |
| `M-x maverick-unhalt` | clear the killswitch |
| `M-x maverick-cancel-control` | stop local status/halt supervision; outcome remains unconfirmed |

Status and halt controls use asynchronous owned processes. Editing remains
available while they wait. `maverick-control-timeout` defaults to 30 seconds
(bounded to 0.1–120 seconds), and responses are limited to 64 KiB. Timeout,
cancellation and nonzero exit never claim that external effects stopped; inspect
local state before another action. Late callbacks cannot replace a newer result.
The halt acknowledgement still requires exact local scope and checkpoint semantics.

The two regression tests in `tests/maverick-control-tests.el` passed in native
Emacs 30.2 using mocked processes and timers. This does not qualify interactive
editing or real CLI cancellation.

See the [client request and acknowledgement contract](../../docs/client-request-lifecycle.md) for replay, deadlines, access errors, and platform qualification limits.
