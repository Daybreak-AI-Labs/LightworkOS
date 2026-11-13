# MCP Tasks (async, pollable tool execution)

Lightwork's MCP server implements
[MCP Tasks 2025-11-25 (experimental)](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/tasks)
on the stdio transport, with the full lifecycle and `notifications/tasks/status`
push, and on the Streamable HTTP transport when `MAVERICK_MCP_HTTP_TASKS` is set,
poll only. Task-driven elicitation (`input_required`) is not supported.

## 1. Why tasks

`maverick_start` runs the whole swarm to completion and is explicitly
**long-running**. Over the stdio transport the server is a single `readline()`
loop, so a synchronous long call **blocks the connection**: the client can't
check status, cancel, or call another tool until it returns.

MCP **Tasks** is the protocol-native answer. A task-augmented request returns a
`CreateTaskResult` immediately and runs in the background; the requestor polls
`tasks/get` and retrieves the result via `tasks/result` once terminal, a uniform
async pattern across request types.

## 2. Server behavior

The implementation is in `packages/maverick-mcp/maverick_mcp/`:

- **Capability** — `handle_initialize` advertises
  `tasks: { list:{}, cancel:{}, requests:{ tools:{ call:{} } } }` when the
  transport enabled tasks. A transport-neutral `self._tasks_enabled` flag gates it
  (distinct from `self._stdio`, which gates *elicitation* because that needs the
  bidirectional pipe). `run()` sets it on stdio; `build_app` sets it on HTTP
  from `MAVERICK_MCP_HTTP_TASKS`. When tasks are disabled the capability is absent,
  a `task` field is ignored, and `tasks/*` return `-32601`, per the spec.
- **Tool opt-in** — `maverick_start` and `maverick_resume` (the long ones) declare
  `execution.taskSupport: "optional"` in `tools/list`. A `task`-augmented call to a
  tool that didn't opt in gets `-32601` (method not found).
- **Create** — a `tools/call` carrying `params.task` (`{ "ttl": <ms> }`) returns a
  `CreateTaskResult` (`{ "task": { taskId, status:"working", createdAt,
  lastUpdatedAt, ttl, pollInterval } }`). The status in the ack is a frozen
  creation snapshot, so it's always `working` even if a fast tool finished first.
- **Execution** — the worker runs the tool on a **fresh `MCPServer` instance**
  (`_task_runner`). That isolates the main server's per-call state
  (`_structured_override`, `_pending_updates`) and its stdio: the worker only
  mutates its task record and the one push it emits (below). Status →
  `completed`, or `failed` when the `CallToolResult` has `isError`.
- **Methods** — `tasks/get` (poll), `tasks/result` (waits up to the configured
  result-block timeout for a terminal state, returns
  exactly the `CallToolResult` with `_meta["io.modelcontextprotocol/related-task"]`),
  `tasks/cancel` (best-effort; `-32602` on an already-terminal task), `tasks/list`
  (opaque-cursor pagination).
- **Notifications** — on stdio, `notifications/tasks/status` is pushed on each
  status transition (`completed` / `failed` / `cancelled`), carrying the full
  Task, so a client learns of completion without polling. Optional per spec
  (clients still poll). Transport writes go through a send lock, so a worker's
  push can't splice into the middle of the main loop's response line.
- **Store** (`tasks.py`, `TaskStore`) — in-memory registry + a bounded
  `ThreadPoolExecutor`; lazy TTL purge on access; registry size cap; crypto-random
  task ids (no auth context on stdio). Env knobs: `MAVERICK_MCP_TASK_WORKERS`,
  `MAVERICK_MCP_MAX_TASKS`, `MAVERICK_MCP_MAX_TASKS_PER_OWNER`,
  `MAVERICK_MCP_TASK_TTL_MS`, `MAVERICK_MCP_TASK_MAX_TTL_MS`,
  `MAVERICK_MCP_TASK_POLL_MS`, `MAVERICK_MCP_TASK_RESULT_BLOCK_MS`.

## 3. HTTP transport (opt-in)

Tasks work over the Streamable HTTP transport when `MAVERICK_MCP_HTTP_TASKS` is
set (default off). The `TaskStore` is transport-agnostic, so the HTTP path reuses
it with the same state machine:

- `build_app` sets `server._tasks_enabled` from the env knob. The store lives on
  the single `server` instance `build_app` wraps, so it persists across requests:
  a task-augmented `tools/call` returns a `CreateTaskResult`, and the client polls
  `tasks/get` / `tasks/result` / `tasks/cancel` / `tasks/list` on subsequent POSTs.
- The four `tasks/*` methods are routed through shared `MCPServer.handle_tasks_*`
  methods, used by both transports, that self-gate on `_tasks_enabled`.
  `_error_envelope` maps `TaskError` to its JSON-RPC `(code, message)` so an HTTP
  client sees the same wire codes as stdio.
- Over HTTP, `tasks/result` waits asynchronously up to the configured
  result-block timeout, without reserving a dispatch worker or blocking the
  FastAPI event loop.
- **No push over HTTP:** `notifications/tasks/status` is stdio-only
  (`_emit_task_status` no-ops when not stdio); HTTP clients poll, which the spec
  requires them to support regardless.
- **Off by default.** HTTP task access is bound to the caller's opaque MCP
  session. Keep its session id for subsequent task requests. With the knob off,
  the server ignores the `task` field and answers synchronously.

## 4. Security / resource notes

- **Isolation** — no auth context on stdio (one client owns the pipe), so task ids
  are `secrets.token_hex(16)`. The single-client assumption is why `tasks.list` is
  safe to advertise there.
- **Bounded** — concurrent workers, registry size, and `ttl` are all capped;
  expired tasks are purged. `tasks/result` waits at most
  `MAVERICK_MCP_TASK_RESULT_BLOCK_MS` (default 60,000 ms); clients can poll
  `tasks/get` instead. The underlying run is budget/wall-clock bounded.

## 5. Limits

- **No `input_required`.** Task-driven elicitation is not supported. Elicitation
  is synchronous within a foreground tool call; a task that parks a question
  leaves it for the async `maverick_answer` flow.
- **Session-bound access over HTTP.** `tasks/get`, `tasks/result`,
  `tasks/cancel` and `tasks/list` expose only that session's tasks; foreign ids
  receive the same "task not found" response as absent ids. Worker capacity is
  shared, with a caller-bound active-task quota (`MAVERICK_MCP_MAX_TASKS_PER_OWNER`)
  in addition to the global cap. Rotating sessions does not reset that quota.
