# MCP catalog synchronization

Both configured MCP clients use the same bounded catalog loader. Startup follows
`nextCursor` until a complete catalog is validated. A refresh publishes one
immutable generation; a malformed later page cannot replace a good catalog with
a partial list. Duplicate names, looping or invalid cursors, malformed object
schemas, and oversized catalogs fail closed. Structural schema checks never fetch
references or execute remote schemas; they are not a complete JSON Schema
conformance validator.

Each synchronization permits at most 32 requests, 2,048 tools in the accepted
generation, and 4 MiB of serialized page data in total. The structural page limit
is 100,000 JSON nodes and depth 64. The complete load has a deadline of the lesser
of the configured client timeout and 30 seconds, including waiting to write to the
stdio pipe. Existing transport frame/body limits still apply before catalog
validation. JSON parsing and bounded in-process schema validation are synchronous;
the deadline is not a preemptive CPU timer.

`client.catalog.status` reports the generation, stale state, safe error reason,
tool count, and the requirement to rebuild registries for new tools. Failed
refreshes retain the last good metadata for diagnosis but make its tools
unavailable. They do not silently serve a stale catalog. `await
client.refresh_tools()` retries explicitly. Stopping a client cancels its owned
refresh and retires all bindings.

Stdio `notifications/tools/list_changed` and notifications interleaved in HTTP
response SSE streams invalidate the catalog immediately. One loader coalesces
concurrent requests and notices. It can make one extra pass when a notice arrives
mid-load, sharing the same request, byte and time budgets. Further changes leave
the catalog stale for an explicit retry. Notification-driven loads start no more
than once per second. There is no autonomous retry loop.

Existing agent registries preserve their admitted tool set. An unchanged tool can
remain available after a successful refresh; a removed tool or any changed
metadata/schema is hidden and refused. Catalog visibility checks also invalidate
the registry's cached model schemas. Newly advertised tools wait for the next
normal registry construction, which applies Shield metadata inspection, ACLs,
rate limits and governance wrappers. Refresh never inserts a new tool into an
active registry. Execution checks the exact admitted metadata identity and current
registry ACL again before the transport write, including after waiting for the
stdio writer lock. Cancellation and budget/halt failures retain their control-flow
meaning.

The HTTP client still does not open a persistent server-to-client GET/SSE channel.
It observes notices only in response streams it receives; a server requiring an
independent notification subscription needs explicit `refresh_tools()` or a new
connection. A catalog refresh cannot undo a tool call already dispatched to a
server, nor establish that the server faithfully implements its advertised tool.
