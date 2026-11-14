# Rust MCP client example

Run `cargo run --locked` against an installed `maverick` CLI. The example
initializes a local stdio session, lists tools, and calls `maverick_facts_get`.

Tool enumeration bounds pages, entries, and aggregate metadata bytes. Tool
errors and malformed `facts` results fail the smoke check; displayed server
text escapes terminal controls. The pinned rmcp transport already limits
incoming lines to 16 MiB. It inherits child stderr directly. Protocol parsing
and request/notification dispatch remain in the pinned SDK.
Initialization and tool checks each have a 30-second deadline. Cleanup is
awaited on errors, and a failed initialization also kills its child process.

Run `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings`.
For the shared executable fixture, set `MCP_BOUNDARY_COMMAND` to a JSON argument
array invoking the built client, then run `python3 -m pytest` on
`examples/clients/java/tests/test_stdio_boundaries.py::StdioBoundaries` and
`examples/clients/java/tests/test_stdio_boundaries.py::ResponseDeadline` from the
repository root. The Java/C# `PipedStreamBounds` cases exercise their separate
bounded stderr readers; Rust inherits that stream instead.
Without `MCP_BOUNDARY_COMMAND`, generic Python test runs skip this native fixture.
The client workflow runs the live smoke; these adversarial checks are run
separately with a built client.
