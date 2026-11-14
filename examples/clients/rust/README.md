# Rust MCP client example

Run `cargo run --locked` against an installed `maverick` CLI. The example
initializes a local stdio session, lists tools, and calls `maverick_facts_get`.

Tool enumeration bounds pages, entries, and aggregate metadata bytes. Tool
errors and malformed `facts` results fail the smoke check; displayed server
text escapes terminal controls. The pinned rmcp transport already limits
incoming lines to 16 MiB. A separate stderr drain bounds lines to 64 KiB and
escapes displayed text before writing it to the terminal. Protocol parsing
and request/notification dispatch remain in the pinned SDK.
Initialization and tool checks each have a 30-second deadline. Cleanup is
awaited on errors, and a failed initialization also kills its child process.
Shutdown waits are bounded even when a nonreading peer blocks the SDK writer;
runtime teardown retains the child process's kill-on-drop guard.

Run `cargo test --locked` and `cargo clippy --locked --all-targets -- -D warnings`.
For the shared executable fixture, set `MCP_BOUNDARY_COMMAND` to a JSON argument
array invoking the built client, then run `python3 -m pytest` on
`examples/clients/java/tests/test_stdio_boundaries.py::StdioBoundaries` and
`examples/clients/java/tests/test_stdio_boundaries.py::ResponseDeadline` from the
repository root. Also run the `PipedStreamBounds::test_piped_streams_refuse_oversized_lines`
method for Rust's captured stderr boundary. The separate descendant cleanup case
exercises Java/C# process-tree cleanup; Rust's guard owns its immediate child.
Without `MCP_BOUNDARY_COMMAND`, generic Python test runs skip this native fixture.
The client workflow runs the live smoke; these adversarial checks are run
separately with a built client.
