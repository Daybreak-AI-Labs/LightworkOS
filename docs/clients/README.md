# Client languages

Lightwork's runtime is written in Python. Other languages drive it over the
[Model Context Protocol](https://modelcontextprotocol.io/) (MCP): run
`maverick mcp` and connect any MCP client to it. For agents that run on
another stack and need governance rather than the full runtime, use the
REST external-agent gateway instead.

| Language | Guide |
|---|---|
| TypeScript | [TypeScript client quickstart](./typescript-quickstart.md) |
| Go | [Go client quickstart](./go-quickstart.md) |
| Rust | [Rust client quickstart](./rust-quickstart.md) |
| C# / .NET | [C# / .NET client quickstart](./csharp-quickstart.md) |
| Java / JVM | [Java / JVM client quickstart](./java-quickstart.md) |
| Any runtime, over HTTPS | [External agent quickstart](./external-agent-quickstart.md) |

## Language bindings

Lightwork is exposed to other languages **over MCP**, not by porting
`maverick-core`. Thin API clients port well; opinionated frameworks do not, and
Lightwork is the second kind. The MCP server ships with quickstarts for the
top five target languages: **TypeScript**, **Go**, **Rust**, **C#** and
**Java**.

There is no language-specific SDK package. A thin TypeScript client package
will be considered if there is demand; open an issue if you need one. Until
then the MCP surface is the supported interface. Operators can see their own
MCP client language mix with the opt-in local tally
(`[analytics] mcp_client_language = true`), which is stored only on the
installation and never sent to the project.

These constraints hold either way:

- `maverick-core` is not ported to a second language.
- Sandbox backends stay Python process glue and are not part of the
  cross-language contract.
- The multi-agent topology (orchestrator, proposer, verifier, revisor,
  reflector) stays in Python.

Other languages drive Lightwork; they do not re-implement it.
