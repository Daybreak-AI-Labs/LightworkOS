# Java / JVM MCP client example

The runnable version of [`docs/clients/java-quickstart.md`](../../../docs/clients/java-quickstart.md),
and the CI smoke test for Lightwork's JVM cross-language MCP surface.

`Client.java` spawns `maverick mcp` (stdio JSON-RPC) and runs the documented
client flow — `initialize` → `tools/list` → a no-LLM `tools/call`
(`maverick_facts_get`). It does **not** call `maverick_start` (that runs the
swarm and needs a provider key + budget), so it's safe to run unattended.

## Run it

```bash
# PyPI publish is pending — until the first tagged release, install the `maverick`
# CLI from a source clone (`pip install -e packages/maverick-core packages/maverick-mcp`)
# or via the native installer (see Releases).
python -m pip install -e ./packages/maverick-core -e ./packages/maverick-mcp
mvn -q compile exec:java
```

Requires JDK 21 (CI uses Temurin 21) and Maven 3.9+.

Expected output ends with:

```
Lightwork exposes 10 tools: maverick_answer, maverick_fact_set, ...
maverick_facts_get round-trip OK
maverick_facts_get structuredContent OK
OK: Java client drove Lightwork over MCP end-to-end
```

CI runs exactly this on every change to the MCP server or the clients (see
`.github/workflows/mcp-client-java.yml`), so a break in `maverick mcp` or the
documented tool surface fails the build.

The Java launcher inherits the parent process environment; `maverick mcp` also
loads the usual CLI config and enabled vaults. For a production launcher, use
the reviewed boundary described in the
[TypeScript client quickstart](../../../docs/clients/typescript-quickstart.md#child-environment-cli-config-and-vaults).

The example bounds graceful SDK shutdown to two seconds and its fallback close
to 500 milliseconds, then allows at most two seconds for process teardown. The
whole cleanup path therefore stays below five seconds. A UUID-scoped registry
records the launcher and server PID plus process start time, letting the guard
tear down only those verified transport roots and their snapshotted
descendants. It never infers ownership from process creation time, and a stale
PID cannot grant authority over a later process. Registry reads are capped at
4 KiB, 20 lines, and 16 process records. A `STARTING` registry never counts as
completed ownership; only the bounded `ACTIVE` form can authorize teardown.
A missing, unreadable, oversized, malformed, incomplete, or token-mismatched
registry fails closed: cleanup reports teardown as unverified and retains the
original registry plus a `.cleanup-failure` recovery record instead of deleting
evidence or terminating an unproven process.

The launcher also gives the real Python MCP process an OS-backed parent-death
contract before it serves requests (a validated process handle on Windows,
`PR_SET_PDEATHSIG` on Linux, and a parent watcher on other POSIX hosts). If the
launcher dies in the narrow interval before `ACTIVE` is recorded, the server
exits itself instead of becoming a re-parented orphan. Run the standalone
acceptance harness with:

```bash
mvn -q test-compile exec:java@cleanup-acceptance
```

It covers cooperative shutdown, a real SDK initialization timeout, an
independently blocked graceful and fallback close, and forced cleanup while an
unrelated Java child created after the guard remains alive. Every cleanup path
is pinned below five seconds. It also corrupts and deletes live ownership
registries to prove cleanup reports failure, retains recovery evidence, and
never falsely claims that an unverified child was torn down. A controlled
launch-window test force-kills the launcher after the server's parent guard is
armed but before `ACTIVE`, then proves no server survives.

## SDK

Uses the official [Java MCP SDK](https://github.com/modelcontextprotocol/java-sdk)
(`io.modelcontextprotocol.sdk:mcp`), pinned in `pom.xml` for reproducible CI.
