# Local companion client contracts

Run with Node 24 and the exact development dependencies in `package.json`:

```sh
npm install --ignore-scripts --no-audit --no-fund
npm test
```

Dependencies may instead be installed in a disposable external directory with
`NODE_PATH` pointing to its `node_modules`; the tests always resolve the source
checkout relative to this directory. No test launches an IDE/browser profile,
contacts a provider, or starts a paid goal. Neovim tests run the actual Lua
source in Fengari with a controlled `vim` API; that is not native Neovim
qualification. See [the lifecycle contract](../../docs/client-request-lifecycle.md)
and the separate mobile/JVM tests for the broader acceptance boundary.

`native-ownership.test.cjs` covers CLI timeout/cancellation, secure token
migration, host/credential changes and safe external-client failures, and
`test_external_examples.py` covers approval gating, truthful finish and REST
receipt recovery. The latter uses pytest and requests from the Python
development environment (`python3 -m pytest apps/client-contract-tests`).
These use controlled host/transport APIs, including real Lua source in Fengari.
They do not qualify installed IDEs, devices, accessibility or live providers.

# Dashboard response schemas

The shared goal and event DTOs are generated from the dashboard's Pydantic
models into `contracts/dashboard-v1.json`, TypeScript files in the mobile
and VS Code clients, and the Python SDK's TypedDict definitions. After changing the server models, run
`python scripts/generate_dashboard_contracts.py` from the repository root;
`python scripts/generate_dashboard_contracts.py --check` checks for drift.
The mobile app can extend a server DTO with client-only state, and each client
retains its own transport, credential, and lifecycle policies.
The shared replay fixture also generates a self-contained Kotlin test fixture
for the JetBrains loopback tests.

`contracts/goal-submission-recovery-v1.json` supplies the same accepted but
not execution-confirmed receipt to the browser extension, Python SDK, and
standalone REST example. Their tests exercise the lost-response path and check
that recovery reads the original submission key without replaying the write;
the mobile and VS Code tests also use its single-write expectation when a
request is cancelled or times out.
