# Go model proxy (`go/model-proxy`)

A faithful Go port of `maverick.model_proxy`: a tiny out-of-process proxy that
holds the provider API key the agent process must **not**. The agent points a
provider `base_url` at this proxy and sends requests with no usable credential;
the proxy strips whatever the client sent, injects the real key, and forwards to
the single configured upstream. The key never lives in the agent's address
space.

## Deployment choices

The Python implementation is part of `maverick-core` and can be launched in a
separate process with `python -m maverick.model_proxy`. It accepts proxy-process
environment variables and, for non-key settings, `[model_proxy]` configuration.
The provider key is read from the proxy process's `MAVERICK_PROXY_KEY`.

The Go implementation can be built as a standalone binary and reads its
configuration from the proxy process's environment. Both implementations are
optional and maintain the same intended request-ownership behavior. Both have
local tests, including generated parity fixtures for authorization, routing and
header decisions. The fixtures do not establish parity for every transport or
provider behavior.

Both listeners stream responses with bounded admission, backpressure and
cancellation. Local transport tests have not qualified either implementation
against live provider traffic, and no comparative speedup has been established.
Choose based on deployment requirements and qualify the intended providers and
workload before making a performance or reliability claim.

The security-critical decision logic —
`BuildRequest` (drop the client's auth + hop-by-hop headers, inject the proxy's
key, refuse a host outside the allow-set), `Authenticate` (constant-time client
token check), `RouteAllowed` (allow-list only model-inference routes) — is
covered by generated parity fixtures against the real Python (see below).

The shared lifecycle, limits and compatibility restrictions are documented in
[model proxy streams](../../docs/operations/model-proxy-streams.md).

## Run

From the repository root, run the Go implementation with config from the
proxy's **own** environment (never the agent's config):

```bash
cd go/model-proxy
export MAVERICK_PROXY_UPSTREAM=https://api.anthropic.com
export MAVERICK_PROXY_KEY=sk-ant-...          # the real key, injected upstream
export MAVERICK_PROXY_CLIENT_TOKEN=some-shared-secret  # agent must present this
export MAVERICK_PROXY_AUTH_STYLE=x-api-key     # or "bearer" (default)
# optional: MAVERICK_PROXY_LISTEN=127.0.0.1:8765
#           MAVERICK_PROXY_ALLOWED_ROUTES="POST /v1/messages, POST /v1/embeddings"

go run ./cmd/model-proxy            # listen
go run ./cmd/model-proxy -check     # validate config and exit
```

The agent then uses the proxy as its provider base URL, with
`MAVERICK_PROXY_CLIENT_TOKEN` as its (useless-elsewhere) api key.

Unlike the Python entry point this reads config **only** from the environment —
no TOML fallback — because running out-of-process means its settings and key
live in its own environment, which is also the documented deploy path.

## Parity with Python

`maverick.model_proxy` is the source of truth. `gen_parity.py` drives a battery
of inputs through the **real Python functions** and writes
`testdata/parity.json`; `parity_test.go` replays it through the Go port and
asserts byte-identical decisions (URLs, forwarded headers, auth/route verdicts,
SSRF blocks). Regenerate after changing either side so they can't drift:

```bash
python3 go/model-proxy/gen_parity.py     # from the repo root, with maverick-core installed
cd go/model-proxy
go test ./...                            # build + unit + parity + concurrency, run with -race in CI
```

CI (`.github/workflows/go-model-proxy.yml`) regenerates the fixture from Python
and fails on any diff, so the committed fixture always matches the current
Python.
