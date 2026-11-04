# gRPC API

Lightwork exposes a small gRPC surface for driving the agent runtime from any
language: start a goal, stream its episode events, cancel it, and read status.
It is the cross-language complement to the [REST API](./api.md) — pick gRPC
when you want a typed, streaming RPC contract and your own client codegen.

## Install & run

The API is behind an optional extra:

```bash
python -m pip install -e './packages/maverick-core[grpc]'
export MAVERICK_GRPC_BEARER_TOKEN='replace-with-a-long-random-token'
python -m maverick.grpc_api --address 127.0.0.1:50051
```

The server compiles the bundled `maverick.proto` into Python stubs on first
start (no generated code is checked in). Point your own `protoc` at the same
proto to generate a client in Go, Rust, TypeScript, C#, Java, etc.

## Service

The proto identifier is `service Maverick` in `package maverick.v1` — these
wire names are STABLE and frozen by the contract gate, so they keep the
original product name even though the docs are branded "Lightwork". Use them
verbatim in your codegen.

```proto
service Maverick {
  rpc StartGoal(StartGoalRequest) returns (StartGoalResponse);
  rpc StreamEpisode(StreamEpisodeRequest) returns (stream Event);
  rpc Cancel(CancelRequest) returns (CancelResponse);
  rpc GetStatus(GetStatusRequest) returns (GoalStatus);
  rpc RunGoal(RunGoalRequest) returns (GoalStatus);
}
```

- **StartGoal** creates a goal and dispatches it for background execution,
  returning the goal id immediately. Optional `max_dollars` / `max_wall_seconds`
  override the per-run budget; `0` uses the server/config default.
- **StreamEpisode** streams the goal's events in id order as they land, ending
  with a final `kind="status"` event carrying the terminal status. Resume after
  a disconnect with `since_id`.
- **Cancel** marks a goal cancelled; it is honoured at the next dispatch / turn
  boundary (in-flight cooperative cancellation rides the global killswitch the
  agent loop already checks).
- **GetStatus** returns the point-in-time status + result.
- **RunGoal** runs an *existing* goal row to completion and blocks until it
  reaches a terminal status — the cross-host Dispatcher seam, where the caller
  and the worker share the world DB. The legacy wire message has no field for
  department-suite grants, so `GrpcDispatcher` refuses every non-`None`
  `allowed_suites` value locally (including the explicit deny-all empty set)
  before sending an RPC. Use the authenticated queue dispatcher when a scoped
  suite grant must cross a process or host boundary; unrestricted `None`
  remains supported over gRPC.

The full message definitions are in
`packages/maverick-core/maverick/grpc_api/maverick.proto`.

## Authentication

The server refuses to start unless a bearer token is configured, either with
`MAVERICK_GRPC_BEARER_TOKEN` or `--bearer-token`. Every RPC must send the token
in gRPC metadata:

```text
authorization: Bearer <token>
```

Clients that omit the token or send the wrong token receive `UNAUTHENTICATED`
before the request reaches `GoalService`.

Bearer credentials protect identity, not transport confidentiality. For any
non-loopback listener or dispatcher target, configure `[grpc] tls = true` with
the appropriate certificate/key and CA settings. Plaintext is allowed by
default only on loopback (for same-host development or a local TLS terminator).
The server and client both refuse remote plaintext unless the operator makes
the narrow, explicit `MAVERICK_ALLOW_INSECURE_GRPC=1` exception for a trusted
private network.

## Notes

- The behaviour lives in a transport-agnostic `GoalService`
  (`maverick.grpc_api.service`); the gRPC layer is a thin protobuf shim, so the
  same logic could back a second transport.
- A loopback listener may remain plaintext behind a same-host TLS terminator.
  Do not expose a plaintext gRPC listener or dispatcher route to an untrusted
  network.
