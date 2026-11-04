# Recipe: API client from OpenAPI

Turn an OpenAPI spec into a small typed client + a smoke test.

## Goal text

```
From the OpenAPI spec at <PATH or URL>, generate a minimal Python client:
  1. Parse the spec; list the operations (method, path, params, response shape).
  2. Write a thin client: one typed method per operation, a shared session,
     and dataclasses for the request/response bodies actually used.
  3. Add one smoke test that constructs the client and asserts a method's URL
     + params are built correctly (mock the transport — no real network).
Output the client module + the test.
```

## Tools used

`http_fetch` (remote spec), `read_file`, `apply_patch`, `shell` (run the test).

## Expected runtime

~2-3 min. Budget-cap $1-2.

## Tips

- Big spec? Add: *"Only the endpoints under /v1/orders."*
