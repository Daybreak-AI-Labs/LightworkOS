# Explicit sandbox policy handoff

`[sandbox] cross_run_pool = true` remains off by default. The normal background
runner creates and closes a fresh sandbox for each run; it does not park one at
run end. Explicit embedders may call `park_at_run_end()` and let `build_sandbox()`
consume the resulting policy entry. This API provides no demonstrated startup
acceleration and is not recommended as a performance setting.

## Ownership and safety

A successful park permanently retires the old backend's execution lease and
stores only an immutable policy snapshot. It does not store that backend or its
workspace. Acquisition consumes one matching entry and constructs a new backend
with the new workspace and timeout, normal engine verification, and the resolved
image ID. An old reference can never execute against the new workspace. The old
handle remains retired after expiry, eviction or pool reset; cleanup is still
allowed. A failed park leaves ownership with the caller.

Only exact built-in Docker and Podman instances with the reviewed state layout
are eligible. Subclasses, extra or missing instance state, credentials attached
to a handle, active execution/cleanup, unresolved container cleanup, warm guests
and read-only workspace overlays prevent transfer. Read-only configurations use
fresh normal construction, which validates their mounts against the new
workspace. Adding a backend field requires an explicit eligibility decision.

The immutable policy covers engine, resolved image content, network/root flags,
process/memory/CPU limits, runtime, disabled warm/read-only features, effective
container user and a fingerprint of the current scrubbed client environment.
Workspace and timeout belong to the new lease and are never copied from the old
one. Raw environment values are not retained in the pool. Missing or malformed
image identity cannot fall back to a tag. Policy or image changes cause a miss;
after admission the container executes by image ID so a later tag move cannot
substitute different content.

The pool is bounded to two entries with a ten-minute monotonic TTL. Concurrent
parking cannot transfer the same lease twice; concurrent acquisition cannot
consume an entry twice. Slow image inspection runs outside the pool lock. A
construction failure consumes the entry and returns a miss so ordinary fresh
construction can surface the current engine/configuration error.

## Compatibility

The explicit API returns a distinct backend object rather than the same mutable
backend with a changed workspace. An embedder must stop using a handle
after `park_at_run_end(handle)` returns true. That retirement is intentional even
when no later caller acquires the policy. Pooling does not replace `close()` for
an ineligible backend; the caller still owns its cleanup.

No persisted pool state or database migration exists. Ordinary runs remain fresh
and the switch remains opt-in. Within-run Docker warm containers and Firecracker
warm microVM behavior are separate features; neither is admitted by this pool.

## Performance qualification

The eligible backends own no reusable daemon connection and start a fresh
container for every command. Two synthetic runs through fresh construction make
two version checks and two guest-run calls. One explicit policy handoff between
those runs additionally makes two image inspections; both version checks and
guest startups still occur. No wall-clock benefit is claimed.

Automatic run-end parking is intentionally not activated. The original
activation criterion remains open: a future design must identify useful work
actually avoided, prove ownership/cleanup and workspace isolation on the real
runner path, and demonstrate benefit against the added validation work. Reusing
a warm guest needs a separate proven scrub design; relaxing the current checks
to manufacture a benchmark improvement is not sufficient.

Offline tests exercise real backend/runner code with synthetic daemon responses.
They do not establish live Docker/Podman, container escape, installed-app or
customer workload acceptance.
