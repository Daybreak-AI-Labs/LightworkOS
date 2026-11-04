# Lazy enterprise connector executors

The declarative enterprise connector catalog separates immutable descriptions
from executors. Registry construction, schema serialization and `find_tools`
search do not construct these REST or GraphQL executors. The first authorized
invocation constructs only the selected connector and its governed wrapper.
Subsequent invocations reuse that registry's executor.

Lazy construction applies automatically to the bulk declarative catalog.
Handwritten tools, context-dependent tools, plugins and MCP registrations are
constructed eagerly. The `deferred_tools` setting still controls
which schemas the model sees; it does not control executor construction.
An authorized hidden tool remains callable without activation.

## Identity and policy

- Immutable descriptors, JSON-compatible schemas and lexical search tokens may
  be shared across registries. Copy schema metadata before changing it.
  Built-in descriptor changes take effect after process restart; private catalog
  specification lists are not a runtime configuration API.
- Each registry owns its executors. Actor, goal, enterprise policy and credential
  authority are not cached globally. Connectors still resolve live credentials at
  the request boundary, under the current tenant and invocation principal.
- Discovery inspects descriptors. It never runs a connector or requests approval.
  Current ACL restrictions apply to discovery, activation and dispatch. Rate-limit,
  cache, retry, budget, killswitch and governance boundaries apply in their usual
  dispatch order.
- Governance wraps the real executor on first use. Receipts retain the real
  connector's implementation provenance. Writes require approval and the
  conditional revision contract where applicable. Explicitly configured
  rate-limit wrappers set up their policy wrapper eagerly, while their connector
  executor stays lazy.

## Failure and recovery

Construction is synchronized per tool instance. Concurrent first invocations
share one construction attempt. A factory returning inconsistent metadata is
rejected before its executor can run. Construction failures return a stable,
sanitized error and are remembered for that instance, preventing repeated broken
initialization. Fix the installation and create a new registry, or explicitly
replace the registered tool, to retry construction. No raw factory exception text
is retained in that failure diagnostic.

Budget and killswitch stop signals keep their control-flow behavior. Normal
execution errors are handled by the tool dispatch policy; they are not stored as
construction failures. Lazy construction does not change external-effect
idempotency or authorize replay of writes.

## Performance

Construction measurements should include both the first registry, which
compiles immutable metadata, and later registries that reuse it. Skipping unused
executor construction does not imply faster provider responses or lower customer
request latency in every workload.
