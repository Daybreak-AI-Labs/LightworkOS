---
name: observability-design
triggers:
  - instrument this service
  - design observability
  - what logs metrics traces do we need
tools_needed:
  - knowledge_search
---
# What this skill does

Designs an observability plan for a single service: the key signals (logs, metrics, traces) to emit, the SLIs derived from them, and where instrumentation points belong in the request path. Produces a concrete instrumentation spec a team can implement, grounded in the service's actual dependencies and traffic shape.

# Steps

1. Establish the service's shape via `knowledge_search`: its endpoints/entrypoints, downstream dependencies, request volume, and existing telemetry. Do not invent dependencies the service does not have.
2. Define the metric set using RED for request-driven paths (Rate, Errors, Duration) and USE for resources (Utilization, Saturation, Errors). Name each metric, its type (counter/gauge/histogram), labels/cardinality, and the SLI it feeds.
3. Specify structured logging (event names, correlation/trace IDs, what to redact — no PII or secrets in logs) and distributed tracing spans at each service boundary and downstream call, with attributes to capture.
4. Hand off the instrumentation spec: signal inventory, candidate SLIs, dashboard groupings, and a minimal alert seed list. State assumptions (sampling rate, retention, backend) and flag any signal you could not ground in known service behavior as unverified.

# Notes

Wrong outputs over-instrument (high-cardinality labels like raw user IDs or full URLs that blow up the metrics backend) or specify signals for code paths that don't exist. Keep cardinality bounded and tie every signal to a question someone will actually ask during an incident. This produces a design only — it does not write instrumentation code or deploy collectors; a human implements and reviews cost. Not for picking a vendor/backend or for defining the SLO targets themselves (use slo-error-budget-policy).
