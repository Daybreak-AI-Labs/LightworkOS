# DGM evaluator evidence contract

## Current readiness

Lightwork's governed code-rung evaluator is fail-closed. No bundled sandbox
backend currently supplies controller-authenticated terminal test counts, so
the stock DGM runner refuses before a model proposal or candidate test runs.

This is an external runtime dependency, not a Python package omission. Docker,
Podman, Kubernetes, Firecracker, and similar process backends can report an
exit code and bounded output, but the candidate controls pytest stdout, JUnit
files in its workspace, and plugins loaded in its process. Treating any of
those as authoritative would allow reward laundering through forged summaries,
skipped collection, early successful exit, or substituted result files.

## Required protocol

A production evaluator backend must be installed through the sandbox SDK and
provide all of these attributes:

```python
authenticated_test_results = True
test_evidence_protocol = "maverick.test-evidence.v1"
test_evidence_authority = "<stable non-secret issuer or key id>"

def exec_authenticated_tests(request, timeout=None):
    ...
```

`request` is an `AuthenticatedTestRequest` issued by the Lightwork controller.
It binds a fresh 256-bit nonce to the exact command, a controller-computed
SHA-256 manifest of the evaluated artifact/workspace, and a stable execution-
context digest covering the baseline/candidate arm, sandbox identity, pinned
sandbox policy, evidence protocol, and evidence authority. The method returns
an exact `AuthenticatedTestEvidence` carrying:

- the same protocol, nonce, request, subject, and execution-context digests;
- the backend's pinned non-secret authority identity; and
- terminal passed, failed, skipped, and error counts.

Lightwork rejects a stale nonce, a command/digest mismatch, a wrong artifact or
arm/context binding, another authority, a subclass or lookalike result object,
non-terminal evidence, negative or boolean counts, zero outcomes, and
implausibly large totals. Skips and errors remain in the denominator. The
broker must independently verify that the compartment it ran matches both
digests; merely echoing controller fields does not satisfy the contract.

## Trust-boundary requirements

The backend is responsible for authenticating the runner event before it
constructs `AuthenticatedTestEvidence`. A conforming deployment needs a trust
boundary the candidate cannot write to, such as a mutually authenticated
evaluator broker, a sidecar with an isolated result channel and pinned key, or
a remotely attested execution controller.

The following do **not** satisfy the contract on their own:

- parsing pytest stdout or stderr;
- reading JUnit, JSON, coverage, or marker files from the candidate workspace;
- signing a file after reading it from that workspace;
- loading a "trusted" pytest plugin in the same Python process as candidate
  code; or
- deriving a pass count only from process exit status.

The broker must also enforce the stock DGM sandbox profile: non-host execution,
deny-by-default egress, non-root execution, bounded output, process and memory
limits, and an exact workspace binding for each baseline/candidate arm.

## Provider implementation checklist

1. Pin a stable evaluator image and runner identity outside the editable source
   tree.
2. Accept the exact nonce-, artifact-, and execution-context-bound request over
   an authenticated controller channel, and independently verify those bindings
   against the compartment selected for execution.
3. Run baseline and candidate in independent, resource-limited compartments.
   Re-materialize or verify the immutable subject before every request; mutable
   caches or state from a prior split must not change the next evaluation arm.
4. Observe terminal test events outside the candidate process and include
   skipped, collection, and runtime errors.
5. Authenticate the response before returning the exact Lightwork evidence
   type; never translate candidate-authored summaries into evidence.
6. Refuse retries or duplicate response nonces at the broker, and retain an
   append-only audit record keyed by request digest.
7. Pin the backend as `[sandbox] backend = "ep:<name>"`, then run a stock DGM
   cycle. Lightwork performs static readiness and workspace-binding checks
   before proposal/evaluation.

Until that external provider exists and passes adversarial conformance tests,
code-rung fitness remains unavailable rather than being replaced with a weaker
or simulated score.
