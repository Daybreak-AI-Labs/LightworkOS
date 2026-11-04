# Bounded legacy sandbox admission

Sandbox SDK v2 normally requires `exec(cmd, timeout=None)`. A trusted legacy
backend whose `exec(cmd)` already enforces its own fixed finite execution cap
can explicitly publish `legacy_execution_policy = LegacyExecutionPolicy(cap)`
from `maverick.sandbox.sdk`. Its author must own physical cancellation/cleanup
and qualify that cap. This declaration is an enforcement contract, not a claim
that signature inspection can prove arbitrary backend behavior.

The SDK and `sandbox_run` admit the call shape before dispatch. The explicit
adapter calls legacy `exec(cmd)` once only when its fixed cap is no longer than
the requested per-call limit. A shorter caller limit is refused before any
command runs. It does not change a shared backend timeout, start a timeout
thread, cancel an awaiter as a substitute for stopping execution, or replay an
exception. Policy or method replacement invalidates an already admitted adapter.
Ownership, path confinement, environment protection and cleanup remain the
backend's responsibilities, as with the native v2 interface. Cancellation and
post-effect errors retain their original types; completed timeout cleanup does
not establish rollback of earlier business effects.

Backends with no declaration remain refused, including existing nonconforming
entry points. A configurable or cooperative backend should implement the native
v2 timeout interface instead of claiming a fixed cap it cannot enforce. There
is no automatic adaptation of arbitrary old plugins and no new sandbox enablement.
