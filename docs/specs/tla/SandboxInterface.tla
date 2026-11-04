------------------------- MODULE SandboxInterface -------------------------
(***************************************************************************)
(* Formal model of Lightwork's sandbox interface (kernel rule 4 and the    *)
(* sandbox SDK v2 contract): every model-driven shell command is mediated  *)
(* by the selected backend, runs with a secret-scrubbed environment, and   *)
(* always reaches a terminal state (completed / timed-out / refused) —     *)
(* never wedged, and never silently downgraded to unsandboxed host exec    *)
(* when a container backend was selected.                                  *)
(*                                                                         *)
(* Model-checked with TLC (see SandboxInterface.cfg); the invariants are   *)
(* the properties the Python test suite pins empirically — this is the     *)
(* state-machine argument that they hold for ALL interleavings, not just   *)
(* the tested ones.                                                        *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    Commands,        \* the (finite, symmetric) set of command identities
    MaxSteps         \* per-command execution budget (models the timeout)

VARIABLES
    backend,         \* the configured backend: "container" or "local"
    state,           \* per-command lifecycle state
    env,             \* per-command child-env class: "scrubbed" | "host"
    ranOn,           \* per-command where it actually executed
    steps            \* per-command elapsed execution steps

vars == <<backend, state, env, ranOn, steps>>

Backends  == {"container", "local"}
States    == {"submitted", "running", "done", "timeout", "refused"}
EnvKinds  == {"scrubbed", "host", "none"}
RunPlaces == {"backend", "hostfallback", "none"}

TypeOK ==
    /\ backend \in Backends
    /\ state  \in [Commands -> States]
    /\ env    \in [Commands -> EnvKinds]
    /\ ranOn  \in [Commands -> RunPlaces]
    /\ steps  \in [Commands -> 0..MaxSteps]

Init ==
    /\ backend \in Backends
    /\ state = [c \in Commands |-> "submitted"]
    /\ env   = [c \in Commands |-> "none"]
    /\ ranOn = [c \in Commands |-> "none"]
    /\ steps = [c \in Commands |-> 0]

(***************************************************************************)
(* Dispatch: a submitted command starts running. The chokepoint ALWAYS     *)
(* scrubs the env, and the run place is the selected backend; the host     *)
(* fallback exists ONLY for the explicitly-local backend.                  *)
(***************************************************************************)
DispatchBackend(c) ==
    /\ state[c] = "submitted"
    /\ state' = [state EXCEPT ![c] = "running"]
    /\ env'   = [env   EXCEPT ![c] = "scrubbed"]
    /\ ranOn' = [ranOn EXCEPT ![c] = "backend"]
    /\ UNCHANGED <<backend, steps>>

DispatchHostFallback(c) ==
    /\ state[c] = "submitted"
    /\ backend = "local"          \* ONLY the local backend may host-exec
    /\ state' = [state EXCEPT ![c] = "running"]
    /\ env'   = [env   EXCEPT ![c] = "scrubbed"]
    /\ ranOn' = [ranOn EXCEPT ![c] = "hostfallback"]
    /\ UNCHANGED <<backend, steps>>

Refuse(c) ==
    \* e.g. a non-conformant external backend: refused, never run
    /\ state[c] = "submitted"
    /\ state' = [state EXCEPT ![c] = "refused"]
    /\ UNCHANGED <<backend, env, ranOn, steps>>

Progress(c) ==
    /\ state[c] = "running"
    /\ steps[c] < MaxSteps
    /\ steps' = [steps EXCEPT ![c] = @ + 1]
    /\ UNCHANGED <<backend, state, env, ranOn>>

Complete(c) ==
    /\ state[c] = "running"
    /\ state' = [state EXCEPT ![c] = "done"]
    /\ UNCHANGED <<backend, env, ranOn, steps>>

(***************************************************************************)
(* The timeout is MANDATORY once the budget is exhausted: a running        *)
(* command at MaxSteps has no Progress action left; the only enabled       *)
(* transitions are Complete or TimeoutFire, so it cannot run forever.      *)
(***************************************************************************)
TimeoutFire(c) ==
    /\ state[c] = "running"
    /\ steps[c] = MaxSteps
    /\ state' = [state EXCEPT ![c] = "timeout"]
    /\ UNCHANGED <<backend, env, ranOn, steps>>

Next == \E c \in Commands :
    \/ DispatchBackend(c)
    \/ DispatchHostFallback(c)
    \/ Refuse(c)
    \/ Progress(c)
    \/ Complete(c)
    \/ TimeoutFire(c)

Spec == Init /\ [][Next]_vars /\ \A c \in Commands :
    \* fairness: a submitted command is eventually dispatched or refused,
    \* and a running one eventually completes or times out — the liveness
    \* the chokepoint's synchronous call structure provides in the code.
    /\ WF_vars(DispatchBackend(c) \/ DispatchHostFallback(c) \/ Refuse(c))
    /\ WF_vars(Complete(c) \/ TimeoutFire(c))

(***************************************************************************)
(* INVARIANTS                                                              *)
(***************************************************************************)

\* 1. No silent downgrade: with a container backend selected, nothing ever
\*    executes on the host fallback.
NoSilentDowngrade ==
    backend = "container" => \A c \in Commands : ranOn[c] # "hostfallback"

\* 2. Scrubbed env: anything that ever ran did so with a scrubbed env —
\*    the host env class is unreachable.
ScrubbedEnvAlways ==
    \A c \in Commands : ranOn[c] # "none" => env[c] = "scrubbed"

\* 3. A refused command never executed.
RefusedNeverRan ==
    \A c \in Commands : state[c] = "refused" => ranOn[c] = "none"

\* 4. Budget bound: steps never exceed the timeout budget.
BudgetBounded ==
    \A c \in Commands : steps[c] <= MaxSteps

\* TEMPORAL: every command terminates (done, timeout, or refused).
EventuallyTerminal ==
    \A c \in Commands :
        <>(state[c] \in {"done", "timeout", "refused"})

=============================================================================
