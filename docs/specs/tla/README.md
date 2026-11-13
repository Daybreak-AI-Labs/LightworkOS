# Formal verification of the sandbox interface (TLA+)

`SandboxInterface.tla` models the sandbox chokepoint (kernel rule 4 in
[`CONTRIBUTING.md`](../../../CONTRIBUTING.md#house-rules) and the sandbox SDK v2
contract) as a state machine and TLC model-checks the
properties the Python suite pins empirically — for **all** interleavings, not
just the tested ones:

| Property | Kind | Meaning |
|---|---|---|
| `NoSilentDowngrade` | invariant | with a container backend selected, nothing ever executes on the host fallback |
| `ScrubbedEnvAlways` | invariant | anything that ran did so with a scrubbed child env |
| `RefusedNeverRan` | invariant | a refused command (e.g. non-conformant external backend) never executed |
| `BudgetBounded` | invariant | execution steps never exceed the timeout budget |
| `EventuallyTerminal` | temporal | every command reaches done / timeout / refused — never wedged |

A previously recorded local run (TLC 2.19, config `SandboxInterface.cfg`,
2 commands, MaxSteps=3) reported **982 states generated, 521 distinct, no errors**.
This is historical evidence, not a CI-verified result for the current source.
The configuration declares no symmetry reduction; the command below disables
deadlock checking with `-deadlock`. CI does not currently run TLC, so rerun it
after changing the model or configuration.
The liveness property needs fairness on *dispatch*: without it, a submitted
command may stutter forever. The code's synchronous chokepoint provides that
fairness, and the spec states it as an explicit assumption.

## Reproducing

```bash
curl -sLo /tmp/tla2tools.jar \
  https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
cd docs/specs/tla
java -cp /tmp/tla2tools.jar tlc2.TLC -deadlock SandboxInterface.tla
```

Scope: the model covers the dispatch/lifecycle/scrub/timeout
contract, not the container runtimes' internals (Docker/gVisor/Firecracker
correctness is theirs). Extending the model (e.g. workdir-confinement paths)
extends the table above.
