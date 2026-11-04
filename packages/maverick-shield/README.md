# maverick-shield

Agent Shield integration for Lightwork. Provides three safety chokepoints
the agent loop wraps around:

- `Shield.scan_input(text)` — before user input enters the orchestrator
- `Shield.scan_tool_call(name, args)` — before any tool executes
- `Shield.scan_output(text)` — before the final answer reaches the user

See [docs/safety.md](https://github.com/Daybreak-AI-Labs/LightworkOS/blob/main/docs/safety.md)
for profiles and threat coverage.

## Roster-wide governance invariants

Beyond the three runtime chokepoints, the platform enforces six governance
invariants verified across every built-in specialist pack with a non-vacuous
fault-injection control (property-fuzzed up to 5,000 iterations):

1. **Tool-reachability** — no drafting/non-builder agent can reach a
   state-mutating tool.
2. **Autonomy dial** — an onboarding agent is never autonomous, and a
   high-risk action is never autonomous even once an agent is graduated.
3. **Capability attenuation** — a spawned child can never exceed its parent's
   grant (no privilege escalation).
4. **Compartment isolation** — a quarantine seal never bleeds across
   compartments or suites.
5. **Hard refusals** — the universal refusal floor is unstrippable.
6. **Budget caps** — no cap is ever silently exceeded.

The suite also hostile-argument fuzzes every connector and tool, and each
invariant ships a fault-injection control proving it is non-vacuous.
