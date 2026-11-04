# Verified: capability attenuation is least-privilege by construction

The [capability layer](../enterprise/security-overview.md) is the
backbone of Lightwork's least-privilege model. A `Capability` is a scoped grant
(tools, risk ceiling, filesystem paths, network hosts) bound to a principal, and
it can only ever be **attenuated** (narrowed) as it propagates — to a subagent,
a federated peer, a queue worker, or an RBAC role. *Everything* that delegates
authority leans on one invariant:

> A derived grant can never permit a tool, path, host, or risk level the parent
> grant didn't.

Formally, the narrowing operators (`Capability.intersect`, `Capability.attenuate`)
form a **meet** in the privilege lattice: `R = P ⊓ C` is ≤ both operands. For
every tool `t`, path `p`, host `h`:

```
R.permits(t)       ⟹  P.permits(t)  ∧  C.permits(t)
R.permits_path(p)  ⟹  P.permits_path(p)  ∧  C.permits_path(p)
R.permits_host(h)  ⟹  P.permits_host(h)  ∧  C.permits_host(h)
risk(R) ≤ min(risk(P), risk(C))      deny(R) ⊇ deny(P) ∪ deny(C)
```

and a whole delegation chain (root → … → leaf) never re-widens.

## How it's verified

Two complementary checks, both in `packages/maverick-core/tests/`:

1. **Property-based suite** (`test_capability_monotonicity.py`) — generates
   thousands of random capability lattices and probes and asserts all five
   implications above, plus chain-attenuation transitivity and meet idempotence.
   Seed-based (stdlib `random`, no new dependency), so it runs in CI as a
   permanent guard.

2. **SMT proof** (`test_capability_glob_smt.py`) — the tool/risk/deny dimensions
   are exact-match sets where monotonicity follows from set theory, but
   `allow_paths` / `allow_hosts` are **fnmatch glob languages**. There, the
   narrowing intersects the *pattern strings*, so we discharge the path/host
   case in Z3: a glob→regex translation is first checked faithful to
   `fnmatch.fnmatchcase`, then for a fully **symbolic, unbounded** path `p`
   (drawn from the real, NUL-free domain) we prove
   `permits_path(p, narrow(A,B)) ⟹ permits_path(p, A)` has no counterexample.
   (Z3 is verification-only and not a project dependency; the test self-skips
   where `z3` isn't installed.)

## Domain assumption & a known wart

* **`_DENY_ALL` sentinel.** "Permits nothing" is encoded as the single pattern
  `"\x00"` (a NUL). The proof confirms it matches no NUL-free string — and a NUL
  is never a valid filesystem path, host, or tool name, so it denies everything
  in the real domain.
* **Sound but incomplete.** Glob narrowing intersects *pattern strings*, not
  glob *languages*. So `narrow({"*"}, {"src/*"})` collapses to deny-all even
  though `*` ⊇ `src/*`. This **over-restricts** — the safe direction. It can
  surprise an operator (use the empty set, not `"*"`, to mean "all paths"), but
  it never escalates, so the security invariant is unaffected. Prefer the
  most-specific globs on the parent grant.
