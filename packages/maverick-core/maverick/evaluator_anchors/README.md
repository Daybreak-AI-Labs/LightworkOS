# Evaluator ground-truth anchors

Each `*.ndjson` file here is the fixed, held-out **anchor** for one evaluator
role (the file stem is the role, e.g. `paper_reviewer.ndjson`). It is the
ground truth a learned evaluator must agree with before it can be promoted over
the incumbent — see `maverick.evaluator_evolution`.

One JSON object per line:

```json
{"id": "rev-0001", "label": true,  "prompt": "<optional artifact text>"}
{"id": "rev-0002", "label": false, "prompt": "..."}
```

- `id` — stable identifier for the datum (immutable once released).
- `label` — the correct verdict (e.g. accept = `true`, reject = `false`).
- `prompt` — optional context shown to the evaluator. Because it changes what the
  evaluator sees, it is included in the released checksum with `id` and `label`.

## The anchor is the guardrail

A weak, mutable, or poisoned anchor turns provable learning into laundered
drift (arXiv 2606.26294). Released anchors are therefore **immutable**, pinned
by checksum in `../evaluator_anchors.lock.json` exactly as released world-model
migrations are. After adding a separately versioned anchor, regenerate the lock
so the addition is reviewed:

```
python -m maverick.evaluator_evolution --regen   # rewrite the lock
python -m maverick.evaluator_evolution --ci       # CI gate: fail on any drift
```

Missing locks, malformed or empty anchor files, unregistered roles, and edits to
any released evaluator-visible field fail closed before anchor scoring.

The repository ships `self_harness_protocol_v1.ndjson`, a balanced synthetic
regression anchor for the self-harness evaluator boundary. It makes the lock and
CI path non-vacuous and reproducible in every checkout. It is not customer,
provider, regulator, or independently administered ground truth, and passing it
does not qualify a production evaluator. Deployment-specific final anchors must
be separately versioned, independently curated, added without changing a
released role, and reviewed together with the regenerated lock.
