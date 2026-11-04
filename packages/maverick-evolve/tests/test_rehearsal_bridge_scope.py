"""The evolve rehearsal bridge must only replay LOCAL-scope
prompts, mirroring the kernel's dreaming.load_rehearsals trust filter."""
from __future__ import annotations

import json

from maverick_evolve.rehearsal_bridge import cases_from_rehearsals


def test_only_local_scope_rows_replayed(tmp_path):
    p = tmp_path / "rehearsals.ndjson"
    rows = [
        {"prompt": "local task", "scope": "local", "evidence": 3},
        {"prompt": "remote/untrusted task", "scope": "remote", "evidence": 9},
        {"prompt": "legacy no-scope task", "evidence": 5},  # ambiguous -> refuse
    ]
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    cases = cases_from_rehearsals(p)
    prompts = {c.prompt for c in cases}
    assert prompts == {"local task"}
    assert "remote/untrusted task" not in prompts
    assert "legacy no-scope task" not in prompts
