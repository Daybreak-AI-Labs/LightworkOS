"""Specialist routing with the real local embedding model (FastEmbed).

Every other routing test pins the lexical fallback or injects a fake embedder,
so this is the one that proves the optional model path works end to end: the
configured FastEmbed model loads, embeds all 2,031 shipped packs, and its
semantic scores route paraphrases that share no useful words with the right
pack. It needs the model files on disk; the optional-heavy CI job restores
them from its cache and runs this with HF_HUB_OFFLINE=1, so the test itself
makes no network request. Building the roster index is real ONNX inference:
about 35 seconds on two cores, hence the longer timeout.
"""
from __future__ import annotations

import pytest

pytest.importorskip("fastembed")

from maverick import domain_router  # noqa: E402
from maverick.domain import builtin_dir, load_domains  # noqa: E402
from maverick.skill import embeddings  # noqa: E402

_PACKS = load_domains(builtin_dir())

# (paraphrase, the pack that serves it). Each target shares no useful term
# with its query: the lexical index alone ranks it 29th or not at all.
_PARAPHRASES = [
    ("our servers went dark and customers cannot log in", "cx_outage_comms"),
    ("check whether this new hire's résumé fits the opening", "hr_resume_screening"),
    ("my house flooded, how do I get reimbursed", "ins_flood_quota"),
]


@pytest.mark.timeout(600)
def test_real_model_embeds_the_roster_and_routes_paraphrases(monkeypatch):
    monkeypatch.setattr(domain_router, "_CACHE", None)  # build, do not reuse
    model = embeddings._get_model()
    assert model is not None, (
        f"FastEmbed could not load {embeddings.MODEL_NAME}; the job fetches it "
        "before the tests run (FASTEMBED_CACHE_PATH)"
    )

    lexical, semantic = domain_router._indexes(_PACKS)
    assert semantic is not None and semantic.available
    assert set(semantic.vectors) == set(_PACKS)
    assert {len(vector) for vector in semantic.vectors.values()} == {384}

    for query, pack in _PARAPHRASES:
        assert pack not in [name for name, _ in lexical.rank(query, k=20)], query
        hybrid = [name for name, _ in domain_router.rank_specialists(query, k=3, domains=_PACKS)]
        assert pack in hybrid, (query, hybrid)

    # A plain job description still routes to its specialist first.
    ap = domain_router.rank_specialists(
        "Accounts payable specialist: process vendor invoices, three-way match, "
        "reconcile statements, prepare payment runs", k=5, domains=_PACKS,
    )
    assert ap[0][0] == "finance_ap", ap
