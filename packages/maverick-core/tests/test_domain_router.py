"""Specialist routing: lexical retrieval over the 1,118-pack roster.

The router is a deterministic pre-filter that narrows the roster to a relevant
shortlist for a task, so the orchestrator picks from ~10 candidates instead of
guessing a suite and browsing it. These tests are the routing BENCHMARK: a
labeled set of realistic task phrasings (no pack-name leakage) with the set of
acceptable specialists for each, asserting recall@10 -- the pre-filter goal --
and suite accuracy stay above a floor, so a future pack/persona edit can't
silently degrade routing.
"""
from __future__ import annotations

from maverick.domain import builtin_dir, load_domains, suite_for
from maverick.domain_router import DomainRouter, rank_specialists

_PACKS = load_domains(builtin_dir())
_ROUTER = DomainRouter(_PACKS)

# (task phrased as a user would, acceptable specialist set, expected suite).
# Multiple packs are acceptable on purpose: with 1,118 specialists several are
# legitimately right for one task, so exact top-1 would understate the router.
_CASES: list[tuple[str, set[str], str]] = [
    ("review this NDA and flag the liability cap and indemnity clauses",
     {"legal_contract_review", "legal_nda_desk"}, "legal"),
    ("do a three-way match on these invoices before we pay the vendor",
     {"finance_ap"}, "finance"),
    ("build a 13 week cash flow forecast",
     {"finance_cash13w", "finance_cashflow"}, "finance"),
    ("screen these resumes against the job rubric", {"hr_screening"}, "hr"),
    ("an employee filed a harassment complaint, help me investigate",
     {"hr_investigations", "hr_employee_relations", "hr_er_intake"}, "hr"),
    ("triage this inbound support ticket and suggest a reply",
     {"cx_triage", "cx_tech_support"}, "customer_experience"),
    ("a customer wants a refund outside policy", {"cx_refunds"}, "customer_experience"),
    ("write an outbound cold email sequence for these prospects",
     {"gtm_outbound_sdr", "gtm_sequencing"}, "sales_gtm"),
    ("our SOC 2 audit needs evidence collected",
     {"itgrc_soc2_evidence", "itgrc_evidence"}, "it_grc"),
    ("a vendor wants access to our data, assess the third party risk",
     {"itgrc_vendor_risk", "itgrc_vendor_monitoring"}, "it_grc"),
    ("investigate this security alert from the SIEM",
     {"itgrc_siem_triage", "sec_soc_triage", "itgrc_threat_detection"}, "it_grc"),
    ("plan the sprint and groom the backlog",
     {"pe_backlog", "pe_roadmap"}, "product_engineering"),
    ("review this pull request for bugs",
     {"pe_code_review", "pe_bug_triage"}, "product_engineering"),
    ("the production service is down, run the incident",
     {"pe_sre_incident_commander", "pe_release_chaos"}, "product_engineering"),
    ("prior authorization for an MRI from the payer", {"hc_prior_auth"}, "healthcare"),
    ("file a claim for water damage on a property policy",
     {"ins_fnol", "ins_claim_file"}, "insurance"),
    ("a wire transfer looks suspicious, check for AML",
     {"bank_aml_alerts", "bank_wire_review", "bank_sar_prep"}, "banking"),
    ("reconcile the month end general ledger close",
     {"finance_gl_close", "finance_close_driver"}, "finance"),
    ("draft a press release for the product launch", {"mkt_pr_comms", "gtm_pr"}, "marketing"),
    ("negotiate pricing on this supplier contract",
     {"proc_sourcing", "proc_should_cost", "gtm_negotiation"}, "procurement"),
    ("value this acquisition target",
     {"strat_valuation", "strat_ma_modeling", "strat_due_diligence"}, "strategy"),
    ("respond to an IRS notice for a client", {"tax_irs_notice"}, "tax"),
    ("schedule preventive maintenance on the line equipment",
     {"ops_maintenance_pm", "mfg_maintenance_pm"}, "operations"),
    ("a shipment is delayed, chase the carrier for an ETA",
     {"log_track_trace", "log_eta_comms"}, "logistics"),
    ("check this construction change order and pay application",
     {"con_pay_apps", "con_change_orders"}, "construction"),
]


def _metrics():
    n = len(_CASES)
    hit1 = rec10 = suite1 = 0
    for query, acceptable, suite in _CASES:
        ranked = [name for name, _ in _ROUTER.rank(query, k=10)]
        if ranked and ranked[0] in acceptable:
            hit1 += 1
        if any(name in acceptable for name in ranked):
            rec10 += 1
        if ranked and suite_for(ranked[0]) == suite:
            suite1 += 1
    return n, hit1, rec10, suite1


def test_recall_at_10_meets_the_prefilter_floor():
    # The pre-filter's job: a valid specialist is in the shortlist it surfaces.
    n, _, rec10, _ = _metrics()
    assert rec10 / n >= 0.80, f"recall@10 = {rec10}/{n}"


def test_top1_and_suite_accuracy_meet_floor():
    n, hit1, _, suite1 = _metrics()
    assert hit1 / n >= 0.50, f"hit@1 = {hit1}/{n}"
    assert suite1 / n >= 0.60, f"suite@1 = {suite1}/{n}"


def test_rank_is_deterministic_and_bounded():
    a = _ROUTER.rank("review this NDA", k=5)
    b = _ROUTER.rank("review this NDA", k=5)
    assert a == b              # pure / stable
    assert len(a) <= 5
    assert all(s > 0 for _, s in a)  # no zero-score padding


def test_offroster_query_returns_nothing():
    # A query with no roster vocabulary returns an empty shortlist, not noise.
    assert _ROUTER.rank("zzzqqq xqzptl", k=10) == []


def test_module_level_cache_matches_fresh_index():
    ranked = rank_specialists("draft a press release", k=5, domains=_PACKS)
    assert [n for n, _ in ranked][:3] == [
        n for n, _ in _ROUTER.rank("draft a press release", k=5)][:3]


def test_router_refreshes_when_a_pack_changes_without_a_new_name():
    from maverick.domain import DomainProfile

    original = {
        "alpha": DomainProfile(name="alpha", description="invoice reconciliation"),
        "beta": DomainProfile(name="beta", description="customer support"),
    }
    revised = {
        "alpha": DomainProfile(name="alpha", description="customer support"),
        "beta": DomainProfile(name="beta", description="invoice reconciliation"),
    }
    assert rank_specialists("invoice", domains=original, alpha=0.0)[0][0] == "alpha"
    assert rank_specialists("invoice", domains=revised, alpha=0.0)[0][0] == "beta"


# --- Embedding / hybrid path (validated with an injected fake embedder, since
#     fastembed is optional and absent in CI's lightweight subset) -----------
import re as _re  # noqa: E402

from maverick.domain import DomainProfile  # noqa: E402
from maverick.domain_router import EmbeddingRouter, _blend  # noqa: E402

# A controllable "semantic" embedder: maps synonym sets to shared concept dims,
# so paraphrases that share no surface tokens still embed close (what a real
# sentence-transformer buys us over lexical).
_CONCEPTS = {
    "separation": {"terminate", "termination", "fire", "layoff", "offboard",
                   "offboarding", "rif"},
    "nda": {"nda", "confidentiality", "nondisclosure", "secrecy"},
    "payable": {"invoice", "payable", "vendor", "bill"},
}


def _fake_embed(texts):
    out = []
    for t in texts:
        toks = set(_re.findall(r"[a-z]+", (t or "").lower()))
        out.append([1.0 if (syns & toks) else 0.0 for syns in _CONCEPTS.values()])
    return out


def _toy_domains():
    return {
        "hr_offboarding": DomainProfile(
            name="hr_offboarding", description="employee offboarding and exit",
            persona="You run offboarding and termination logistics for departing staff."),
        "legal_nda_desk": DomainProfile(
            name="legal_nda_desk", description="confidentiality agreements",
            persona="You process NDAs and confidentiality and secrecy obligations."),
        "finance_ap": DomainProfile(
            name="finance_ap", description="accounts payable",
            persona="You match each vendor invoice and stage the payable."),
    }


def test_embedding_router_ranks_paraphrase_without_shared_tokens():
    r = EmbeddingRouter(_toy_domains(), embed_fn=_fake_embed)
    assert r.available
    # "let someone go" shares no surface tokens with the offboarding pack, but
    # the synonym concept ("fire") makes it the top semantic match.
    scores = r.score_all("we need to fire a staff member")
    assert max(scores, key=scores.get) == "hr_offboarding"


def test_embedding_router_unavailable_without_a_model():
    r = EmbeddingRouter(_toy_domains(), embed_fn=lambda _t: None)
    assert not r.available
    assert r.score_all("anything") == {}


def test_blend_reranks_toward_semantic():
    lexical = {"a": 10.0, "b": 1.0}     # lexical loves a
    semantic = {"a": 0.1, "b": 1.0}     # semantic loves b
    blended = _blend(lexical, semantic, alpha=0.8)
    assert blended["b"] > blended["a"]  # high alpha -> semantic wins


def test_blend_with_no_semantic_is_lexical_unchanged():
    lexical = {"a": 3.0, "b": 1.0}
    assert _blend(lexical, {}, alpha=0.6) == lexical


def test_rank_specialists_falls_back_to_lexical_when_no_embedder(monkeypatch):
    # With the embedder forced unavailable, hybrid == the lexical ranking, so
    # the benchmark still holds (no regression from adding the embedding path).
    import maverick.domain_router as dr
    monkeypatch.setattr(dr, "EmbeddingRouter",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no model")))
    hybrid = [n for n, _ in rank_specialists("review an NDA", k=5, domains=_PACKS)]
    lexical = [n for n, _ in _ROUTER.rank("review an NDA", k=5)]
    assert hybrid == lexical


def test_rank_specialists_caches_explicit_domain_embedding_index(monkeypatch):
    # list_specialists passes an explicit enabled-domain roster; that path must
    # reuse the module cache so repeated user queries do not re-embed every pack.
    import maverick.domain_router as dr

    calls = []

    def counting_embed(texts):
        calls.append(len(texts))
        return [[1.0] for _ in texts]

    class CountingEmbeddingRouter(dr.EmbeddingRouter):
        def __init__(self, domains):
            super().__init__(domains, embed_fn=counting_embed)

    monkeypatch.setattr(dr, "_CACHE", None)
    monkeypatch.setattr(dr, "EmbeddingRouter", CountingEmbeddingRouter)

    dr.rank_specialists("review an NDA", k=3, domains=_PACKS)
    dr.rank_specialists("draft a press release", k=3, domains=_PACKS)

    assert calls == [len(_PACKS), 1, 1]


def test_concurrent_build_for_another_roster_cannot_leak_into_this_one(monkeypatch):
    # Simulate a second request finishing its build while this one is between
    # building its index and publishing it.
    import maverick.domain_router as dr
    from maverick.domain import DomainProfile

    mine = {"alpha_pack": DomainProfile(name="alpha_pack", description="review an NDA")}
    theirs = {"beta_secret": DomainProfile(name="beta_secret", description="review an NDA")}
    monkeypatch.setattr(dr, "_CACHE", None)
    interleaved = []

    def embedding(domains):
        if not interleaved:
            interleaved.append(True)
            dr._indexes(theirs)
        raise RuntimeError("no model")

    monkeypatch.setattr(dr, "EmbeddingRouter", embedding)
    assert [n for n, _ in dr.rank_specialists("review an NDA", domains=mine)] == ["alpha_pack"]
    assert [n for n, _ in dr.rank_specialists("review an NDA", domains=mine)] == ["alpha_pack"]
