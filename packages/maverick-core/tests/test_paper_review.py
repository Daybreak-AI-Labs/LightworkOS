"""Vendor-paper review: instrument classification, deterministic gap finding,
and model-drafted clause language that can never weaken our position."""
from __future__ import annotations

import json

from maverick import paper_review as pr

DPA_TEXT = """DATA PROCESSING AGREEMENT
This Data Processing Agreement is entered into pursuant to Article 28 GDPR.
1. Processor shall process personal data only on documented instructions from the Controller.
2. Personnel authorised to process personal data are bound by confidentiality undertakings.
3. Processor may engage sub-processors at its sole discretion without notice to the Controller.
4. Processor shall notify the Controller of a personal data breach without undue delay.
5. Personal data may be transferred to third countries at Processor's discretion.
"""

ADDENDUM_TEXT = """PRIVACY ADDENDUM (CCPA)
This Addendum reflects the California Consumer Privacy Act as amended by the CPRA.
1. Service Provider processes personal information for the specified business purpose only.
2. Service Provider shall not sell personal information.
3. Service Provider may combine personal information with data from other sources.
"""


def test_classifies_a_gdpr_dpa():
    c = pr.classify_instrument(DPA_TEXT, filename="Acme-DPA.docx")
    assert c["instrument"] == "dpa" and c["confidence"] == "high"
    assert c["dpa_score"] > c["addendum_score"]


def test_classifies_a_ccpa_addendum():
    c = pr.classify_instrument(ADDENDUM_TEXT, filename="Acme-Privacy-Addendum.pdf")
    assert c["instrument"] == "addendum"
    assert c["addendum_score"] > c["dpa_score"]


def test_unrecognisable_document_defaults_to_the_stronger_instrument():
    c = pr.classify_instrument("This is a mutual non-disclosure agreement.")
    assert c["instrument"] == "dpa" and c["confidence"] == "low"
    assert "human must confirm" in c["reason"]


def test_deterministic_gaps_against_the_article_28_checklist():
    r = pr.analyze(DPA_TEXT, vendor="Acme", document_name="Acme-DPA.docx")
    assert r.instrument == "dpa"
    by_key = {c.clause_key: c for c in r.concerns}
    # Stated plainly -> present.
    assert by_key["instructions"].status == "present"
    assert by_key["confidentiality"].status == "present"
    # Absent from the document -> missing, and it is a real gap.
    assert by_key["audit"].status == "missing"
    assert by_key["audit"] in r.gaps
    # Every clause carries our standard position as the proposed language.
    assert by_key["audit"].proposed == pr.OUR_POSITIONS["audit"]
    assert r.clauses_total == 10 and r.gaps


def test_negated_clause_is_flagged_unclear_not_credited():
    # The clause pattern matches, but the sentence negates it -- crediting this
    # as satisfied would be the worst possible failure mode.
    text = ("DATA PROCESSING AGREEMENT under Article 28 GDPR.\n"
            "Processor shall not delete or return personal data at the end of "
            "the provision of services.\n")
    r = pr.analyze(text)
    status = {c.clause_key: c.status for c in r.concerns}
    assert status["deletion"] in ("unclear", "conflicting")
    assert any(c.clause_key == "deletion" for c in r.gaps)


def test_permissive_language_is_conflicting_not_present():
    # THE case that presence-detection alone gets wrong: the paper mentions
    # sub-processors, so a "does it mention X" check scores it satisfied, while
    # the sentence actually grants the vendor the right our template withholds.
    r = pr.analyze(DPA_TEXT)
    sub = next(c for c in r.concerns if c.clause_key == "subprocessors")
    assert sub.status == "conflicting"
    assert sub.severity == "high"          # escalated: worse than an omission
    assert "sole discretion" in sub.their_language
    assert sub in r.gaps


def test_adverse_scan_is_topic_scoped_so_clauses_do_not_steal_anchors():
    # "sole discretion" appears in BOTH sentences. Without topic scoping the
    # transfers clause anchors onto the sub-processor paragraph, the two edits
    # collide on one paragraph, and one of them silently goes unapplied.
    text = ("DATA PROCESSING AGREEMENT under Article 28 GDPR.\n"
            "2. Processor may engage sub-processors at its sole discretion.\n"
            "3. Personal data may be transferred to any third country at "
            "Processor's sole discretion.\n")
    r = pr.analyze(text)
    by_key = {c.clause_key: c for c in r.concerns}
    assert by_key["subprocessors"].status == "conflicting"
    assert by_key["transfers"].status == "conflicting"
    assert "sub-processors" in by_key["subprocessors"].their_language
    assert "third country" in by_key["transfers"].their_language
    # Distinct anchors -> both edits actually land.
    from maverick import docx_redline as dr
    res = dr.build_redlined_docx([p for p in text.split("\n") if p.strip()],
                                 r.edits(), date="2026-07-27T12:00:00Z")
    assert len(res.applied) == 2 and not res.unmatched


def test_conflicting_addendum_clause_is_caught():
    r = pr.analyze(ADDENDUM_TEXT)
    combining = next(c for c in r.concerns if c.clause_key == "no_combining")
    assert combining.status == "conflicting"
    assert "may combine" in combining.their_language.lower()


def test_addendum_uses_the_ccpa_checklist():
    r = pr.analyze(ADDENDUM_TEXT, vendor="Acme")
    assert r.instrument == "addendum"
    keys = {c.clause_key for c in r.concerns}
    assert "no_sale" in keys and "instructions" not in keys
    by_key = {c.clause_key: c for c in r.concerns}
    assert by_key["no_sale"].status == "present"
    assert by_key["noncompliance_notice"].status == "missing"


def test_edits_anchor_on_the_vendors_own_paragraph():
    r = pr.analyze(DPA_TEXT)
    edits = r.edits()
    subproc = [e for e in edits if e.clause_key == "subprocessors"]
    assert subproc, "the weak sub-processor clause must produce an edit"
    # The anchor is the vendor's ACTUAL sentence, in original case, so the
    # redline lands on their paragraph rather than appending a stray clause.
    assert "sole discretion" in subproc[0].find
    assert subproc[0].find in DPA_TEXT
    # A wholly absent clause becomes an insertion, not a bogus replacement.
    audit = [e for e in edits if e.clause_key == "audit"][0]
    assert audit.is_insertion and audit.replace


def test_recommendation_is_deterministic_from_severity():
    r = pr.analyze(DPA_TEXT)
    assert r.high_severity_gaps > 0
    assert r.recommendation == "do_not_sign_without_changes"
    clean = pr.PaperReview(vendor="X", instrument="dpa")
    assert clean.recommendation == "acceptable"


def test_review_without_a_model_still_produces_complete_language(monkeypatch):
    # No provider key in the environment: every proposed clause must still be
    # our full template text, never an empty stub.
    def unavailable(*_args, **_kwargs):
        raise RuntimeError("model unavailable in this deterministic test")

    monkeypatch.setattr("maverick.llm.LLM", unavailable)
    r = pr.review_paper(DPA_TEXT, vendor="Acme", use_model=True)
    assert not r.drafted_with_model
    for c in r.gaps:
        assert c.proposed and c.drafted_by == "template"


class _Resp:
    def __init__(self, text):
        self.text = text


class _FakeLLM:
    def __init__(self, reply):
        self._reply = reply
        self.calls = 0

    def complete(self, **kw):
        self.calls += 1
        return _Resp(self._reply)


def _patch_llm(monkeypatch, fake):
    from maverick import llm as llm_mod
    monkeypatch.setattr(llm_mod, "LLM", lambda *a, **k: fake)
    monkeypatch.setattr(llm_mod, "model_for_role", lambda role: "claude-opus-4-8")


def test_model_draft_is_used_when_it_preserves_our_position(monkeypatch):
    good = ("Supplier shall not appoint any Sub-Processor without the Customer's "
            "prior written authorisation and shall impose equivalent obligations "
            "on each Sub-Processor, notify Customer, and remain liable.")
    fake = _FakeLLM(good)
    _patch_llm(monkeypatch, fake)
    r = pr.analyze(DPA_TEXT)
    r = pr.draft_language(r)
    assert fake.calls > 0 and r.drafted_with_model
    sub = next(c for c in r.concerns if c.clause_key == "subprocessors")
    assert sub.proposed == good and sub.drafted_by == "model"


def test_model_draft_that_weakens_our_position_is_rejected(monkeypatch):
    # Drops "not"/"without"/"prior written" -- exactly the terms that carry the
    # obligation. Our template language must survive instead.
    weak = ("Supplier may appoint Sub-Processors and will use commercially "
            "reasonable efforts to tell the Customer about them at some point.")
    _patch_llm(monkeypatch, _FakeLLM(weak))
    r = pr.draft_language(pr.analyze(DPA_TEXT))
    sub = next(c for c in r.concerns if c.clause_key == "subprocessors")
    assert sub.proposed == pr.OUR_POSITIONS["subprocessors"]
    assert sub.drafted_by == "template" and not r.drafted_with_model


def test_model_commentary_and_markdown_are_rejected(monkeypatch):
    _patch_llm(monkeypatch, _FakeLLM("## Suggested clause\n- Processor shall..."))
    r = pr.draft_language(pr.analyze(DPA_TEXT))
    assert all(c.drafted_by == "template" for c in r.gaps)


def test_model_never_changes_the_gap_list(monkeypatch):
    before = {c.clause_key: c.status for c in pr.analyze(DPA_TEXT).concerns}
    _patch_llm(monkeypatch, _FakeLLM(
        "Processor shall not do the thing without prior written notice, shall "
        "notify, shall delete, shall encrypt, shall audit within seventy-two "
        "hours, with equivalent obligations."))
    after = {c.clause_key: c.status
             for c in pr.draft_language(pr.analyze(DPA_TEXT)).concerns}
    assert before == after


def test_to_dict_is_report_ready():
    d = pr.review_paper(DPA_TEXT, vendor="Acme", use_model=False).to_dict()
    assert d["instrument_label"] == "Data Processing Agreement"
    assert d["gaps"] and d["recommendation"] and d["concerns"]
    assert d["clauses_total"] == 10


def test_config_can_forbid_the_model_from_seeing_contracts(monkeypatch, tmp_path):
    # An operator who says no must get template language and no model call at
    # all -- "no model touches our contracts" has to be enforceable.
    from maverick import config
    cfg = tmp_path / "config.toml"
    cfg.write_text("[paper_review]\nuse_model = false\n", encoding="utf-8")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    config.reset_config_cache()
    fake = _FakeLLM("Processor shall not do anything without prior written "
                    "notice and shall notify, delete, encrypt, audit.")
    _patch_llm(monkeypatch, fake)
    try:
        r = pr.review_paper(DPA_TEXT, vendor="Acme")
        assert fake.calls == 0 and not r.drafted_with_model
        assert all(c.drafted_by == "template" for c in r.gaps)
        # The findings themselves are unchanged by the knob.
        assert r.gaps and r.recommendation == "do_not_sign_without_changes"
    finally:
        config.reset_config_cache()


# --- the operator's clause playbook (the setup path) ----------------------

def test_playbook_defaults_to_the_shipped_positions(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import config
    config.reset_config_cache()
    try:
        assert not pr.playbook_path().exists()
        assert pr.load_playbook() == pr.default_playbook()
    finally:
        config.reset_config_cache()


def test_written_playbook_overrides_only_what_it_names(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import config
    config.reset_config_cache()
    try:
        mine = "Supplier shall not appoint any Sub-Processor without consent."
        pr.write_playbook({**pr.default_playbook(), "subprocessors": mine})
        active = pr.load_playbook()
        assert active["subprocessors"] == mine
        # Everything untouched still carries our language.
        assert active["audit"] == pr.OUR_POSITIONS["audit"]
        # And it is the language the redline actually demands.
        r = pr.analyze("DATA PROCESSING AGREEMENT under Article 28 GDPR.\n"
                       "Processor may engage sub-processors at its sole "
                       "discretion.\n")
        sub = next(c for c in r.concerns if c.clause_key == "subprocessors")
        assert sub.proposed == mine
    finally:
        config.reset_config_cache()


def test_a_broken_playbook_degrades_to_the_shipped_positions(
        tmp_path, monkeypatch):
    # A syntactically broken or half-written playbook must never leave a
    # redline with empty clauses -- that would send a vendor a blank demand.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import config
    config.reset_config_cache()
    try:
        path = pr.playbook_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{ not json at all", encoding="utf-8")
        assert pr.load_playbook() == pr.default_playbook()
        path.write_text('{"positions": "not an object"}', encoding="utf-8")
        assert pr.load_playbook() == pr.default_playbook()
        # Empty values are ignored rather than blanking a clause.
        path.write_text('{"positions": {"audit": "   "}}', encoding="utf-8")
        assert pr.load_playbook()["audit"] == pr.OUR_POSITIONS["audit"]
    finally:
        config.reset_config_cache()


def test_playbook_path_is_configurable(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    custom = tmp_path / "legal" / "our-clauses.json"
    # JSON string escaping is compatible with a TOML basic string. In
    # particular, it doubles Windows path separators instead of emitting
    # invalid TOML escapes such as ``\U`` from ``C:\Users``.
    cfg.write_text(
        f"[paper_review]\nplaybook_path = {json.dumps(str(custom))}\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick import config
    config.reset_config_cache()
    try:
        assert pr.playbook_path() == custom
        pr.write_playbook({**pr.default_playbook(), "audit": "Our audit text."})
        assert custom.exists()
        assert pr.load_playbook()["audit"] == "Our audit text."
    finally:
        config.reset_config_cache()


def test_analysis_memo_is_shared_and_states_its_limits():
    r = pr.review_paper(DPA_TEXT, vendor="Acme", document_name="a.docx",
                        use_model=False)
    memo = pr.analysis_memo(r, version=3, reviewed_by="A. Novak",
                            redline_filename="acme-dpa-redline.docx")
    assert "VENDOR PAPER REVIEW — Acme  (v3)" in memo
    assert "A. Novak" in memo and "acme-dpa-redline.docx" in memo
    assert "CONFLICTS WITH OUR POSITION" in memo
    assert "a model cannot create or clear a finding" in memo


def test_analysis_memo_explains_refused_redline_scope():
    from maverick import docx_redline as dr

    anchor = "Processor may engage subcontractors without prior approval."
    wrapped = "8.2. " + anchor + " All other duties survive."
    result = dr.build_redlined_docx([wrapped], [
        dr.ClauseEdit(find=anchor, replace="Prior approval is required.")],
        date="2026-09-22T12:00:00Z")
    review = pr.review_paper(DPA_TEXT, vendor="Acme", use_model=False)
    memo = pr.analysis_memo(review, redline_result=result)
    assert "manual review" in memo
    assert "Edit 1: The anchor covers only part of a paragraph" in memo
    assert "Supply the complete paragraph and replacement" in memo


# --- drafting OUR paper (the vendor signs our template) --------------------

def _draft_doc_xml(content: bytes) -> str:
    import io
    import zipfile
    return zipfile.ZipFile(io.BytesIO(content)).read(
        "word/document.xml").decode()


def test_draft_our_paper_fills_values_in_red(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import config
    config.reset_config_cache()
    try:
        d = pr.draft_our_paper("Acme Corp", instrument="dpa",
                               org="Globex Holdings LLC",
                               effective_date="2026-08-02")
        assert d.instrument == "dpa" and d.clause_count == 10
        assert d.filled == ["processor: Acme Corp",
                            "controller: Globex Holdings LLC",
                            "effective date: 2026-08-02"]
        doc = _draft_doc_xml(d.content)
        from maverick.docx_redline import FILL_COLOR, revision_count
        # Every auto-filled value is a red run; template language is not.
        assert doc.count(f'w:val="{FILL_COLOR}"') >= 5
        assert "Acme Corp" in doc and "Globex Holdings LLC" in doc
        # The body is our standard clause language (the 72h breach term).
        assert "seventy-two (72) hours" in doc
        # A draft is a clean document -- no fabricated tracked changes.
        assert revision_count(d.content) == (0, 0)
    finally:
        config.reset_config_cache()


def test_draft_without_values_keeps_red_placeholders(tmp_path, monkeypatch):
    # A missing org or date must never be guessed: it stays a bracketed
    # placeholder, still rendered red so counsel cannot miss it.
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import config
    config.reset_config_cache()
    try:
        d = pr.draft_our_paper("", instrument="dpa")
        doc = _draft_doc_xml(d.content)
        assert "[CONTROLLER LEGAL ENTITY]" in doc
        assert "[PROCESSOR LEGAL ENTITY]" in doc
        assert "[EFFECTIVE DATE]" in doc
    finally:
        config.reset_config_cache()


def test_draft_org_name_comes_from_config(tmp_path, monkeypatch):
    cfg = tmp_path / "config.toml"
    cfg.write_text('[paper_review]\norg_name = "Daybreak Labs, Inc."\n',
                   encoding="utf-8")
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    from maverick import config
    config.reset_config_cache()
    try:
        d = pr.draft_our_paper("Acme Corp")
        assert "controller: Daybreak Labs, Inc." in d.filled
        assert "Daybreak Labs, Inc." in _draft_doc_xml(d.content)
    finally:
        config.reset_config_cache()


def test_draft_respects_the_operator_playbook(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import config
    config.reset_config_cache()
    try:
        mine = "Supplier shall not appoint any Sub-Processor without consent."
        pr.write_playbook({**pr.default_playbook(), "subprocessors": mine})
        doc = _draft_doc_xml(pr.draft_our_paper("Acme Corp").content)
        assert mine in doc
        assert pr.OUR_POSITIONS["subprocessors"] not in doc
    finally:
        config.reset_config_cache()


def test_draft_addendum_uses_service_provider_terms(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    from maverick import config
    config.reset_config_cache()
    try:
        d = pr.draft_our_paper("Vendor X", instrument="addendum")
        doc = _draft_doc_xml(d.content)
        assert "CCPA/CPRA SERVICE-PROVIDER ADDENDUM" in doc
        assert "[BUSINESS LEGAL ENTITY]" in doc
        assert "Cal. Civ. Code" in doc      # the checklist citations
        try:
            pr.draft_our_paper("Vendor X", instrument="nda")
            raise AssertionError("unknown instrument must be rejected")
        except ValueError:
            pass
    finally:
        config.reset_config_cache()


# --- the negotiation round-trip in the memo --------------------------------

def test_memo_reports_negotiation_progress():
    r = pr.review_paper(DPA_TEXT, vendor="Acme", use_model=False)
    memo = pr.analysis_memo(
        r, version=2, closed_from_previous=[
            "Sub-processor authorization and flow-down"], previous_version=1)
    assert "NEGOTIATION PROGRESS" in memo
    assert "closes 1 of the change(s) we demanded in v1" in memo
    assert "+ Sub-processor authorization and flow-down" in memo
    # Nothing accepted reads as exactly that -- not as silence.
    memo2 = pr.analysis_memo(r, version=2, closed_from_previous=[],
                             previous_version=1)
    assert "None of the changes we demanded in v1" in memo2
    # A first round has no progress section at all.
    memo3 = pr.analysis_memo(r, version=1)
    assert "NEGOTIATION PROGRESS" not in memo3


def test_requirement_labels_cover_both_instruments():
    dpa = pr.requirement_labels("dpa")
    add = pr.requirement_labels("addendum")
    assert dpa["subprocessors"] == "Sub-processor authorization and flow-down"
    assert "no_sale" in add and "limited_purpose" in add
