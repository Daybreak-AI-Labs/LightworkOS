"""Learned-capability ledger panel + generated-tool removal."""
from __future__ import annotations

import hashlib
import json
import time

from fastapi.testclient import TestClient


def _client():
    from maverick_dashboard.app import app
    return TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def _isolate(monkeypatch, tmp_path):
    """Point the self-learning ledger + generated-tools dir at tmp_path."""
    from maverick import self_learning, world_model
    from maverick.safety import consent

    ledger = tmp_path / "learned.ndjson"
    gen = tmp_path / "generated_tools"
    gen.mkdir()
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setitem(self_learning.__dict__, "LEARNED_PATH", ledger)
    monkeypatch.setitem(self_learning.__dict__, "GENERATED_TOOLS_DIR", gen)
    monkeypatch.setattr(
        consent,
        "CONSENT_LEDGER_PATH",
        tmp_path / "consent.ledger",
    )
    monkeypatch.delenv("MAVERICK_DASHBOARD_TOKEN", raising=False)
    return ledger, gen


def _owned_source(target, source, *, consented=True):
    """Create a newly published, explicitly local synthetic source."""
    from maverick.learning_content import lineage, publish
    from maverick.safety import consent
    target.write_text(source, encoding="utf-8")
    publish(target, source, lineage())
    if consented:
        digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        consent.grant_persistent("register-generated-tool", scope=f"shared:{target.stem}:{digest}")


def _write_ledger(path, entries):
    path.write_text("".join(json.dumps({"content_version": 1, "owner": "", "goal_id": None, **e}) + "\n" for e in entries), encoding="utf-8")


def _write_shared_guidance(blocks, store, *, metadata=None):
    """Seed newly authored local guidance with the required source receipts."""
    from maverick import self_harness as sh

    sh._write_addenda(blocks, store)
    meta = dict(metadata or {})
    for key, block in blocks.items():
        for line in sh._bullets(block):
            provenance = meta.get(sh._line_id(key, line), {})
            sh._upsert_line_meta(
                meta, key, line, {**provenance, "source_goal_ids": [0]},
                now=provenance.get("updated_at", time.time()),
            )
    sh._write_line_meta(meta, store)


def _shared_case(goal, expected):
    return {"goal": goal, "expected": expected,
            "privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [0]}


def test_snapshot_uses_verified_request_owner_without_admin_bypass(monkeypatch, tmp_path):
    from maverick import self_learning
    from maverick.connections import bind_principal
    from maverick_dashboard import api

    ledger, _gen = _isolate(monkeypatch, tmp_path)
    with bind_principal("user:employee"):
        self_learning.record("employee private task", "skill", "employee_skill", path=ledger)
    request = object()
    monkeypatch.setattr(api, "goal_owner_filter", lambda req: "user:admin")
    assert api._learned_snapshot(request=request)["learned"] == []
    monkeypatch.setattr(api, "goal_owner_filter", lambda req: "user:employee")
    assert api._learned_snapshot(request=request)["learned"][0]["name"] == "employee_skill"


def test_learned_panel_renders_ledger_entries(monkeypatch, tmp_path):
    ledger, _gen = _isolate(monkeypatch, tmp_path)
    _write_ledger(ledger, [
        {"ts": time.time(), "need": "send an sms", "kind": "tool",
         "name": "send_sms", "source": "generated", "outcome": "acquired"},
        {"ts": time.time(), "need": "scrape a page", "kind": "skill",
         "name": "web_scrape", "source": "catalog", "outcome": "failed"},
    ])
    text = _client().get("/learned").text
    assert "learned skills and tools" in text.lower()
    assert "Send sms" in text
    assert "Web scrape" in text
    assert "send an sms" in text
    assert "Added" in text and "Failed" in text
    from test_support.plain_language import developer_terms
    assert developer_terms(text) == []


def test_learned_page_renders_empty(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    text = _client().get("/learned").text
    assert "Nothing learned yet" in text and "Turn on self-learning" in text
    assert "Checking your retained tools" in text and 'id="generated-tools"' in text
    listing = _client().get("/api/v1/generated-tool-removals").json()
    assert listing["choices"] == []
    assert "No shared lessons yet. Lessons appear here after agents finish tasks" in text
    # Reached from the Learning page (one nav entry per job: /learned left the
    # sidebar; the link lives on /learning).
    assert 'href="/learned"' in _client().get("/learning").text


def test_learned_page_has_no_admin_config_copy(monkeypatch, tmp_path):
    # Everything is configured in-app now: no "For administrators" details
    # blocks, no config-file / CLI instructions — the page points at the
    # Learning page's in-app switches instead.
    _isolate(monkeypatch, tmp_path)
    _seed_harness(monkeypatch, tmp_path, enabled=False)
    text = _client().get("/learned").text
    assert "For administrators" not in text
    assert "server configuration" not in text
    assert "maverick self-harness" not in text
    assert "learned.ndjson" not in text and "generated_tools/" not in text
    # The shared hero renders with a real fact from context...
    assert "hero-statebox" in text
    assert "Self-coaching off" in text
    # ...and the OFF note routes users to the in-app switch.
    assert "Self-coaching is off" in text
    assert 'href="/learning"' in text


def _seed_harness(monkeypatch, tmp_path, *, enabled=True):
    """Point the self-harness store at tmp_path and seed one model's guidance."""
    from maverick import self_harness as sh
    store = tmp_path / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: store)
    if enabled:
        monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    else:
        monkeypatch.setenv("MAVERICK_SELF_HARNESS", "0")
        monkeypatch.setattr("maverick.config.load_config", dict)
    _write_shared_guidance(
        {"claude-x": "Operating guidance learned for this model:\n"
                     "- verify the export precondition before acting"}, store)
    return store


def test_harness_guidance_renders_on_page_and_api(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _seed_harness(monkeypatch, tmp_path, enabled=True)
    text = _client().get("/learned").text
    assert "Lessons Lightwork taught itself" in text
    assert 'data-model="claude-x"' in text and "Remove this lesson" in text
    assert "verify the export precondition before acting" in text
    # API mirrors the page.
    body = _client().get("/api/v1/learned").json()
    assert body["harness_enabled"] is True
    assert body["harness"][0]["model_id"] == "claude-x"
    assert "verify the export precondition before acting" in body["harness"][0]["lines"]


def test_harness_view_shows_recent_rate_and_pending_corpus(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import config
    from maverick import self_harness as sh
    from maverick import self_harness_eval as ev
    store = tmp_path / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: store)
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    _write_shared_guidance({"m1": "Operating guidance learned for this model:\n"
                             "- verify the export"}, store, metadata={sh._line_id("m1", "verify the export"): {
        "model_id": "m1", "text": "verify the export",
        "signature": "timeout: slow export",
        "recall_success": 6, "recall_failure": 2,
        "recent_outcomes": [1, 0, 0, 0]}})
    cpath = tmp_path / "corpus.json"
    cpath.write_text("{}")
    assert ev.stage_candidates(cpath, "m1", [_shared_case("g", "e")]) == 1
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "eval_corpus": str(cpath)}})
    text = _client().get("/learned").text
    assert "75% success" in text                       # lifetime rate unchanged
    assert "lately 1 went well, 3 did not (25%)" in text   # the recency signal
    assert "suggested test case" in text               # staged ground truth visible
    assert "pc-resolve" in text and "Keep as a test case" in text  # ...resolvable in-page
    body = _client().get("/api/v1/learned").json()
    rec = body["harness"][0]["provenance"][0]
    assert rec["recent_rate"] == 0.25 and body["pending_corpus"] == {"m1": 1}
    assert body["pending_items"]["m1"][0]["goal"] == "g"


def _enable_oidc_principal_map(monkeypatch, *, default_role: str = "viewer") -> None:
    import maverick_dashboard.auth as auth
    import maverick_dashboard.rbac as rbac
    from maverick.oidc import VerifiedPrincipal

    monkeypatch.setattr(auth, "oidc_enabled", lambda: True)
    monkeypatch.setattr(rbac, "default_role", lambda: default_role)

    def _verify(token, **_kw):
        return VerifiedPrincipal(
            sub=token, issuer="https://issuer.example", audience="maverick",
            claims={"sub": token},
        )

    monkeypatch.setattr(auth, "verify_oidc_token", _verify)


def _as(user: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {user}", "Origin": "http://127.0.0.1"}


def test_pending_corpus_details_are_admin_only(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    _enable_oidc_principal_map(monkeypatch, default_role="viewer")
    import maverick_dashboard.rbac as rbac
    from maverick import config
    from maverick import self_harness_eval as ev

    cpath = tmp_path / "corpus.json"
    cpath.write_text("{}")
    assert ev.stage_candidates(cpath, "m1", [_shared_case(
        "Synthetic workspace review case", "Synthetic expected result",
    )]) == 1
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "eval_corpus": str(cpath)},
        "dashboard": {"default_role": "viewer"},
    })

    viewer_body = _client().get("/api/v1/learned", headers=_as("lowpriv")).json()
    assert viewer_body["pending_corpus"] == {"m1": 1}
    assert viewer_body["pending_items"] == {}
    viewer_page = _client().get("/learned", headers=_as("lowpriv")).text
    assert "suggested test case" in viewer_page
    assert "Keep as a test case" not in viewer_page
    assert "Synthetic workspace review case" not in viewer_page
    assert "Synthetic expected result" not in viewer_page

    monkeypatch.setattr(
        rbac, "get_stored_role", lambda p: "admin" if p == "user:admin" else None,
    )
    admin_body = _client().get("/api/v1/learned", headers=_as("admin")).json()
    assert (
        admin_body["pending_items"]["m1"][0]["goal"]
        == "Synthetic workspace review case"
    )


def test_admin_shared_view_withholds_legacy_and_employee_sources(monkeypatch, tmp_path):
    from maverick import config, world_model
    from maverick import self_harness as sh
    from maverick import self_harness_eval as ev
    from maverick_dashboard import rbac

    _isolate(monkeypatch, tmp_path)
    _enable_oidc_principal_map(monkeypatch)
    monkeypatch.setattr(rbac, "get_stored_role", lambda p: "admin" if p == "user:admin" else None)
    world = world_model.WorldModel()
    try:
        private_goal = world.create_goal("Synthetic employee work", owner="user:employee")
    finally:
        world.close()

    store = tmp_path / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: store)
    _write_shared_guidance({"m1": "Operating guidance learned for this model:\n- Shared lesson"}, store)
    blocks = sh.load_addenda(store)
    blocks["m1"] += "\n- Legacy lesson\n- Employee private lesson"
    sh._write_addenda(blocks, store)
    meta = sh.load_line_meta(store)
    meta[sh._line_id("m1", "Employee private lesson")] = {
        "model_id": "m1", "text": "Employee private lesson",
        "privacy_schema": "shared-unowned-sources-v1", "source_goal_ids": [private_goal],
    }
    sh._write_line_meta(meta, store)

    corpus = tmp_path / "corpus.json"
    assert ev.stage_candidates(corpus, "m1", [_shared_case("Shared case", "Shared result")]) == 1
    withheld = [
        {"goal": "Legacy case", "expected": "Legacy result"},
        {**_shared_case("Employee private case", "Private result"),
         "source_goal_ids": [private_goal]},
    ]
    assert ev.stage_candidates(corpus, "m1", withheld) == 0
    # Historical records remain on disk without gaining display/review authority.
    pending_path = ev.pending_corpus_path(corpus)
    raw = ev._load_raw(pending_path)
    raw["m1"].extend(withheld)
    ev._write_corpus_file(pending_path, raw, seal=True)
    before = {path: path.read_bytes() for path in (store, sh._meta_path(store), pending_path)}
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "eval_corpus": str(corpus)},
    })

    response = _client().get("/api/v1/learned", headers=_as("admin"))
    assert response.status_code == 200
    body = response.json()
    assert body["harness"][0]["lines"] == ["Shared lesson"]
    assert body["pending_corpus"] == {"m1": 1}
    assert body["pending_items"]["m1"][0]["goal"] == "Shared case"
    page = _client().get("/learned", headers=_as("admin"))
    assert page.status_code == 200
    assert "Shared lesson" in page.text and "Shared case" in page.text
    for text in ("Legacy lesson", "Employee private lesson", "Legacy case", "Employee private case"):
        assert text not in page.text and text not in response.text
    assert {path: path.read_bytes() for path in before} == before


def test_harness_corpus_review_endpoint(monkeypatch, tmp_path):
    # The dashboard resolves staged candidates with the SAME verdicts as the
    # CLI: accept merges into the live corpus, reject is remembered. Cross-
    # site POSTs are blocked by the same-origin middleware; a stale index is
    # a 409 (the page reloads and re-lists), not a silent no-op.
    _isolate(monkeypatch, tmp_path)
    from maverick import config
    from maverick import self_harness_eval as ev
    cpath = tmp_path / "corpus.json"
    cpath.write_text("{}")
    assert ev.stage_candidates(cpath, "m1", [
        _shared_case("g1", "e1"), _shared_case("g2", "e2"),
    ]) == 2
    monkeypatch.setattr(config, "load_config", lambda *a, **k: {
        "self_harness": {"enable": True, "eval_corpus": str(cpath)}})
    client = _client()
    ok = {"Origin": "http://127.0.0.1"}
    r = client.post("/api/v1/harness-corpus/review",
                    json={"key": "m1", "accept": [1], "reject": [2]}, headers=ok)
    assert r.status_code == 200, r.text
    assert r.json() == {"merged": 1, "duplicates": 0, "rejected": 1}
    assert [c["goal"] for c in ev.load_eval_corpus(cpath)["m1"]] == ["g1"]
    assert ev.load_rejected(cpath) == {"m1": ["g2"]}
    # stale index -> 409 conflict
    r = client.post("/api/v1/harness-corpus/review",
                    json={"key": "m1", "accept": [5]}, headers=ok)
    assert r.status_code == 409
    # cross-site POST blocked by the same-origin middleware
    r = client.post("/api/v1/harness-corpus/review",
                    json={"key": "m1", "accept": [1]},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_harness_view_shows_provenance_and_conflicts(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    from maverick import self_harness as sh
    store = tmp_path / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: store)
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    _write_shared_guidance({"claude-x":
                       "Operating guidance learned for this model:\n"
                       "- Prefer streaming for large exports\n"
                       "- Avoid streaming for large exports"}, store, metadata={sh._line_id("claude-x", "Prefer streaming for large exports"): {
        "model_id": "claude-x", "text": "Prefer streaming for large exports",
        "signature": "timeout: slow export", "held_out_delta": 0.2, "samples": 8,
        "learned_at": 1700000000.0, "updated_at": 1700000000.0}})
    text = _client().get("/learned").text
    assert "timeout: slow export" in text          # per-line provenance rendered
    assert "may contradict each other" in text     # conflict badge rendered
    body = _client().get("/api/v1/learned").json()
    h = body["harness"][0]
    assert h["provenance"] and h["conflicts"]


def test_harness_view_shows_efficacy_canary_and_domain(monkeypatch, tmp_path):
    # The /learned page surfaces the outcome-driven lifecycle the CLI exposes:
    # per-line success/failure counters, the canary probation badge, and the
    # department tag for domain-scoped guidance.
    _isolate(monkeypatch, tmp_path)
    from maverick import self_harness as sh
    store = tmp_path / "addenda.json"
    monkeypatch.setattr(sh, "_store_path", lambda: store)
    monkeypatch.setenv("MAVERICK_SELF_HARNESS", "1")
    finance_key = sh._scoped_key("claude-x", "domain=finance")
    _write_shared_guidance({
        "claude-x": "Operating guidance learned for this model:\n- check inputs first",
        finance_key: "Operating guidance learned for this model:\n- reconcile before posting",
    }, store, metadata={
        sh._line_id("claude-x", "check inputs first"): {
            "model_id": "claude-x", "text": "check inputs first",
            "recall_success": 3, "recall_failure": 1, "canary": True,
            "learned_at": 1700000000.0, "updated_at": 1700000000.0},
        sh._line_id(finance_key, "reconcile before posting"): {
            "model_id": finance_key, "text": "reconcile before posting",
            "learned_at": 1700000000.0, "updated_at": 1700000000.0},
    })
    body = _client().get("/api/v1/learned").json()
    prov = body["harness"][0]["provenance"]
    by_text = {r["text"]: r for r in prov}
    assert by_text["check inputs first"]["success"] == 3
    assert by_text["check inputs first"]["failure"] == 1
    assert by_text["check inputs first"]["rate"] == 0.75
    assert by_text["check inputs first"]["canary"] is True
    assert by_text["reconcile before posting"]["domain"] == "finance"
    text = _client().get("/learned").text
    assert "On trial" in text                        # probation badge rendered
    assert "Decide lessons on trial now" in text
    assert "75% success" in text                     # outcome counters rendered
    assert "Finance" in text                          # department tag rendered


def test_harness_guidance_shows_off_note_when_disabled(monkeypatch, tmp_path):
    # Stored-but-paused guidance is still shown, with a clear "not recalled" note
    # (matches `maverick self-harness show`).
    _isolate(monkeypatch, tmp_path)
    _seed_harness(monkeypatch, tmp_path, enabled=False)
    body = _client().get("/api/v1/learned").json()
    assert body["harness_enabled"] is False
    assert body["harness"][0]["model_id"] == "claude-x"
    text = _client().get("/learned").text
    assert "Self-coaching is off" in text


def test_generated_tools_list_renders(monkeypatch, tmp_path):
    _ledger, gen = _isolate(monkeypatch, tmp_path)
    _owned_source(gen / "send_sms.py", "# tool\n")
    (gen / ".staging_x.py").write_text("# hidden\n", encoding="utf-8")
    text = _client().get("/learned").text
    assert "Stop tools Lightwork wrote" in text and ".staging_x.py" not in text
    # The page reads the owned tools from the removal listing.
    labels = [row["label"] for row in _client().get("/api/v1/generated-tool-removals").json()["choices"]]
    # Dot/underscore-prefixed staging files are not listed.
    assert labels == ["send sms"]
    # API shape mirrors the page.
    body = _client().get("/api/v1/learned").json()
    assert "send_sms.py" in body["generated_tools"]


def _remove(client, label, *, step="apply"):
    """Stop and remove one owned tool through the page's reviewed path."""
    base = "/api/v1/generated-tool-removals"
    listing = client.get(base)
    if listing.status_code != 200:
        return listing
    body = listing.json()
    key = next((row["value"] for row in body["choices"] if row["label"] == label), "0" * 64)
    review = client.post(base + "/review", json={"tool": key, "action": "remove", "context": body["context"]})
    if review.status_code != 200 or step == "review":
        return review
    return client.post(base + "/apply", json={"token": review.json()["token"], "confirmed": True})


def test_delete_removes_only_named_file(monkeypatch, tmp_path):
    _ledger, gen = _isolate(monkeypatch, tmp_path)
    _owned_source(gen / "bad.py", "# bad\n")
    _owned_source(gen / "good.py", "# good\n")
    r = _remove(_client(), "bad")
    assert r.status_code == 200 and r.json()["confirmed"] is True
    assert not (gen / "bad.py").exists()
    assert (gen / "good.py").exists()


def test_delete_revokes_digest_and_records_tombstone(monkeypatch, tmp_path):
    _ledger, gen = _isolate(monkeypatch, tmp_path)
    from maverick import self_learning
    from maverick.safety import consent

    source = "# generated tool\n"
    target = gen / "bad.py"
    _owned_source(target, source)
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    scope = f"shared:bad:{digest}"
    consent.grant_persistent("register-generated-tool", scope=scope)
    assert consent._check_ledger("register-generated-tool", scope)

    events = []
    monkeypatch.setattr(
        "maverick.audit.audit_event",
        lambda kind, **payload: events.append((kind, payload)) or True,
    )
    response = _remove(_client(), "bad")

    assert response.status_code == 200 and response.json()["confirmed"] is True
    assert not target.exists()
    assert not consent._check_ledger("register-generated-tool", scope)
    records = [
        json.loads(line)
        for line in consent.consent_ledger_path().read_text(
            encoding="utf-8",
        ).splitlines()
    ]
    assert records[-1]["op"] == "revoke"
    assert records[-1]["scope"] == scope
    assert events[-1][1]["operation"] == "generated_tool_authority_revoked"
    assert events[-1][1]["source_sha256"] == digest

    # Identical bytes appearing later are inert until a fresh consent decision
    # creates a new post-tombstone grant.
    target.write_text(source, encoding="utf-8")
    assert "bad" not in self_learning.generated_tool_names()


def test_delete_audit_failure_keeps_source_but_revokes_authority(
    monkeypatch,
    tmp_path,
):
    _ledger, gen = _isolate(monkeypatch, tmp_path)
    from maverick.safety import consent

    source = "# generated tool\n"
    target = gen / "bad.py"
    _owned_source(target, source)
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    scope = f"shared:bad:{digest}"
    consent.grant_persistent("register-generated-tool", scope=scope)
    monkeypatch.setattr("maverick.audit.audit_event", lambda *a, **k: False)

    response = _remove(_client(), "bad")

    # The original stays unconfirmed rather than claiming a removal.
    assert response.status_code == 200 and response.json()["confirmed"] is False
    assert target.exists()
    assert not consent._check_ledger("register-generated-tool", scope)


def test_delete_missing_file_404(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    r = _remove(_client(), "nope", step="review")
    assert r.status_code == 404


def test_delete_rejects_traversal(monkeypatch, tmp_path):
    """A traversal / outside-dir name must be refused and touch nothing."""
    _ledger, gen = _isolate(monkeypatch, tmp_path)
    secret = tmp_path / "secret.py"
    secret.write_text("# do not delete\n", encoding="utf-8")
    client = _client()
    context = client.get("/api/v1/generated-tool-removals").json()["context"]
    # The review accepts only an owned tool's digest key, never a file name.
    for name in ("foo.txt", "x.py.bak", "..", "../secret.py", "subdir/x.py", "secret.py"):
        r = client.post("/api/v1/generated-tool-removals/review",
                        json={"tool": name, "action": "remove", "context": context})
        assert r.status_code == 422, name
    # The older name-based control refuses every name without removing anything.
    for name in ("foo.txt", "x.py.bak", "..", "..%2Fsecret.py", "subdir%2Fx.py"):
        r = client.request(
            "DELETE", f"/api/v1/generated-tools/{name}",
            headers={"Origin": "http://127.0.0.1"},
        )
        assert r.status_code in (404, 409), name
    # The out-of-dir target survived every attempt.
    assert secret.exists()


def test_delete_respects_same_origin(monkeypatch, tmp_path):
    """Cross-site DELETE (no token, bad Origin) is blocked by middleware."""
    _ledger, gen = _isolate(monkeypatch, tmp_path)
    _owned_source(gen / "bad.py", "# bad\n")
    client = _client()
    r = client.request(
        "DELETE", "/api/v1/generated-tools/bad.py",
        headers={"Origin": "http://evil.example"},
    )
    assert r.status_code == 403
    # The file survives the blocked request.
    assert (gen / "bad.py").exists()
