"""Earned Autonomy: consequence cards, the predicted-vs-actual
join, evidence-driven graduation/demotion, the saga, and the agent wiring."""
from __future__ import annotations

import json

import pytest
from maverick import earned_autonomy as ea


def _engine(tmp_path, *, policy=None, frozen=False, grants=None, revokes=None,
            audits=None, now=(lambda: 100.0)):
    """A deterministic engine: injected clock, spies for grant/revoke/audit."""
    grants = grants if grants is not None else []
    revokes = revokes if revokes is not None else []
    audits = audits if audits is not None else []
    return ea.EarnedAutonomyEngine(
        cards=ea.CardStore(path=tmp_path / "cards.ndjson"),
        ledger=ea.TrustLedger(path=tmp_path / "trust.ndjson"),
        policy=policy or ea.GraduationPolicy(
            min_streak=3, min_samples=3, min_accuracy=0.9, tolerance=0.25,
            max_auto_risk="high", require_reversible=True, armed=True),
        frozen_fn=lambda: frozen,
        audit_fn=lambda kind, **p: audits.append((kind, p)),
        grant_fn=grants.append,
        revoke_fn=revokes.append,
        now=now,
    )


def _card(engine, *, episode_id, predicted=0.9, reversible=True,
          action="wire_transfer", principal="cfo-bot", risk="high",
          source="simulate"):
    """A card from the shadow-mode path by default.

    ``source`` matters: only ``"simulate"`` carries reversibility a preview
    adapter actually demonstrated, and ``GraduationPolicy.require_reversible``
    defaults to True, so a card sourced anywhere else cannot satisfy the
    reversibility gate. The provenance rule itself is pinned below.
    """
    return engine.record_card(
        principal=principal, action=action, risk=risk,
        predicted_outcome=predicted, goal_id=1, episode_id=episode_id,
        reversible=reversible, source=source, ts=float(episode_id))


@pytest.fixture(autouse=True)
def _on(monkeypatch):
    """These are engine-behavior tests; the enable gate is tested explicitly."""
    monkeypatch.setenv("MAVERICK_EARNED_AUTONOMY", "1")


# -- stores: chained, persistent, tamper-evident ---------------------------


def test_card_store_roundtrip_and_chain(tmp_path):
    store = ea.CardStore(path=tmp_path / "c.ndjson")
    card = ea.ConsequenceCard(
        principal="p", action="deploy", risk="high", predicted_outcome=0.8,
        goal_id=1, episode_id=7, reversible=True, ts=1.0)
    assert store.append(card) is True
    assert store.verify().startswith("VALID: 1 link(s)")
    again = ea.CardStore(path=tmp_path / "c.ndjson")
    rows = again.cards()
    assert len(rows) == 1 and rows[0]["action"] == "deploy"
    assert again.verify().startswith("VALID: 1")


def test_tampered_store_is_detected(tmp_path):
    store = ea.CardStore(path=tmp_path / "c.ndjson")
    for ep in (1, 2):
        store.append(ea.ConsequenceCard(
            principal="p", action="send", risk="high", predicted_outcome=0.5,
            goal_id=1, episode_id=ep, ts=float(ep)))
    lines = (tmp_path / "c.ndjson").read_text().splitlines()
    row = json.loads(lines[0])
    row["predicted_outcome"] = 1.0  # rewrite history
    lines[0] = json.dumps(row, sort_keys=True)
    (tmp_path / "c.ndjson").write_text("\n".join(lines) + "\n")
    assert ea.CardStore(path=tmp_path / "c.ndjson").verify().startswith("BROKEN")


def test_two_writers_on_one_file_do_not_fork_the_chain(tmp_path):
    """A second process-alike writer chains onto the FILE's head, not its own
    stale in-memory tail (the cross-process refresh-under-lock contract)."""
    a = ea.TrustLedger(path=tmp_path / "t.ndjson")
    b = ea.TrustLedger(path=tmp_path / "t.ndjson")  # loaded before a writes
    assert a.record_event("hit", "deploy", card_id="a1", ts=1.0)
    assert b.record_event("hit", "deploy", card_id="b1", ts=2.0)  # stale tail
    fresh = ea.TrustLedger(path=tmp_path / "t.ndjson")
    assert fresh.verify().startswith("VALID: 2")
    assert fresh.state("deploy").hits == 2


def test_trust_ledger_reduction(tmp_path):
    ledger = ea.TrustLedger(path=tmp_path / "t.ndjson")
    for kind, cid in (("hit", "a"), ("hit", "b"), ("miss", "c"), ("hit", "d"),
                      ("superseded", "e")):
        assert ledger.record_event(kind, "deploy", principal="p", card_id=cid,
                                   ts=1.0)
    s = ledger.state("deploy")
    assert (s.hits, s.misses, s.streak) == (3, 1, 1)
    assert s.samples == 4 and s.accuracy == 0.75 and s.graduated is False
    # superseded enters the idempotency set but never the evidence counts.
    assert ledger.scored_ids() == frozenset({"a", "b", "c", "d", "e"})
    assert ledger.record_event("bogus", "deploy") is False


def test_states_skips_type_corrupt_rows(tmp_path):
    ledger = ea.TrustLedger(path=tmp_path / "t.ndjson")
    assert ledger.record_event("hit", "deploy", card_id="a", ts=1.0)
    lines = (tmp_path / "t.ndjson").read_text().splitlines()
    row = json.loads(lines[0])
    row["ts"] = "not-a-number"
    lines.append(json.dumps(row, sort_keys=True))
    (tmp_path / "t.ndjson").write_text("\n".join(lines) + "\n")
    fresh = ea.TrustLedger(path=tmp_path / "t.ndjson")
    assert fresh.state("deploy").hits == 1  # bad row skipped, no crash


def _event(kind, ts, card_id=""):
    return {"kind": kind, "action": "deploy", "principal": "", "card_id": card_id,
            "ts": ts, "reason": ""}


def _legacy_ledger(path, events):
    """Write evidence the way the release before signed heads did: chained
    rows, sorted-key JSON lines, and no signed audit head anywhere."""
    prev, lines = ea._GENESIS, []
    for fields in events:
        row = {**fields, "prev": prev, "hash": ea._ChainedLog._row_hash(fields, prev)}
        lines.append(json.dumps(row, sort_keys=True) + "\n")
        prev = row["hash"]
    path.write_text("".join(lines))


def _signed_heads(ledger):
    from maverick.audit.signing import _segment_text, day_files

    directory = ledger._log._anchor_location()[1]
    return [json.loads(line) for day in day_files(directory)
            for line in _segment_text(day).splitlines() if line.strip()]


def test_legacy_ledger_is_adopted_and_accepts_evidence_and_revoke(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")  # a signed main audit log
    path = tmp_path / "trust.ndjson"
    _legacy_ledger(path, [_event("hit", 1.0, "a"), _event("graduate", 2.0)])
    ledger = ea.TrustLedger(path=path)
    assert ledger.state("deploy").graduated
    assert ledger.record_event("hit", "deploy", card_id="b", ts=3.0)
    assert ledger.verify().startswith("VALID: 3")
    assert ledger.record_event("revoke", "deploy", reason="operator", ts=4.0)
    assert ledger.state("deploy").graduated is False
    assert ledger.verify().startswith("VALID: 4")
    heads = _signed_heads(ledger)
    # The adoption is itself a signed record, anchored at the legacy head.
    assert heads[0]["adopted_from_unanchored"] is True
    assert heads[0]["row_count"] == 2
    assert [h.get("adopted_from_unanchored") for h in heads[1:]] == [None, None]
    assert not any("unverified_ledger" in row for row in ledger._log.rows())


def test_removed_signed_heads_never_allow_a_second_adoption(tmp_path, monkeypatch):
    import shutil

    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")  # a signed main audit log
    path = tmp_path / "trust.ndjson"
    _legacy_ledger(path, [_event("hit", 1.0, "a"), _event("graduate", 2.0)])
    ledger = ea.TrustLedger(path=path)
    assert ledger.record_event("miss", "deploy", card_id="b", ts=3.0)
    assert ledger.record_event("demote", "deploy", ts=4.0)
    assert ledger.state("deploy").graduated is False
    lines = path.read_text().splitlines(keepends=True)
    # Deleting the latest miss/demote rows of an anchored ledger is detected.
    path.write_text("".join(lines[:2]))
    assert ledger.verify().startswith("BROKEN: head does not match")
    assert not ledger.record_event("hit", "deploy", card_id="c", ts=5.0)
    # Removing the whole signed namespace does not make it look never-anchored:
    # the main audit log still records that this store was anchored.
    shutil.rmtree(ledger._log._anchor_location()[1])
    status = ledger.verify()
    assert status.startswith("BROKEN") and "anchored before" in status
    assert not ledger.record_event("hit", "deploy", card_id="d", ts=6.0)
    assert path.read_text() == "".join(lines[:2])
    assert ledger.state("deploy").hits == 1


def test_unsigned_audit_log_install_adopts_legacy_evidence_once(tmp_path, monkeypatch):
    import shutil

    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "0")  # operator chose an unsigned log
    path = tmp_path / "trust.ndjson"
    _legacy_ledger(path, [_event("hit", 1.0, "a"), _event("graduate", 2.0)])
    ledger = ea.TrustLedger(path=path)
    assert ledger.record_event("hit", "deploy", card_id="b", ts=3.0)
    assert ledger.verify().startswith("VALID: 3")
    shutil.rmtree(ledger._log._anchor_location()[1])
    assert "anchored before" in ledger.verify()
    assert not ledger.record_event("hit", "deploy", card_id="c", ts=4.0)


def test_fabricated_ledger_at_an_anchored_path_is_not_adopted(tmp_path, monkeypatch):
    import shutil

    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    path = tmp_path / "trust.ndjson"
    ledger = ea.TrustLedger(path=path)
    assert ledger.record_event("miss", "deploy", card_id="a", ts=1.0)
    shutil.rmtree(ledger._log._anchor_location()[1])
    _legacy_ledger(path, [_event("hit", float(i), f"h{i}") for i in range(3)]
                   + [_event("graduate", 4.0)])
    forged = ea.TrustLedger(path=path)
    assert "anchored before" in forged.verify()
    assert not forged.record_event("hit", "deploy", card_id="z", ts=5.0)


def test_forced_revoke_lands_on_unverified_evidence_without_laundering_it(tmp_path):
    path = tmp_path / "trust.ndjson"
    ledger = ea.TrustLedger(path=path)
    for kind, ts in (("hit", 1.0), ("graduate", 2.0), ("miss", 3.0), ("demote", 4.0)):
        assert ledger.record_event(kind, "deploy", card_id=f"c{ts:.0f}", ts=ts)
    lines = path.read_text().splitlines(keepends=True)
    path.write_text("".join(lines[:2]))  # drop the miss + demote
    assert ledger.state("deploy").graduated
    assert ledger.record_event("revoke", "deploy", reason="operator", ts=5.0)
    assert ledger.state("deploy").graduated is False
    row = ledger._log.rows()[-1]
    assert row["kind"] == "revoke"
    assert row["unverified_ledger"].startswith("BROKEN: head does not match")
    # The truncation stays visible and ordinary evidence is still refused.
    assert ledger.verify().startswith("BROKEN")
    assert not ledger.record_event("hit", "deploy", card_id="c6", ts=6.0)


def test_failed_signed_head_withdraws_the_row_and_keeps_the_ledger_usable(tmp_path, monkeypatch):
    from maverick.audit import signing

    ledger = ea.TrustLedger(path=tmp_path / "trust.ndjson")
    assert ledger.record_event("hit", "deploy", card_id="a", ts=1.0)
    real_anchor = ledger._log._record_anchor
    monkeypatch.setattr(ledger._log, "_record_anchor", lambda *a, **k: False)
    assert not ledger.record_event("hit", "deploy", card_id="b", ts=2.0)
    assert ledger.state("deploy").hits == 1 and "b" not in ledger.scored_ids()
    monkeypatch.setattr(ledger._log, "_record_anchor", real_anchor)
    assert ledger.verify().startswith("VALID: 1")
    # Fail after the signed head landed (the anchor-ledger write): the row is
    # withdrawn and the restored head re-recorded, so nothing stays wedged.
    calls = []
    real_append = signing._append_anchor

    def flaky(*args):
        calls.append(args)
        return False if len(calls) == 1 else real_append(*args)

    monkeypatch.setattr(signing, "_append_anchor", flaky)
    assert not ledger.record_event("hit", "deploy", card_id="c", ts=3.0)
    assert ledger.state("deploy").hits == 1 and "c" not in ledger.scored_ids()
    assert ledger.verify().startswith("VALID: 1")
    assert ledger.record_event("hit", "deploy", card_id="d", ts=4.0)
    assert ledger.record_event("demote", "deploy", ts=5.0)
    assert ledger.verify().startswith("VALID: 3")


def test_forced_rows_after_one_anchor_failure_are_re_anchored_by_the_next_append(
        tmp_path, monkeypatch):
    path = tmp_path / "trust.ndjson"
    ledger = ea.TrustLedger(path=path)
    assert ledger.record_event("hit", "deploy", card_id="a", ts=1.0)
    real_anchor = ledger._log._record_anchor
    monkeypatch.setattr(ledger._log, "_record_anchor", lambda *a, **k: False)
    assert ledger.record_event("demote", "deploy", ts=2.0)  # lands unverified
    monkeypatch.setattr(ledger._log, "_record_anchor", real_anchor)
    assert ledger.verify().startswith("BROKEN")
    assert ledger.record_event("hit", "deploy", card_id="b", ts=3.0)
    assert ledger.verify().startswith("VALID: 3")
    # Only unverified demote/revoke rows are ever tolerated past the head.
    lines = path.read_text().splitlines(keepends=True)
    row = {**_event("graduate", 4.0), "unverified_ledger": "BROKEN: forged"}
    prev = json.loads(lines[-1])["hash"]
    row = {**row, "prev": prev, "hash": ea._ChainedLog._row_hash(row, prev)}
    path.write_text("".join(lines) + json.dumps(row, sort_keys=True) + "\n")
    assert not ledger.record_event("hit", "deploy", card_id="c", ts=5.0)
    assert ledger.verify().startswith("BROKEN: head does not match")


def test_two_ledger_objects_keep_the_signed_day_count_in_step(tmp_path):
    path = tmp_path / "trust.ndjson"
    a, b = ea.TrustLedger(path=path), ea.TrustLedger(path=path)
    assert a.record_event("hit", "deploy", card_id="a1", ts=1.0)
    assert b.record_event("hit", "deploy", card_id="b1", ts=2.0)
    assert a.verify().startswith("VALID: 2")
    assert a.record_event("hit", "deploy", card_id="a2", ts=3.0)
    assert ea.TrustLedger(path=path).verify().startswith("VALID: 3")
    assert b.record_event("hit", "deploy", card_id="b2", ts=4.0)


def test_append_does_not_reverify_earlier_signed_heads(tmp_path, monkeypatch):
    from maverick.audit import signing

    path = tmp_path / "trust.ndjson"
    ledger = ea.TrustLedger(path=path)
    for i in range(3):
        assert ledger.record_event("hit", "deploy", card_id=f"a{i}", ts=float(i))
    calls = []
    for name in ("verify_chain", "verify_anchors", "_segment_text"):
        real = getattr(signing, name)
        monkeypatch.setattr(signing, name, lambda *a, _real=real, _name=name, **k: (
            calls.append(_name), _real(*a, **k))[1])
    for i in range(5):
        assert ledger.record_event("hit", "deploy", card_id=f"b{i}", ts=10.0 + i)
    assert calls == []
    # An explicit verify() still runs the full check.
    assert ledger.verify().startswith("VALID: 8")
    assert "verify_anchors" in calls and "verify_chain" in calls
    # A change made outside this object brings the full check back to append.
    lines = path.read_text().splitlines(keepends=True)
    path.write_text("".join(lines[:-1]))
    calls.clear()
    assert not ledger.record_event("hit", "deploy", card_id="c", ts=20.0)
    assert "verify_anchors" in calls


# -- the enable gate -------------------------------------------------------


def test_disabled_by_default(monkeypatch, tmp_path):
    monkeypatch.delenv("MAVERICK_EARNED_AUTONOMY", raising=False)
    monkeypatch.setattr("maverick.config.get_earned_autonomy",
                        lambda: {"enable": False})
    assert ea.enabled() is False
    engine = _engine(tmp_path)
    assert _card(engine, episode_id=1) is None
    assert engine.reconcile() == ea.ReconcileReport()


def test_env_master_switch_overrides_config(monkeypatch):
    monkeypatch.setattr("maverick.config.get_earned_autonomy",
                        lambda: {"enable": True})
    monkeypatch.setenv("MAVERICK_EARNED_AUTONOMY", "0")
    assert ea.enabled() is False
    monkeypatch.setenv("MAVERICK_EARNED_AUTONOMY", "1")
    assert ea.enabled() is True


def test_writes_blocked_by_learning_guard(tmp_path, monkeypatch):
    """Both write surfaces -- record_card AND reconcile -- respect the HALT."""
    engine = _engine(tmp_path)
    _card(engine, episode_id=1)
    monkeypatch.setattr("maverick.learning_guard.learning_write_allowed",
                        lambda *a, **k: False)
    assert _card(engine, episode_id=2) is None
    assert engine.reconcile(resolve=lambda g, e: 1.0) == ea.ReconcileReport()
    assert engine.ledger.states() == {}  # no evidence minted under HALT


# -- the predicted-vs-actual join ------------------------------------------


def test_reconcile_scores_hits_and_misses_idempotently(tmp_path):
    engine = _engine(tmp_path)
    _card(engine, episode_id=1, predicted=0.9)   # actual 1.0 -> hit (|0.1|<=0.25)
    _card(engine, episode_id=2, predicted=0.9)   # actual 0.0 -> miss
    _card(engine, episode_id=3, predicted=0.9)   # no actual yet -> unscored
    actuals = {(1, 1): 1.0, (1, 2): 0.0}
    report = engine.reconcile(resolve=lambda g, e: actuals.get((g, e)))
    assert (report.scored, report.hits, report.misses) == (2, 1, 1)
    s = engine.ledger.state("wire_transfer")
    assert (s.hits, s.misses, s.streak) == (1, 1, 0)
    # Idempotent: nothing is double-counted on a second pass.
    again = engine.reconcile(resolve=lambda g, e: actuals.get((g, e)))
    assert again.scored == 0
    assert engine.ledger.state("wire_transfer").samples == 2


def test_same_episode_cards_collapse_to_one_outcome(tmp_path):
    """One observed consequence grades ONE prediction per action type -- ten
    same-episode cards must not mint a ten-hit streak."""
    engine = _engine(tmp_path)
    for i in range(10):
        engine.record_card(
            principal="cfo-bot", action="wire_transfer", risk="high",
            predicted_outcome=0.9, goal_id=1, episode_id=7, reversible=True,
            source="rehearsal", ts=float(i))
    report = engine.reconcile(resolve=lambda g, e: 1.0)
    assert (report.scored, report.hits, report.superseded) == (1, 1, 9)
    s = engine.ledger.state("wire_transfer")
    assert (s.hits, s.streak) == (1, 1)
    # And nothing is re-scored on the next pass.
    assert engine.reconcile(resolve=lambda g, e: 1.0).scored == 0


def test_reconcile_skips_cards_without_a_join_key(tmp_path):
    engine = _engine(tmp_path)
    _card(engine, episode_id=0)  # no episode -> nothing to join against
    report = engine.reconcile(resolve=lambda g, e: 1.0)
    assert report.scored == 0


def test_two_engine_instances_never_double_score(tmp_path):
    """A second reconciler (another process-alike) sees the first's events."""
    a = _engine(tmp_path)
    _card(a, episode_id=1)
    b = _engine(tmp_path)  # stale in-memory view, same files
    assert a.reconcile(resolve=lambda g, e: 1.0).scored == 1
    assert b.reconcile(resolve=lambda g, e: 1.0).scored == 0
    assert b.ledger.state("wire_transfer").hits == 1


# -- graduation: the earned dial -------------------------------------------


def _graduate(engine, *, n=3):
    for ep in range(1, n + 1):
        _card(engine, episode_id=ep, predicted=0.9)
    return engine.reconcile(resolve=lambda g, e: 1.0)


def test_streak_graduates_and_grants(tmp_path):
    grants, audits = [], []
    engine = _engine(tmp_path, grants=grants, audits=audits)
    report = _graduate(engine)
    assert report.graduated == ("wire_transfer",)
    assert grants == []
    assert engine.ledger.state("wire_transfer").graduated is True
    assert engine.decide("wire_transfer", risk="high").auto is False
    decisions = [p.get("decision") for k, p in audits
                 if k == "autonomy_graduation"]
    assert decisions == ["graduate"]


def test_one_miss_demotes_instantly_and_revokes(tmp_path):
    grants, revokes = [], []
    engine = _engine(tmp_path, grants=grants, revokes=revokes)
    _graduate(engine)
    _card(engine, episode_id=9, predicted=0.9)
    report = engine.reconcile(resolve=lambda g, e: 0.0 if e == 9 else 1.0)
    assert report.demoted == ("wire_transfer",)
    assert revokes == []
    s = engine.ledger.state("wire_transfer")
    assert s.graduated is False and s.streak == 0 and s.ever_graduated is True
    assert engine.decide("wire_transfer", risk="high").auto is False


def test_any_agents_miss_demotes_the_action_type(tmp_path):
    """Trust accrues to the ACTION TYPE (the unit enforcement grants at):
    a miss by a different agent still withdraws the action's autonomy."""
    revokes = []
    engine = _engine(tmp_path, revokes=revokes)
    _graduate(engine)  # earned by cfo-bot
    _card(engine, episode_id=9, principal="intern-bot", predicted=0.9)
    report = engine.reconcile(resolve=lambda g, e: 0.0 if e == 9 else 1.0)
    assert report.demoted == ("wire_transfer",)
    assert engine.ledger.state("wire_transfer").graduated is False


def test_unarmed_policy_never_graduates(tmp_path):
    grants = []
    engine = _engine(tmp_path, grants=grants, policy=ea.GraduationPolicy(
        min_streak=3, min_samples=3, max_auto_risk="high", armed=False))
    report = _graduate(engine)
    assert report.graduated == () and grants == []


def test_risk_ceiling_blocks_high_risk_by_default(tmp_path):
    engine = _engine(tmp_path, policy=ea.GraduationPolicy(
        min_streak=3, min_samples=3, armed=True))  # default ceiling: medium
    assert _graduate(engine).graduated == ()
    # An unknown ceiling is the MOST restrictive, never permissive.
    verdict = ea.evaluate_graduation(
        ea.TrustState("read_file", hits=50, misses=0, streak=50),
        risk="low", reversible_share=1.0, frozen=False,
        policy=ea.GraduationPolicy(min_streak=3, min_samples=3, armed=True,
                                   max_auto_risk="unlimited"))
    assert verdict.graduate is False
    assert any(g.gate == "risk_ceiling" and not g.ok for g in verdict.gates)


def test_unknown_action_risk_ranks_above_every_ceiling(tmp_path):
    """A mislabeled/novel risk level ('critical', a typo) must fail closed --
    NOT collapse to medium the way tool_risk.risk_rank would rank it."""
    verdict = ea.evaluate_graduation(
        ea.TrustState("wire_transfer", hits=50, misses=0, streak=50),
        risk="critical", reversible_share=1.0, frozen=False,
        policy=ea.GraduationPolicy(min_streak=3, min_samples=3, armed=True,
                                   max_auto_risk="high"))
    assert verdict.graduate is False
    engine = _engine(tmp_path)
    _graduate(engine)
    assert engine.decide("wire_transfer", risk="critical").auto is False


def test_graduation_uses_live_tool_risk_not_card_label(tmp_path, monkeypatch):
    """The ceiling consults tool_risk(action), never the recorder's claim."""
    engine = _engine(tmp_path, policy=ea.GraduationPolicy(
        min_streak=3, min_samples=3, armed=True, max_auto_risk="medium"))
    for ep in (1, 2, 3):
        _card(engine, episode_id=ep, risk="medium")  # mislabeled: really high
    import importlib

    trm = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(trm, "tool_risk", lambda n, overrides=None: "high")
    assert engine.reconcile(resolve=lambda g, e: 1.0).graduated == ()
    # And an unresolvable classification keeps the human too.
    monkeypatch.setattr(
        trm, "tool_risk",
        lambda n, overrides=None: (_ for _ in ()).throw(RuntimeError("gone")))
    assert engine.reconcile(resolve=lambda g, e: 1.0).graduated == ()


def test_irreversible_cards_block_graduation(tmp_path):
    engine = _engine(tmp_path)
    _card(engine, episode_id=1, reversible=False)
    for ep in (2, 3):
        _card(engine, episode_id=ep)
    report = engine.reconcile(resolve=lambda g, e: 1.0)
    assert report.graduated == ()
    states = {g.gate: g for g in ea.evaluate_graduation(
        engine.ledger.state("wire_transfer"), risk="high",
        reversible_share=2 / 3, policy=engine.policy, frozen=False).gates}
    assert states["reversibility"].ok is False


def test_calibration_freeze_blocks_graduation(tmp_path):
    engine = _engine(tmp_path, frozen=True)
    assert _graduate(engine).graduated == ()

    def _boom():
        raise RuntimeError("no verdict")

    engine2 = _engine(tmp_path / "b")
    engine2.frozen_fn = _boom  # can't confirm the judge -> treated frozen
    assert _graduate(engine2).graduated == ()


def test_legacy_grant_callback_is_not_invoked(tmp_path):
    def _refuse(action):
        raise RuntimeError("ledger sealed")

    engine = _engine(tmp_path)
    engine.grant_fn = _refuse
    report = _graduate(engine)
    assert report.graduated == ("wire_transfer",)
    assert engine.ledger.state("wire_transfer").graduated is True


def test_evidence_write_failure_does_not_create_or_revoke_grant(tmp_path):
    """A failed evidence write does not touch independent consent grants."""
    grants, revokes = [], []
    engine = _engine(tmp_path, grants=grants, revokes=revokes)
    engine.ledger = ea.TrustLedger(path=tmp_path / "t.ndjson", max_rows=3)
    report = _graduate(engine)  # 3 hit rows fill the ledger; graduate drops
    assert report.graduated == ()
    assert grants == []
    assert revokes == []
    assert engine.ledger.state("wire_transfer").graduated is False
    assert engine.decide("wire_transfer", risk="high").auto is False


def test_miss_at_ledger_capacity_still_demotes(tmp_path):
    """The demote row is FORCED past the capacity bound: after a miss the
    queryable dial must never stay AUTO just because the ledger is full."""
    revokes = []
    engine = _engine(tmp_path, revokes=revokes)
    engine.ledger = ea.TrustLedger(path=tmp_path / "t.ndjson", max_rows=4)
    _graduate(engine)  # 3 hits + 1 graduate = at capacity, graduated
    assert engine.decide("wire_transfer", risk="high").auto is False
    _card(engine, episode_id=9)
    engine.reconcile(resolve=lambda g, e: 0.0 if e == 9 else 1.0)
    assert revokes == []
    assert engine.ledger.state("wire_transfer").graduated is False
    assert engine.decide("wire_transfer", risk="high").auto is False


def test_evidence_demotion_does_not_call_legacy_revocation_callback(tmp_path):
    calls = []
    engine = _engine(tmp_path)
    engine.revoke_fn = calls.append
    _graduate(engine)
    _card(engine, episode_id=9)
    engine.reconcile(resolve=lambda g, e: 0.0 if e == 9 else 1.0)
    engine.reconcile(resolve=lambda g, e: None)
    assert calls == []
    assert engine.ledger.state("wire_transfer").graduated is False


def test_operator_revoke(tmp_path):
    revokes = []
    engine = _engine(tmp_path, revokes=revokes)
    _graduate(engine)
    assert engine.revoke("wire_transfer", reason="quarter close") is True
    assert revokes == []
    assert engine.ledger.state("wire_transfer").graduated is False
    # One more accurate prediction does not undo the operator's revoke.
    _card(engine, episode_id=9)
    assert engine.reconcile(resolve=lambda g, e: 1.0).graduated == ()
    assert engine.ledger.state("wire_transfer").graduated is False


# -- decide(): every uncertainty keeps the human ---------------------------


def test_decide_fails_toward_human(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    _graduate(engine)
    assert engine.decide("wire_transfer", risk="high").auto is False
    # Frozen verifier suspends the dial.
    engine.frozen_fn = lambda: True
    assert engine.decide("wire_transfer", risk="high").auto is False
    engine.frozen_fn = lambda: False
    # Operational halt suspends the dial.
    monkeypatch.setattr("maverick.killswitch.is_active", lambda: True)
    assert engine.decide("wire_transfer", risk="high").auto is False
    monkeypatch.setattr("maverick.killswitch.is_active", lambda: False)
    # Disabled feature, unproven actions, over-ceiling risk: all human.
    assert engine.decide("run_payroll", risk="high").auto is False
    monkeypatch.setenv("MAVERICK_EARNED_AUTONOMY", "0")
    assert engine.decide("wire_transfer", risk="high").auto is False


def test_decide_default_risk_uses_live_classification(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    _graduate(engine)
    import importlib

    trm = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(trm, "tool_risk", lambda n, overrides=None: "high")
    assert engine.decide("wire_transfer").auto is False  # evidence is advisory
    monkeypatch.setattr(
        trm, "tool_risk",
        lambda n, overrides=None: (_ for _ in ()).throw(RuntimeError("gone")))
    assert engine.decide("wire_transfer") == ea.EarnedDecision(
        False, "action risk unavailable")


def test_status_orders_most_proven_first(tmp_path):
    engine = _engine(tmp_path)
    _graduate(engine)
    _card(engine, episode_id=8, action="send_invoice")
    engine.reconcile(resolve=lambda g, e: 1.0)
    states = engine.status()
    assert [s.action for s in states] == ["wire_transfer", "send_invoice"]
    assert states[0].graduated is True and states[1].graduated is False


# -- the compensating-action saga ------------------------------------------


def test_saga_commits_when_every_step_succeeds():
    trail = []
    steps = [
        ea.SagaStep("hold", lambda: trail.append("hold") or "held",
                    lambda: trail.append("-hold") or "released"),
        ea.SagaStep("post", lambda: trail.append("post") or "posted",
                    lambda: trail.append("-post") or "reversed"),
    ]
    result = ea.run_saga(steps)
    assert result.committed is True
    assert [r.step for r in result.results] == ["hold", "post"]
    assert trail == ["hold", "post"] and result.compensated == ()


def test_saga_rolls_back_completed_prefix_in_reverse():
    trail = []

    def _fail():
        raise RuntimeError("wire rejected")

    steps = [
        ea.SagaStep("hold", lambda: trail.append("hold") or "ok",
                    lambda: trail.append("undo-hold") or "ok"),
        ea.SagaStep("post", lambda: trail.append("post") or "ok",
                    lambda: trail.append("undo-post") or "ok"),
        ea.SagaStep("wire", _fail, lambda: "never-reached"),
    ]
    result = ea.run_saga(steps)
    assert result.committed is False
    assert "wire" in result.reason
    assert [r.step for r in result.compensated] == ["post", "hold"]
    assert trail == ["hold", "post", "undo-post", "undo-hold"]


def test_saga_refuses_irreversible_steps_before_any_effect():
    ran = []
    steps = [ea.SagaStep("wire", lambda: ran.append("wire") or "ok", None)]
    result = ea.run_saga(steps)
    assert result.committed is False and ran == []
    assert "without an inverse" in result.reason
    assert ea.run_saga(steps, allow_irreversible=True).committed is True


def test_saga_records_failed_compensation():
    def _bad_undo():
        raise RuntimeError("cannot release")

    def _fail():
        raise RuntimeError("boom")

    steps = [
        ea.SagaStep("hold", lambda: "ok", _bad_undo),
        ea.SagaStep("wire", _fail, lambda: "ok"),
    ]
    result = ea.run_saga(steps)
    assert result.committed is False
    assert [(r.step, r.ok) for r in result.compensated] == [("hold", False)]
    assert "RuntimeError" in result.compensated[0].detail
    assert "rolled back 0 of 1" in result.reason


# -- run-path wiring -------------------------------------------------------


def test_shared_singleton_uses_data_dir(tmp_path, monkeypatch):
    base = tmp_path / "home"
    monkeypatch.setattr("maverick.paths.data_dir",
                        lambda *p, **k: base.joinpath(*p))
    ea.reset_shared()
    try:
        engine = ea.shared()
        assert engine.record_card(
            principal="p", action="deploy", risk="high", predicted_outcome=0.7,
            goal_id=1, episode_id=1, ts=1.0)
        assert (base / "consequence_cards.ndjson").exists()
        assert ea.shared() is engine
    finally:
        ea.reset_shared()


class _Verdict:
    def __init__(self, known=True, predicted=0.9, reason="well-trodden",
                 decision="proceed"):
        self.known = known
        self.predicted_outcome = predicted
        self.reason = reason
        self.decision = decision


def test_capture_prediction_filters_placeholders_and_held_actions(tmp_path):
    engine = _engine(tmp_path)
    assert ea.capture_prediction(
        _Verdict(known=False), principal="p", action="shell", risk="high",
        goal_id=1, episode_id=1, engine=engine) is None
    # A held action never executed -- its prediction must not become evidence.
    for held in ("block", "escalate"):
        assert ea.capture_prediction(
            _Verdict(decision=held), principal="p", action="shell", risk="high",
            goal_id=1, episode_id=1, engine=engine) is None
    card_id = ea.capture_prediction(
        _Verdict(), principal="p", action="shell", risk="high",
        goal_id=1, episode_id=1, engine=engine)
    assert card_id is not None
    rows = engine.cards.cards()
    assert len(rows) == 1
    assert rows[0]["source"] == "rehearsal" and rows[0]["predicted_outcome"] == 0.9
    # Garbage verdicts never raise into the caller.
    assert ea.capture_prediction(
        object(), principal="p", action="shell", risk="high",
        goal_id=1, episode_id=1, engine=engine) is None


# -- config getter ---------------------------------------------------------


def test_get_earned_autonomy_defaults_and_strict_arming(monkeypatch):
    from maverick import config as cfg_mod
    monkeypatch.setattr(cfg_mod, "load_config", lambda *a, **k: {
        "earned_autonomy": {
            "enable": True, "auto_graduate": "true",  # string never arms
            "min_streak": -5, "min_accuracy": 7, "max_auto_risk": "HIGH",
        },
    })
    cfg = cfg_mod.get_earned_autonomy()
    assert cfg["enable"] is True
    assert cfg["auto_graduate"] is False
    assert cfg["min_streak"] == 10          # invalid -> strict default
    assert cfg["min_accuracy"] == 0.9       # out of range -> strict default
    assert cfg["max_auto_risk"] == "high"
    assert cfg["require_reversible"] is True
    monkeypatch.setattr(cfg_mod, "load_config", lambda *a, **k: {})
    assert cfg_mod.get_earned_autonomy()["enable"] is False


def test_get_earned_autonomy_rejects_boolean_numbers(monkeypatch):
    """`min_streak = true` must not collapse the graduation bar to 1."""
    from maverick import config as cfg_mod
    monkeypatch.setattr(cfg_mod, "load_config", lambda *a, **k: {
        "earned_autonomy": {"min_streak": True, "min_samples": True},
    })
    cfg = cfg_mod.get_earned_autonomy()
    assert cfg["min_streak"] == 10 and cfg["min_samples"] == 10


# -- the operator CLI ------------------------------------------------------


def _cli(tmp_path, monkeypatch, args, env=None):
    from click.testing import CliRunner
    from maverick.cli import main
    base = tmp_path / "home"
    monkeypatch.setattr("maverick.paths.data_dir",
                        lambda *p, **k: base.joinpath(*p))
    ea.reset_shared()
    try:
        return CliRunner().invoke(main, ["earned-autonomy", *args],
                                  env=env or {"MAVERICK_EARNED_AUTONOMY": "1"})
    finally:
        ea.reset_shared()


def test_cli_empty_state_and_reconcile(tmp_path, monkeypatch):
    res = _cli(tmp_path, monkeypatch, ["--reconcile"])
    assert res.exit_code == 0, res.output
    assert "Reconciled 0 card(s)" in res.output
    assert "No consequence-card evidence" in res.output


def test_cli_disabled_message_and_revoke(tmp_path, monkeypatch):
    res = _cli(tmp_path, monkeypatch, ["--revoke", "wire_transfer"],
               env={"MAVERICK_EARNED_AUTONOMY": "0"})
    assert res.exit_code == 0, res.output
    assert "Evidence qualification cleared for 'wire_transfer'" in res.output
    assert "Explicit standing consent grants are unchanged" in res.output
    assert "disabled" in res.output
    # The revoke event landed even while the feature is off.
    assert "wire_transfer: no approval granted by evidence" in res.output


# -- agent integration: the rehearsal verdict lands as a card --------------


def _ctx(tmp_path, fake_llm):
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "w.db")
    gid = world.create_goal("test", "")
    return SwarmContext(
        llm=fake_llm, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=gid, max_depth=1,
    )


@pytest.mark.asyncio
async def test_agent_pins_rehearsal_prediction_as_card(
    tmp_path, fake_llm, monkeypatch, fresh_human_decision,
):
    from maverick import rehearsal
    from maverick.agent import Agent

    monkeypatch.setenv("MAVERICK_REHEARSAL", "1")
    # Subject is the rehearsal→card pipeline; the shell tool must actually
    # run, so the shared fixture supplies the fresh human decision its
    # permit requires (auto-approve would deny it).
    monkeypatch.setattr(
        "maverick.rehearsal_runtime.gate_tool",
        lambda **kw: rehearsal.RehearsalVerdict(
            rehearsal.PROCEED, 0.92, 0.05, 12, True, "well-trodden"))
    base = tmp_path / "home"
    monkeypatch.setattr("maverick.paths.data_dir",
                        lambda *p, **k: base.joinpath(*p))
    ea.reset_shared()
    try:
        ctx = _ctx(tmp_path, fake_llm)
        agent = Agent(ctx=ctx, role="orchestrator", brief="t", depth=0)
        out = await agent._run_tool("shell", {"cmd": "echo PINNED"})
        assert "PINNED" in out  # PROCEED: the tool actually ran
        rows = ea.shared().cards.cards()
        assert len(rows) == 1
        assert rows[0]["action"] == "shell"
        assert rows[0]["predicted_outcome"] == 0.92
        assert rows[0]["source"] == "rehearsal"
    finally:
        ea.reset_shared()


@pytest.mark.asyncio
async def test_agent_does_not_pin_held_verdicts(tmp_path, fake_llm, monkeypatch):
    from maverick import rehearsal
    from maverick.agent import Agent

    monkeypatch.setenv("MAVERICK_REHEARSAL", "1")
    monkeypatch.setattr(
        "maverick.rehearsal_runtime.gate_tool",
        lambda **kw: rehearsal.RehearsalVerdict(
            rehearsal.BLOCK, 0.1, 0.05, 12, True, "confidently poor"))
    base = tmp_path / "home"
    monkeypatch.setattr("maverick.paths.data_dir",
                        lambda *p, **k: base.joinpath(*p))
    ea.reset_shared()
    try:
        ctx = _ctx(tmp_path, fake_llm)
        agent = Agent(ctx=ctx, role="orchestrator", brief="t", depth=0)
        out = await agent._run_tool("shell", {"cmd": "echo HELD"})
        assert "HELD" not in out  # the action was held, never executed
        assert ea.shared().cards.cards() == []  # and never became evidence
    finally:
        ea.reset_shared()


# -- Shadow Mode: preview -> gate -> execute -> sign -----------------------


def _preview(*, action="wire_transfer", risk="high", predicted=0.9,
             reversible=True, exposure=240000.0):
    return ea.ConsequencePreview(
        action=action, predicted_outcome=predicted, risk=risk,
        effect=f"would move ${exposure:,.0f} via {action}",
        exposure_dollars=exposure, entities=("INV-42", "INV-43"),
        reversible=reversible)


def _steps(trail, *, fail=False):
    def _do():
        trail.append("do")
        if fail:
            raise RuntimeError("wire rejected")
        return "posted"

    return [ea.SagaStep("wire", _do, lambda: trail.append("undo") or "reversed")]


def test_shadow_human_approves_then_executes_and_pins_card(tmp_path):
    audits, trail = [], []
    engine = _engine(tmp_path, audits=audits)
    res = ea.shadow_execute(
        _preview(), _steps(trail), principal="cfo-bot", goal_id=1,
        episode_id=5, approve=lambda view: True, engine=engine)
    assert res.approved and res.executed and res.committed
    assert res.auto_approved is False and res.card_id is not None
    assert trail == ["do"]
    rows = engine.cards.cards()
    assert len(rows) == 1 and rows[0]["source"] == "simulate"
    assert rows[0]["exposure_dollars"] == 240000.0
    # The chain is signed: a shadow_execution audit row with the exposure.
    kinds = [k for k, _p in audits if k == "shadow_execution"]
    assert kinds == ["shadow_execution"]
    payload = next(p for k, p in audits if k == "shadow_execution")
    assert payload["decision"] == "approved" and payload["committed"] is True
    assert payload["exposure"] == 240000.0


def test_shadow_denied_does_not_execute_or_pin_a_card(tmp_path):
    audits, trail = [], []
    engine = _engine(tmp_path, audits=audits)
    res = ea.shadow_execute(
        _preview(), _steps(trail), principal="cfo-bot", goal_id=1,
        episode_id=5, approve=lambda view: False, engine=engine)
    assert res.approved is False and res.executed is False
    assert res.card_id is None and trail == []          # nothing ran
    assert engine.cards.cards() == []                   # nothing gradeable
    assert next(p for k, p in audits if k == "shadow_execution")["decision"] == "denied"


def test_shadow_approval_error_is_a_denial(tmp_path):
    trail = []
    engine = _engine(tmp_path)

    def _boom(view):
        raise RuntimeError("approver offline")

    res = ea.shadow_execute(
        _preview(), _steps(trail), principal="cfo-bot", goal_id=1,
        episode_id=5, approve=_boom, engine=engine)
    assert res.approved is False and trail == []


def test_shadow_still_requires_approval_for_a_graduated_action_type(tmp_path):
    trail = []
    engine = _engine(tmp_path)
    _graduate(engine)  # action-wide evidence does not authorize this effect
    assert engine.decide("wire_transfer", risk="high").auto is False
    consulted = []
    res = ea.shadow_execute(
        _preview(), _steps(trail), principal="cfo-bot", goal_id=1,
        episode_id=9, approve=lambda view: consulted.append(view) or False,
        engine=engine)
    assert res.auto_approved is False and not res.executed and not res.committed
    assert len(consulted) == 1
    assert trail == []


def test_shadow_refuses_irreversible_without_undo_before_any_effect(tmp_path):
    trail = []
    engine = _engine(tmp_path)
    steps = [ea.SagaStep("wire", lambda: trail.append("do") or "posted", None)]
    res = ea.shadow_execute(
        _preview(reversible=False), steps, principal="cfo-bot", goal_id=1,
        episode_id=5, approve=lambda view: True, engine=engine)
    assert res.approved is True and res.executed is False
    assert res.committed is False and res.card_id is None
    assert trail == []                        # refused before any effect
    assert engine.cards.cards() == []         # and never became evidence
    assert "without an inverse" in res.reason


def test_shadow_rolls_back_and_pins_no_card_on_failure(tmp_path):
    trail = []
    engine = _engine(tmp_path)
    steps = [
        ea.SagaStep("hold", lambda: trail.append("hold") or "ok",
                    lambda: trail.append("undo-hold") or "released"),
        ea.SagaStep("wire", lambda: (_ for _ in ()).throw(RuntimeError("no")),
                    lambda: "n/a"),
    ]
    res = ea.shadow_execute(
        _preview(), steps, principal="cfo-bot", goal_id=1, episode_id=5,
        approve=lambda view: True, engine=engine)
    assert res.executed is True and res.committed is False
    assert res.card_id is None                       # rolled back -> not graded
    assert engine.cards.cards() == []
    assert trail == ["hold", "undo-hold"]            # prefix compensated


def test_shadow_card_view_bounds_content_and_omits_raw_params(tmp_path):
    engine = _engine(tmp_path)
    captured = {}
    ea.shadow_execute(
        ea.ConsequencePreview(
            action="wire_transfer", predicted_outcome=0.9, risk="high",
            effect="x" * 5000, exposure_dollars=1000.0,
            entities=tuple(f"e{i}" for i in range(100)), reversible=True,
            params_sha256="deadbeef"),
        [ea.SagaStep("w", lambda: "ok", lambda: "ok")],
        principal="p", goal_id=1, episode_id=5,
        approve=lambda view: captured.update(view) or True, engine=engine)
    assert len(captured["effect"]) <= 300          # bounded
    assert len(captured["entities"]) == 32         # capped
    assert "params_sha256" not in captured         # raw params never shown


def test_shadow_end_to_end_earns_autonomy_from_real_outcomes(tmp_path):
    """The compounding loop: human-approved shadow executions get graded by
    reality, and after a proven streak the evidence is marked qualified."""
    engine = _engine(tmp_path)
    for ep in (1, 2, 3):
        res = ea.shadow_execute(
            _preview(), [ea.SagaStep("w", lambda: "ok", lambda: "ok")],
            principal="cfo-bot", goal_id=1, episode_id=ep,
            approve=lambda view: True, engine=engine)
        assert res.committed and res.card_id is not None
    # Reality confirms every prediction -> the streak graduates the action.
    report = engine.reconcile(resolve=lambda g, e: 1.0)
    assert report.graduated == ("wire_transfer",)
    assert engine.decide("wire_transfer", risk="high").auto is False


@pytest.mark.parametrize("source", ["rehearsal", "declared", "", "adapter"])
def test_asserted_reversibility_does_not_earn_autonomy(tmp_path, source):
    """A card that only *claims* an undo must not satisfy the reversibility gate.

    Regression: _reversible_share counted every card with reversible=True
    regardless of provenance, so a caller passing reversible=True through
    capture_prediction -- or anything calling record_card directly, which gets
    source="declared" from the dataclass default -- could graduate an action
    type past a gate whose failure text promises "a guaranteed undo". The same
    blended number is what an attestation would have shown an auditor.

    Only a preview adapter that round-tripped the write demonstrates an undo.
    Everything else keeps the human.
    """
    engine = _engine(tmp_path)
    for ep in (1, 2, 3):
        _card(engine, episode_id=ep, reversible=True, source=source)
    assert engine._reversible_share("wire_transfer") == 0.0
    assert engine.reconcile(resolve=lambda g, e: 1.0).graduated == ()
    assert engine.decide("wire_transfer", risk="high").auto is False


def test_one_asserted_card_blocks_an_otherwise_demonstrated_action(tmp_path):
    """Unearned cards stay in the denominator; they don't get filtered away.

    Dropping them would let a single demonstrated card carry an action type
    whose other writes were never previewed. The gate needs share >= 1.0, so a
    mixed history holds the human until every card is demonstrated.
    """
    engine = _engine(tmp_path)
    _card(engine, episode_id=1, source="simulate")
    _card(engine, episode_id=2, source="simulate")
    _card(engine, episode_id=3, source="rehearsal")  # asserted, not demonstrated
    assert engine._reversible_share("wire_transfer") == pytest.approx(2 / 3)
    assert engine.reconcile(resolve=lambda g, e: 1.0).graduated == ()


def test_irreversible_simulate_card_is_not_counted_either(tmp_path):
    """Provenance is necessary, not sufficient: the flag still has to be True."""
    engine = _engine(tmp_path)
    for ep in (1, 2, 3):
        _card(engine, episode_id=ep, reversible=False, source="simulate")
    assert engine._reversible_share("wire_transfer") == 0.0
    assert engine.reconcile(resolve=lambda g, e: 1.0).graduated == ()


def test_shadow_gate_uses_live_risk_not_the_preview_label(tmp_path, monkeypatch):
    """Regression: an under-declared preview risk must NOT let an already-
    graduated action auto-execute once its live risk exceeds the ceiling."""
    trail = []
    # Ceiling is medium; the action graduates while its live risk is medium...
    engine = _engine(tmp_path, policy=ea.GraduationPolicy(
        min_streak=3, min_samples=3, max_auto_risk="medium",
        require_reversible=True, armed=True))
    import importlib
    trm = importlib.import_module("maverick.safety.tool_risk")
    monkeypatch.setattr(trm, "tool_risk", lambda n, overrides=None: "medium")
    for ep in (1, 2, 3):
        _card(engine, episode_id=ep, action="send_campaign", risk="medium")
    assert engine.reconcile(resolve=lambda g, e: 1.0).graduated == ("send_campaign",)
    # ...then the action is reclassified UP to high (or the ceiling tightens).
    monkeypatch.setattr(trm, "tool_risk", lambda n, overrides=None: "high")
    # A preview under-declares the risk as 'medium' to try to skip the human.
    consulted = []
    res = ea.shadow_execute(
        _preview(action="send_campaign", risk="medium"), _steps(trail),
        principal="cfo-bot", goal_id=1, episode_id=9,
        approve=lambda view: consulted.append(view) or False, engine=engine)
    # The live-risk recheck keeps the human: auto is refused, approve consulted,
    # and (approve said no) nothing executes.
    assert res.auto_approved is False
    assert len(consulted) == 1 and res.executed is False and trail == []


def test_shadow_empty_steps_is_signed(tmp_path):
    audits = []
    engine = _engine(tmp_path, audits=audits)
    res = ea.shadow_execute(
        _preview(), [], principal="p", goal_id=1, episode_id=5,
        approve=lambda view: True, engine=engine)
    assert res.approved is True and res.executed is False
    assert next(p for k, p in audits if k == "shadow_execution")["committed"] is False
