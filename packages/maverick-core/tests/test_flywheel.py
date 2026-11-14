"""The flywheel: one grounded pass triages, guards, consolidates, and discovers
-- every engine turning together."""
from __future__ import annotations

import pytest
from maverick import consequence as cq
from maverick import flywheel
from maverick import negative_knowledge as nk
from maverick import procedural_memory as pm
from maverick.counterfactual_rollout import Transition, TransitionModel
from maverick.trajectory_store import TrajectoryStep


def _ep(eid, domain, tool, outcome):
    return [
        TrajectoryStep(ts=1.0, goal_id=1, episode_id=eid, step=0, role="coder",
                       tool=tool, domain=domain),
        TrajectoryStep(ts=1.0, goal_id=1, episode_id=eid, step=1, role="coder",
                       tool="log", domain=domain, is_final=True, outcome=outcome),
    ]


def _corpus():
    # X/Y correlate with outcomes; these ordinary rows prove no causal effect.
    steps, eid = [], 0
    for domain in ("fin", "ops"):
        for _ in range(12):
            eid += 1
            steps += _ep(eid, domain, "X", 0.2)
        for _ in range(12):
            eid += 1
            steps += _ep(eid, domain, "Y", 0.9)
    return steps


def test_run_once_turns_every_engine(tmp_path):
    rails = nk.GuardrailRegistry(path=tmp_path / "g.json")
    mem = pm.MemoryStore(path=tmp_path / "m.json")
    rep = flywheel.run_once(_corpus(), guardrails=rails, memory=mem)

    assert rep.n_episodes == 48 and not rep.acted
    assert rep.failure_classes[0].action == "X"
    assert not rep.failure_classes[0].trustworthy
    assert not rep.guardrails and not rep.memories and not rep.hypotheses
    assert rep.predicted_lift == 0
    # The real writer persists no causal promotion from observational evidence.
    assert rails.consult("X") is None and mem.strength_of("Y") == 0


def test_halt_at_guardrail_persistence_boundary_prevents_learned_write(
    monkeypatch, tmp_path,
):
    from maverick.killswitch import Halted

    rails = nk.GuardrailRegistry(path=tmp_path / "g.json")
    mem = pm.MemoryStore(path=tmp_path / "m.json")

    def guard(_job: str, phase: str) -> None:
        if phase == "guardrail_persistence":
            raise Halted("operator stop", "test")

    monkeypatch.setattr(flywheel, "check_learning_halt", guard)
    with pytest.raises(Halted):
        flywheel.run_once(_corpus(), guardrails=rails, memory=mem)
    assert rails.all() == []
    assert mem.recall() == []
    assert not (tmp_path / "g.json").exists()
    assert not (tmp_path / "m.json").exists()


def test_maybe_run_does_not_swallow_halt(monkeypatch):
    from maverick.killswitch import Halted

    monkeypatch.setattr(flywheel.data_engine, "enabled", lambda: True)

    def halt(_job: str, _phase: str) -> None:
        raise Halted("operator stop", "test")

    monkeypatch.setattr(flywheel, "check_learning_halt", halt)
    with pytest.raises(Halted):
        flywheel.maybe_run()


def test_run_once_simulates_when_world_model_supplied(tmp_path):
    START, GOOD, BAD = ("start",), ("good",), ("bad",)
    wm = TransitionModel().fit(
        [Transition(START, "Y", GOOD)] * 12 + [Transition(GOOD, "go", None, 1.0)] * 12
        + [Transition(START, "X", BAD)] * 12 + [Transition(BAD, "go", None, 0.0)] * 12
    )
    rep = flywheel.run_once(
        _corpus(), guardrails=nk.GuardrailRegistry(path=tmp_path / "g.json"),
        memory=pm.MemoryStore(path=tmp_path / "m.json"),
        world_model=wm, start_states=[START])
    assert rep.failure_classes and not rep.guardrails
    assert not rep.simulations  # simulated results cannot repair missing causal evidence


def test_grounded_outcome_prefers_reality(tmp_path, monkeypatch):
    store = cq.ConsequenceStore(path=tmp_path / "c.ndjson")
    store.record(1, 7, 1.0)  # reality: this episode actually succeeded
    monkeypatch.setattr("maverick.consequence.shared", lambda: store)
    monkeypatch.setenv("MAVERICK_CONSEQUENCE", "1")

    of = flywheel.grounded_outcome_fn()
    ep = _ep(7, "fin", "X", 0.2)   # proxy says 0.2, reality says 1.0
    assert of(ep) == 1.0


def test_maybe_run_noop_when_disabled(monkeypatch):
    monkeypatch.delenv("MAVERICK_DATA_ENGINE", raising=False)
    monkeypatch.setattr("maverick.config.get_data_engine", lambda: {"enable": False})
    rep = flywheel.maybe_run()
    assert rep.n_episodes == 0 and not rep.acted


def test_run_once_audits_each_learned_write_as_it_happens(tmp_path, monkeypatch):
    import maverick.audit as audit
    rows = []
    monkeypatch.setattr(audit, "record", lambda kind, **kw: rows.append((kind, kw)))
    rep = flywheel.run_once(_corpus(), guardrails=nk.GuardrailRegistry(path=tmp_path / "g.json"),
                            memory=pm.MemoryStore(path=tmp_path / "m.json"))
    assert [(k, kw["agent"], kw["store"], kw["written"]) for k, kw in rows] == [
        (audit.EventKind.LEARNING_UPDATE, "flywheel", "guardrails", len(rep.guardrails)),
        (audit.EventKind.LEARNING_UPDATE, "flywheel", "procedural_memory", len(rep.memories))]

    rows.clear()
    broken = pm.MemoryStore(path=tmp_path / "m2.json")
    monkeypatch.setattr(broken, "update", lambda mems: (_ for _ in ()).throw(OSError("disk")))
    with pytest.raises(OSError):
        flywheel.run_once(_corpus(), guardrails=nk.GuardrailRegistry(path=tmp_path / "g2.json"),
                          memory=broken)
    assert [kw["store"] for _, kw in rows] == ["guardrails"]  # the earlier write is on record


def test_cli_flywheel_fails_on_an_incomplete_cycle(monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main

    monkeypatch.setattr(
        "maverick.flywheel.maybe_run",
        lambda: flywheel.FlywheelReport(n_episodes=0, complete=False, problem="store unavailable"))
    text = CliRunner().invoke(main, ["flywheel"])
    assert text.exit_code != 0
    assert "store unavailable" in text.output
    as_json = CliRunner().invoke(main, ["flywheel", "--json"])
    assert as_json.exit_code != 0
    assert '"complete": false' in as_json.output
