from __future__ import annotations

import random

import pytest
from maverick_evolve import EvalCase
from maverick_evolve.archive import Archive, Candidate
from maverick_evolve.loop import evolve_continuous


# ---- archive persistence (accumulate across rounds/runs) ----
def test_archive_save_load_roundtrip(tmp_path):
    a = Archive(capacity=10)
    a.add(Candidate(config={"k": 1}, score=0.5))
    a.add(Candidate(config={"k": 2}, score=0.9))
    p = tmp_path / "arch.json"
    a.save(p)
    b = Archive.load(p)
    assert b.capacity == 10
    assert b.best().config == {"k": 2}
    assert len(b.candidates) == 2


def test_archive_load_missing_returns_empty(tmp_path):
    a = Archive.load(tmp_path / "nope.json")
    assert a.candidates == []


def test_archive_load_corrupt_fails_closed(tmp_path):
    from maverick_evolve.archive import ArchiveIntegrityError

    p = tmp_path / "bad.json"
    p.write_text("{not json", encoding="utf-8")
    with pytest.raises(ArchiveIntegrityError):
        Archive.load(p)


def test_archive_checksum_detects_tampering(tmp_path):
    import json

    from maverick_evolve.archive import ArchiveIntegrityError

    p = tmp_path / "archive.json"
    archive = Archive()
    archive.add(Candidate(config={"n": 1}, score=0.5))
    archive.save(p)
    raw = json.loads(p.read_text(encoding="utf-8"))
    raw["payload"]["candidates"][0]["score"] = 1.0
    p.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ArchiveIntegrityError, match="checksum"):
        Archive.load(p)


# ---- continuous loop ----
# Graded landscape: one case per threshold so fitness rises smoothly with the
# knob and evolution has a gradient to climb (realistic, not a flat step).
_THRESHOLDS = [2, 4, 6, 8, 10, 12, 14]


def _graded_cases():
    return [EvalCase(prompt=str(t), check=lambda o: o == "GOOD") for t in _THRESHOLDS]


def _graded_factory():
    def factory(config: dict):
        async def agent(prompt: str) -> str:
            return "GOOD" if config.get("n", 0) >= int(prompt) else "BAD"
        return agent
    return factory


@pytest.mark.asyncio
async def test_continuous_accumulates_and_climbs(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)
    space = {"n": ("int", 1, 16)}
    archive_path = tmp_path / "arch.json"
    best, history = await evolve_continuous(
        {"n": 4}, _graded_cases(), _graded_factory(),
        rounds=3, generations_per_round=40,
        archive_path=archive_path, space=space, rng=random.Random(0),
    )
    assert len(history) == 3
    assert all("best_score" in h for h in history)
    # climbed substantially above the seed (n=4 passes 2/7 thresholds ~= 0.29)
    assert best.config["n"] >= 12 and best.score >= 6 / 7 - 1e-9
    # archive was persisted and accumulated
    assert archive_path.exists()
    assert Archive.load(archive_path).best().config["n"] >= 12


@pytest.mark.asyncio
async def test_continuous_resumes_from_saved_archive(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)
    space = {"n": ("int", 1, 16)}
    p = tmp_path / "arch.json"
    # seed a prior run's archive with a strong candidate
    seeded = Archive()
    seeded.add(Candidate(config={"n": 15}, score=1.0))
    seeded.save(p)
    best, _ = await evolve_continuous(
        {"n": 4}, _graded_cases(), _graded_factory(),
        rounds=1, generations_per_round=1, archive_path=p,
        space=space, rng=random.Random(0),
    )
    assert best.score == 1.0  # inherited the prior population's winner


@pytest.mark.asyncio
async def test_continuous_remeasures_persisted_scores_before_selection(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)
    path = tmp_path / "stale.json"
    stale = Archive()
    stale.add(Candidate(config={"n": 15}, score=1.0))
    stale.save(path)

    def changed_factory(config):
        async def agent(_prompt):
            return "GOOD" if config["n"] == 4 else "BAD"
        return agent

    best, history = await evolve_continuous(
        {"n": 4}, [EvalCase(prompt="now", check=lambda out: out == "GOOD")],
        changed_factory, rounds=1, generations_per_round=0,
        archive_path=path, space={"n": ("int", 1, 16)}, rng=random.Random(0),
    )
    assert best.config == {"n": 4}
    assert history[0]["archive_revalidated"] is True
    scores = {candidate.config["n"]: candidate.score
              for candidate in Archive.load(path).candidates}
    assert scores[15] == 0.0 and scores[4] == 1.0


@pytest.mark.asyncio
async def test_continuous_skips_rounds_when_frozen(monkeypatch):
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: True)
    best, history = await evolve_continuous(
        {"n": 4}, _graded_cases(), _graded_factory(),
        rounds=3, generations_per_round=10, rng=random.Random(0),
    )
    assert len(history) == 3
    assert all(h.get("skipped") for h in history)
    # Nothing evolved while the judge was frozen, but the seed is still a valid
    # returnable candidate (the archive is seeded up front) -- best() must not
    # be None, so callers always get a usable config back.
    assert best is not None
    assert best.config == {"n": 4}


@pytest.mark.asyncio
async def test_continuous_skips_when_calibration_backend_errors(monkeypatch):
    def _boom():
        raise OSError("calibration verdict unreadable")

    monkeypatch.delenv("MAVERICK_LEARNING_FROZEN", raising=False)
    monkeypatch.setattr("maverick.calibration.learning_frozen", _boom)
    best, history = await evolve_continuous(
        {"n": 4}, _graded_cases(), _graded_factory(),
        rounds=2, generations_per_round=10, rng=random.Random(0),
    )
    assert best.config == {"n": 4}
    assert len(history) == 2
    assert all(item.get("skipped") for item in history)


@pytest.mark.asyncio
async def test_continuous_risk_contract_fails_before_development_spend(monkeypatch):
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)
    factory_calls: list[dict] = []

    def factory(config: dict):
        factory_calls.append(config)

        async def agent(_prompt: str) -> str:
            return "PASS"

        return agent

    with pytest.raises(ValueError, match="durable confirmation authorization"):
        await evolve_continuous(
            {"n": 0},
            [EvalCase(prompt="development", check=lambda out: out == "PASS")],
            factory,
            rounds=1,
            generations_per_round=1,
            space={"n": ("int", 0, 1)},
            risk_limited=True,
            confirmation_cases=[
                EvalCase(prompt=f"sealed-{index}", check=lambda out: out == "PASS")
                for index in range(20)
            ],
        )

    assert factory_calls == []


@pytest.mark.asyncio
async def test_continuous_rejects_flat_confirmation_without_persisting(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)
    archive_path = tmp_path / "unconfirmed.json"
    sealed_prompts: list[tuple[int, str]] = []

    def factory(config: dict):
        async def agent(prompt: str) -> str:
            if prompt == "development":
                return "PASS" if config["n"] == 1 else "FAIL"
            sealed_prompts.append((config["n"], prompt))
            return "SAME"
        return agent

    best, history = await evolve_continuous(
        {"n": 0},
        [EvalCase(prompt="development", check=lambda out: out == "PASS")],
        factory,
        rounds=1,
        generations_per_round=1,
        archive_path=archive_path,
        space={"n": ("int", 0, 1)},
        rng=random.Random(1),
        confirmation_cases=[
            EvalCase(prompt="sealed", check=lambda out: out == "SAME")
        ],
    )

    assert best.config == {"n": 0}
    assert history[-1]["confirmation"] == "rejected"
    assert sealed_prompts == [(0, "sealed"), (1, "sealed")]
    # An unconfirmed development winner must not become adoptable on disk.
    assert not archive_path.exists()


@pytest.mark.asyncio
async def test_rejected_revalidation_durably_revokes_prior_confirmation(
    tmp_path, monkeypatch,
):
    """A failed new study must not leave the prior study adoptable on disk."""
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)
    archive_path = tmp_path / "previously-confirmed.json"
    archive = Archive()
    prior = archive.add(Candidate(config={"n": 1}, score=1.0))
    archive.mark_confirmed(prior.id)
    archive.save(archive_path)

    def factory(config: dict):
        async def agent(prompt: str) -> str:
            if prompt == "development":
                return "PASS" if config["n"] == 1 else "FAIL"
            return "SAME"
        return agent

    best, history = await evolve_continuous(
        {"n": 0},
        [EvalCase(prompt="development", check=lambda out: out == "PASS")],
        factory,
        rounds=1,
        generations_per_round=0,
        archive_path=archive_path,
        space={"n": ("int", 0, 1)},
        rng=random.Random(0),
        confirmation_cases=[
            EvalCase(prompt="sealed", check=lambda out: out == "SAME")
        ],
    )

    assert best.config == {"n": 0}
    assert history[-1]["confirmation"] == "rejected"
    persisted = Archive.load(archive_path)
    assert persisted.best() is not None
    assert persisted.confirmed_candidate_id is None
    assert persisted.confirmed_best() is None


@pytest.mark.asyncio
async def test_revalidation_exception_durably_revokes_prior_confirmation(
    tmp_path, monkeypatch,
):
    """Revocation is committed before revalidation work can fail or crash."""
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)
    archive_path = tmp_path / "previously-confirmed.json"
    archive = Archive()
    prior = archive.add(Candidate(config={"n": 1}, score=1.0))
    archive.mark_confirmed(prior.id)
    archive.save(archive_path)

    async def fail_revalidation(*_args, **_kwargs):
        raise RuntimeError("revalidation backend unavailable")

    monkeypatch.setattr(
        "maverick_evolve.loop.evolve_with_eval", fail_revalidation)
    with pytest.raises(RuntimeError, match="revalidation backend unavailable"):
        await evolve_continuous(
            {"n": 0},
            [EvalCase(prompt="development", check=lambda _out: True)],
            _graded_factory(),
            rounds=1,
            generations_per_round=0,
            archive_path=archive_path,
            confirmation_cases=[
                EvalCase(prompt="sealed", check=lambda _out: True)
            ],
        )

    persisted = Archive.load(archive_path)
    assert persisted.best() is not None
    assert persisted.confirmed_candidate_id is None
    assert persisted.confirmed_best() is None


@pytest.mark.asyncio
async def test_continuous_persists_only_after_true_lift_confirms(
    tmp_path, monkeypatch,
):
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)
    archive_path = tmp_path / "confirmed.json"
    sealed_prompts: list[tuple[int, str]] = []

    def factory(config: dict):
        async def agent(prompt: str) -> str:
            if prompt == "sealed":
                sealed_prompts.append((config["n"], prompt))
            return "PASS" if config["n"] == 1 else "FAIL"
        return agent

    best, history = await evolve_continuous(
        {"n": 0},
        [EvalCase(prompt="development", check=lambda out: out == "PASS")],
        factory,
        rounds=1,
        generations_per_round=1,
        archive_path=archive_path,
        space={"n": ("int", 0, 1)},
        rng=random.Random(1),
        confirmation_cases=[
            EvalCase(prompt="sealed", check=lambda out: out == "PASS")
        ],
        confirmation_margin=0.25,
    )

    assert best.config == {"n": 1}
    assert history[-1]["confirmation"] == "passed"
    assert sealed_prompts == [(0, "sealed"), (1, "sealed")]
    persisted = Archive.load(archive_path)
    assert persisted.best().config == {"n": 1}
    assert persisted.confirmed_best().config == {"n": 1}


# ---- demo CLI ----
def test_cli_demo_runs(capsys):
    from maverick_evolve.cli import main
    rc = main(["--demo", "--rounds", "2", "--generations", "25"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "BEST:" in out


def test_cli_no_args_prints_help(capsys):
    from maverick_evolve.cli import main
    rc = main([])
    assert rc == 0
    assert "maverick-evolve" in capsys.readouterr().out


@pytest.mark.asyncio
async def test_seed_champion_is_never_marked_promotion_confirmed(tmp_path, monkeypatch):
    # With no child beating the seed, confirm_candidate returns the seed with no
    # sealed comparison and no authorization; marking it confirmed made any
    # caller-chosen seed adoptable.
    monkeypatch.setattr("maverick_evolve.loop.calibration_frozen", lambda: False)
    archive_path = tmp_path / "seed.json"
    sealed: list[str] = []

    def factory(config: dict):
        async def agent(prompt: str) -> str:
            if prompt != "development":
                sealed.append(prompt)
            return "PASS"
        return agent

    authorized: list[object] = []
    best, history = await evolve_continuous(
        {"n": 0},
        [EvalCase(prompt="development", check=lambda out: out == "PASS")],
        factory,
        rounds=1,
        generations_per_round=0,
        archive_path=archive_path,
        space={"n": ("int", 0, 1)},
        rng=random.Random(1),
        confirmation_cases=[EvalCase(prompt="sealed", check=lambda out: out == "PASS")],
        confirmation_authorize=lambda *a, **k: authorized.append(a),
    )

    assert best.config == {"n": 0}
    assert history[-1]["confirmation"] == "rejected"
    assert sealed == [] and authorized == []
    if archive_path.exists():
        assert Archive.load(archive_path).confirmed_candidate_id is None
