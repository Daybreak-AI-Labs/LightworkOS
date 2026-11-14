"""A trial version of a changed specialist: deterministic goal split, recorded versions, ends and automatic roll back."""
from __future__ import annotations

from dataclasses import asdict
from types import SimpleNamespace

import pytest

PACK = "proc_po_chaser"


@pytest.fixture
def env(monkeypatch, tmp_path):
    from maverick import config
    from maverick import specialist_canary as canary

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "mh"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    audits = []
    import maverick.audit as audit

    monkeypatch.setattr(audit, "audit_event", lambda kind, **payload: audits.append(payload) or True)

    def settings(text: str) -> None:
        (tmp_path / "config.toml").write_text(text, encoding="utf-8")
        config.reset_config_cache()

    settings("")
    yield SimpleNamespace(canary=canary, settings=settings, audits=audits)
    config.reset_config_cache()


class FakeWorld:
    """Goal statuses and no feedback rows: enough for the trial's counts."""

    def __init__(self):
        self.status: dict[int, str] = {}

    def get_goals(self, goal_ids):
        return {goal_id: SimpleNamespace(status=self.status[goal_id]) for goal_id in goal_ids if goal_id in self.status}

    def query(self, sql, params=()):
        return []


def _start(canary, percent=50, *, name=PACK, profile=None):
    return canary.start(name, patch={"persona": "changed"}, profile=profile or {"name": name, "persona": "changed"},
                        percent=percent, actor="owner@example.test", title="Changed", reason="Test")


def _goals_on(canary, version, count, *, first=1, name=PACK, world=None):
    """Goal ids that a live trial assigns to ``version``, started in order."""
    found, goal_id = [], first
    while len(found) < count:
        chosen, _ = canary.version_for_goal(name, goal_id, world=world)
        if chosen == version:
            found.append(goal_id)
        goal_id += 1
    return found


def test_with_no_trial_nothing_is_recorded_and_the_current_version_runs(env):
    canary = env.canary

    assert canary.version_for_goal(PACK, 1) == (canary.CURRENT, None)
    assert canary.live(PACK) is None
    assert canary.TRIAL_GOALS.get(canary._goal_record_id(PACK, 1)) is None
    assert canary.TRIAL_GOALS.get(canary._goal_record_id(PACK, 3)) is None  # blocked


def test_the_trial_share_is_chosen_from_the_goal_id_and_each_goal_keeps_its_version(env):
    canary = env.canary
    _start(canary, percent=30)

    versions = {goal_id: canary.version_for_goal(PACK, goal_id)[0] for goal_id in range(1, 201)}
    share = sum(1 for version in versions.values() if version == canary.CANDIDATE) / len(versions)
    assert 0.2 <= share <= 0.4
    # The same goal always gets the same version, from the record and from the goal id alone.
    assert all(canary.version_for_goal(PACK, goal_id)[0] == version for goal_id, version in list(versions.items())[:25])
    assert all((canary.bucket(PACK, goal_id) < 30) == (version == canary.CANDIDATE) for goal_id, version in versions.items())
    row = canary.TRIAL_GOALS.get(canary._goal_record_id(PACK, 7))
    assert row["version"] == versions[7] and row["goal_id"] == 7


def test_a_recorded_choice_is_kept_after_the_trial_has_ended(env):
    canary = env.canary
    trial = _start(canary, percent=50)
    candidate_goal = _goals_on(canary, canary.CANDIDATE, 1)[0]
    canary.finish(PACK, candidate_id=trial["candidate_id"], outcome=canary.PROMOTED, actor="owner")

    # The goal already on the trial keeps its recorded version; a later trial cannot change it.
    assert canary.version_for_goal(PACK, candidate_goal) == (canary.CURRENT, None)
    later = _start(canary, percent=50)
    assert canary.version_for_goal(PACK, candidate_goal) == (canary.CURRENT, None)
    assert later["candidate_id"] != trial["candidate_id"]


def test_a_full_trial_store_drops_finished_goals_of_ended_trials(env, monkeypatch):
    canary = env.canary
    monkeypatch.setattr(canary, "MAX_ROWS", 4)
    monkeypatch.setattr(canary, "_PRUNE_RETRY_AFTER", 0.0)
    world = FakeWorld()
    first = _start(canary, percent=50)
    for goal_id in range(1, 5):
        canary.version_for_goal(PACK, goal_id)
        world.status[goal_id] = "blocked" if goal_id == 3 else "done"
    world.status[4] = "running"  # still running: its recorded choice must stay
    canary.finish(PACK, candidate_id=first["candidate_id"], outcome=canary.ROLLED_BACK, actor="owner")
    second = _start(canary, percent=50)

    canary.version_for_goal(PACK, 100, world=world)
    row = canary.TRIAL_GOALS.get(canary._goal_record_id(PACK, 100))
    assert row is not None and row["candidate_id"] == second["candidate_id"]
    assert canary.TRIAL_GOALS.get(canary._goal_record_id(PACK, 4))["candidate_id"] == first["candidate_id"]
    assert canary.TRIAL_GOALS.get(canary._goal_record_id(PACK, 1)) is None
    assert canary.TRIAL_GOALS.get(canary._goal_record_id(PACK, 3)) is None  # blocked


def test_a_resumed_goal_with_no_recorded_choice_keeps_the_current_version(env):
    canary = env.canary
    _start(canary, percent=50)

    assert canary.version_for_goal(PACK, 424242, resume=True) == (canary.CURRENT, None)
    assert canary.TRIAL_GOALS.get(canary._goal_record_id(PACK, 424242)) is None


def test_a_second_change_is_refused_while_a_trial_is_live(env):
    canary = env.canary
    _start(canary, percent=10)

    with pytest.raises(canary.TrialAlreadyLive):
        _start(canary, percent=10)
    assert canary.live(PACK)["percent"] == 10


def test_ending_a_trial_with_a_stale_candidate_is_refused(env):
    canary = env.canary
    trial = _start(canary, percent=10)

    with pytest.raises(canary.TrialChanged):
        canary.finish(PACK, candidate_id="not-the-live-one", outcome=canary.ROLLED_BACK, actor="owner")
    canary.finish(PACK, candidate_id=trial["candidate_id"], outcome=canary.ROLLED_BACK, actor="owner")
    assert canary.live(PACK) is None
    assert canary.TRIALS.get(canary._trial_id(PACK))["last"]["outcome"] == canary.ROLLED_BACK


def test_a_candidate_goal_runs_the_trial_profile_and_others_run_the_current_one(env):
    from maverick.domain import builtin_domains

    canary = env.canary
    current = builtin_domains()[PACK]
    changed = asdict(current)
    changed["persona"] = current.persona + " Always name the supplier to chase in one short line."
    _start(canary, percent=50, profile=changed)
    candidate_goal = _goals_on(canary, canary.CANDIDATE, 1)[0]
    current_goal = _goals_on(canary, canary.CURRENT, 1)[0]

    run_candidate, version = canary.profile_for_goal(PACK, current, candidate_goal)
    run_current, current_version = canary.profile_for_goal(PACK, current, current_goal)
    assert version == canary.CANDIDATE and run_candidate.persona == changed["persona"]
    assert current_version == canary.CURRENT and run_current is current


def test_automatic_roll_back_needs_ten_finished_candidate_goals_and_a_gap_of_more_than_twenty_points(env):
    canary = env.canary
    env.settings("[agent_tests]\ncanary_auto_rollback = true\n")
    world = FakeWorld()
    trial = _start(canary, percent=50)
    candidate = _goals_on(canary, canary.CANDIDATE, 10)
    current = _goals_on(canary, canary.CURRENT, 10, first=1000)
    # Candidate fails 5 of 10 (50%); current fails 2 of 10 (20%): 30 points, more than 20.
    for index, goal_id in enumerate(candidate):
        world.status[goal_id] = "failed" if index < 5 else "done"
    for index, goal_id in enumerate(current):
        world.status[goal_id] = "failed" if index < 2 else "done"

    new_goal = _goals_on(canary, canary.CURRENT, 1, first=5000)[0]
    assert canary.version_for_goal(PACK, new_goal, world=world) == (canary.CURRENT, None)
    assert canary.live(PACK) is None
    assert canary.TRIALS.get(canary._trial_id(PACK))["last"]["outcome"] == canary.ROLLED_BACK_AUTOMATICALLY
    assert any(row.get("verb") == "agent_trial_rolled_back_automatically" for row in env.audits)
    assert trial["candidate_id"] == canary.TRIALS.get(canary._trial_id(PACK))["last"]["candidate_id"]


def test_a_gap_of_exactly_twenty_points_and_too_few_goals_do_not_roll_back(env):
    canary = env.canary
    env.settings("[agent_tests]\ncanary_auto_rollback = true\n")
    world = FakeWorld()
    _start(canary, percent=50)
    candidate = _goals_on(canary, canary.CANDIDATE, 10)
    current = _goals_on(canary, canary.CURRENT, 10, first=1000)
    # Candidate 4 of 10 failed (40%), current 2 of 10 (20%): exactly 20 points is not more than 20.
    for index, goal_id in enumerate(candidate):
        world.status[goal_id] = "failed" if index < 4 else "done"
    for index, goal_id in enumerate(current):
        world.status[goal_id] = "failed" if index < 2 else "done"
    assert canary.version_for_goal(PACK, 6000, world=world)[0] in {canary.CURRENT, canary.CANDIDATE}
    assert canary.live(PACK) is not None

    # Nine finished candidate goals is not enough, however bad they are.
    for goal_id in candidate[:-1]:
        world.status[goal_id] = "failed"
    world.status[candidate[-1]] = "running"
    assert canary.auto_rollback_due(PACK, world, canary.live(PACK)) is False


def test_the_automatic_roll_back_is_off_by_default(env):
    canary = env.canary
    world = FakeWorld()
    _start(canary, percent=50)
    for goal_id in _goals_on(canary, canary.CANDIDATE, 10):
        world.status[goal_id] = "failed"
    for goal_id in _goals_on(canary, canary.CURRENT, 10, first=1000):
        world.status[goal_id] = "blocked" if goal_id == 3 else "done"

    canary.version_for_goal(PACK, 5000, world=world)
    assert canary.live(PACK) is not None
    assert not any(row.get("verb") == "agent_trial_rolled_back_automatically" for row in env.audits)


def test_a_trial_applies_only_to_its_own_specialist(env):
    canary = env.canary
    _start(canary, percent=20)

    # Another specialist keeps its own, untouched, current version.
    assert canary.version_for_goal("proc_other_pack", 1) == (canary.CURRENT, None)
    assert canary.live("proc_other_pack") is None


def test_automatic_roll_back_waits_for_a_finished_current_goal_to_compare_with(env):
    canary = env.canary
    env.settings("[agent_tests]\ncanary_auto_rollback = true\n")
    world = FakeWorld()
    _start(canary, percent=50)
    candidate = _goals_on(canary, canary.CANDIDATE, 10)
    current = _goals_on(canary, canary.CURRENT, 10, first=1000)
    for goal_id in candidate:
        world.status[goal_id] = "failed"
    # With no finished current goal there is no current failure share to compare with, so the trial is not rolled back.
    for goal_id in current:
        world.status[goal_id] = "running"
    assert canary.auto_rollback_due(PACK, world, canary.live(PACK)) is False
    # Once one current goal finishes, the comparison exists and the failing trial is rolled back.
    world.status[current[0]] = "done"
    assert canary.auto_rollback_due(PACK, world, canary.live(PACK)) is True


def test_the_automatic_check_runs_at_most_once_a_minute_for_a_trial(env, monkeypatch):
    canary = env.canary
    env.settings("[agent_tests]\ncanary_auto_rollback = true\n")
    world = FakeWorld()
    _start(canary, percent=50)
    calls = []
    monkeypatch.setattr(canary, "auto_rollback_due", lambda *args: calls.append(args) or False)
    clock = [1000.0]
    monkeypatch.setattr(canary, "_now", lambda: clock[0])
    for goal_id in range(1, 6):
        canary.version_for_goal(PACK, goal_id, world=world)
    assert len(calls) == 1
    clock[0] += canary.AUTO_CHECK_SECONDS + 1
    canary.version_for_goal(PACK, 7, world=world)
    assert len(calls) == 2


def test_the_feedback_counts_say_when_the_bounded_summary_was_cut_short(env):
    canary = env.canary
    _start(canary, percent=50)
    _goals_on(canary, canary.CANDIDATE, 1)

    class FullFeedbackWorld(FakeWorld):
        def query(self, sql, params=()):
            # Five thousand receipts is the summary's limit; these cannot be read, so the summary stays partial.
            return [{"id": index, "owner": "", "receipt": "{}"} for index in range(5000)]

    stats = canary.version_stats(PACK, FullFeedbackWorld(), candidate_id=canary.live(PACK)["candidate_id"])
    assert stats[canary.CANDIDATE]["feedback_complete"] is False
    assert stats[canary.CURRENT]["feedback_complete"] is False
    complete = canary.version_stats(PACK, FakeWorld(), candidate_id=canary.live(PACK)["candidate_id"])
    assert complete[canary.CANDIDATE]["feedback_complete"] is True
