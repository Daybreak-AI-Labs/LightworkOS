"""The optional usability survey: SUS scoring, once-a-quarter offers, privacy, results."""
from __future__ import annotations

import calendar
import json
import os

import pytest
from maverick import usability_survey as survey

Q4 = calendar.timegm((2026, 10, 5, 12, 0, 0))
Q1 = calendar.timegm((2027, 1, 2, 12, 0, 0))


@pytest.fixture
def home(monkeypatch, tmp_path):
    from maverick import config

    def configure(text: str) -> None:
        path = tmp_path / "config.toml"
        path.write_text(text, encoding="utf-8")
        monkeypatch.setenv("MAVERICK_CONFIG", str(path))
        config.reset_config_cache()

    for name in tuple(os.environ):
        if name.startswith("MAVERICK_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    configure("[analytics]\nusability_survey = true\n")
    yield configure
    config.reset_config_cache()


def test_sus_scoring_follows_brooke():
    assert survey.sus_score([5, 1] * 5) == 100.0
    assert survey.sus_score([1, 5] * 5) == 0.0
    assert survey.sus_score([3] * 10) == 50.0
    # Odd items count (answer - 1), even items (5 - answer), times 2.5.
    assert survey.sus_score([4, 2, 4, 1, 4, 2, 5, 1, 4, 2]) == 82.5
    for bad in ([3] * 9, [3] * 9 + [6], [3] * 9 + [True]):
        with pytest.raises(survey.SurveyError):
            survey.sus_score(bad)


def test_the_published_items_and_quarters():
    assert len(survey.SUS_ITEMS) == 10
    assert survey.SUS_ITEMS[0].startswith("I think that I would like to use")
    assert survey.SUS_ITEMS[9].startswith("I needed to learn a lot of things")
    assert 3 <= len(survey.TOP_TASKS) <= 5
    assert survey.quarter(Q4) == "2026-Q4" and survey.quarter(Q1) == "2027-Q1"


def test_off_by_default(home):
    home("")
    assert survey.enabled() is False
    assert survey.offer_sus("user:kim", Q4) is False
    with pytest.raises(survey.SurveyError):
        survey.record_sus("user:kim", [3] * 10, now=Q4)
    home("[analytics]\nusability_survey = false\n")
    assert survey.enabled() is False


def test_sus_is_offered_once_a_quarter_and_one_dismissal_hides_it(home):
    assert survey.offer_sus("user:kim", Q4) is True
    survey.dismiss("user:kim", "sus", now=Q4)
    assert survey.offer_sus("user:kim", Q4) is False
    with pytest.raises(survey.SurveyError):
        survey.record_sus("user:kim", [3] * 10, now=Q4)
    assert survey.offer_sus("user:kim", Q1) is True
    assert survey.offer_sus("user:lee", Q4) is True
    assert survey.record_sus("user:lee", [4] * 10, role="approver", now=Q4) == 50.0
    assert survey.offer_sus("user:lee", Q4) is False


def test_seq_is_per_task_and_validated(home):
    assert survey.offer_seq("user:kim", "decide_approval", Q4) is True
    survey.record_seq("user:kim", "decide_approval", 6, now=Q4)
    assert survey.offer_seq("user:kim", "decide_approval", Q4) is False
    assert survey.offer_seq("user:kim", "change_setting", Q4) is True
    survey.dismiss("user:kim", "seq:change_setting", now=Q4)
    assert survey.offer_seq("user:kim", "change_setting", Q4) is False
    for task, rating in (("unknown", 4), ("invite_person", 0), ("invite_person", 8)):
        with pytest.raises(survey.SurveyError):
            survey.record_seq("user:kim", task, rating, now=Q4)


def test_stored_answers_never_hold_a_name(home):
    survey.record_sus("user:kim.smith@example.test", [5, 1] * 5, role="employee", now=Q4)
    survey.record_seq("user:kim.smith@example.test", "run_task", 7, role="employee", now=Q4)
    text = survey.store_path().read_text(encoding="utf-8")
    assert "kim" not in text and "example.test" not in text
    stored = json.loads(text)
    assert stored["sus"][0]["role"] == "employee" and "principal" not in stored["sus"][0]
    assert oct(survey.store_path().stat().st_mode)[-3:] == "600"


def test_results_need_five_answers_and_give_a_confidence_interval(home):
    scores = [[5, 1] * 5, [4, 2] * 5, [4, 2] * 5, [3] * 10, [5, 2] * 5]  # 100, 75, 75, 50, 87.5
    for index, answers in enumerate(scores[:4]):
        survey.record_sus(f"user:{index}", answers, role="administrator", now=Q4)
    survey.record_sus("user:x", [3] * 10, role="nonsense", now=Q4)
    report = survey.results("2026-Q4")
    admin = next(row for row in report["sus"] if row["role"] == "administrator")
    assert admin == {"role": "administrator", "label": admin["label"], "n": 4, "enough": False}
    assert next(row for row in report["sus"] if row["role"] == survey.NOT_GIVEN)["n"] == 1
    survey.record_sus("user:4", scores[4], role="administrator", now=Q4)
    admin = next(row for row in survey.results("2026-Q4")["sus"] if row["role"] == "administrator")
    assert admin["n"] == 5 and admin["enough"] is True
    assert admin["mean"] == 77.5
    # sd = 18.54; t(4) = 2.776; margin = 23.0, clipped at the top of the scale
    assert (admin["low"], admin["high"]) == (54.5, 100.0)
    assert survey.results("2027-Q1")["sus_total"]["n"] == 0


def test_seq_results_per_task(home):
    for index, rating in enumerate([7, 6, 6, 5, 7]):
        survey.record_seq(f"user:{index}", "invite_person", rating, now=Q4)
    row = next(r for r in survey.results("2026-Q4")["seq"] if r["task"] == "invite_person")
    assert row["n"] == 5 and row["mean"] == 6.2 and row["enough"] is True
