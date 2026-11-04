"""Workflow publication contracts; authored for the later validation phase."""
import pytest
from maverick import templates
from maverick import workflow_versions as versions


@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(templates, "USER_TEMPLATES", tmp_path / "templates")
    monkeypatch.setattr(versions, "enabled", lambda: True)


def test_new_draft_requires_checked_publication_and_edit_keeps_published_snapshot(store):
    first = templates.save_user_template("weekly", title="Review", body="Review {{topic}}", owner="user:a")
    with pytest.raises(ValueError, match="Publish"):
        versions.execution_template("weekly")
    current = versions.history("weekly", "user:a")["current"]
    with pytest.raises(ValueError, match="fixture"):
        versions.publish("weekly", "user:a", expected_version=current, label="Initial")
    result = versions.record_fixture("weekly", "user:a", expected_version=current,
                                     inputs={"topic": "Sales"}, expected_contains="Sales")
    assert result["passed"] and result["external_actions"] == 0
    versions.publish("weekly", "user:a", expected_version=current, label="Initial")
    templates.save_user_template("weekly", title="Review", body="Different {{topic}}", owner="user:a", expected_generation=first.generation)
    published, version = versions.execution_template("weekly")
    assert published.body == "Review {{topic}}" and version == current
    assert versions.history("weekly", "user:a")["current"] != current


def test_restore_keeps_history_and_rechecks_owner_and_generation(store):
    first = templates.save_user_template("weekly", title="First", body="First", owner="user:a")
    original = versions.history("weekly", "user:a")["current"]
    second = templates.save_user_template("weekly", title="Second", body="Second", owner="user:a", expected_generation=first.generation)
    with pytest.raises(PermissionError):
        versions.restore("weekly", original, "user:b", expected_generation=second.generation)
    with pytest.raises(FileExistsError):
        versions.restore("weekly", original, "user:a", expected_generation=first.generation)
    restored = versions.restore("weekly", original, "user:a", expected_generation=second.generation)
    assert restored.generation == 3 and restored.body == "First"
    assert len(versions.history("weekly", "user:a")["versions"]) == 3


def test_failed_sample_does_not_authorize_publication_and_no_external_execution(store):
    templates.save_user_template("sample", title="Sample", body="Safe text", owner="user:a")
    current = versions.history("sample", "user:a")["current"]
    checked = versions.record_fixture("sample", "user:a", expected_version=current,
                                      inputs={}, expected_contains="Absent")
    assert not checked["passed"] and checked["external_actions"] == 0
    with pytest.raises(ValueError, match="fixture"):
        versions.publish("sample", "user:a", expected_version=current, label="Candidate")


def test_unpublished_snapshot_survives_publication_of_prior_version(store):
    templates.save_user_template("sample", title="Sample", body="Original", owner="user:a")
    snapshot = versions.history("sample", "user:a")["current"]
    copied = versions.restore("sample", snapshot, "user:a", expected_generation=1, new_name="copy")
    assert copied.name == "copy" and copied.owner == "user:a"
    with pytest.raises(FileExistsError):
        versions.restore("sample", snapshot, "user:a", expected_generation=1, new_name="copy")
