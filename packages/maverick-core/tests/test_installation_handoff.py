"""Private handoff regression fixtures; authored, not executed for the UX audit."""
import contextlib
import copy

import pytest
from maverick import installation_handoff as handoff


@pytest.fixture
def store(monkeypatch, tmp_path):
    records = {}
    monkeypatch.setattr(handoff.recovery, "_locked", contextlib.nullcontext)
    monkeypatch.setattr(handoff.recovery, "_store", lambda: tmp_path)
    monkeypatch.setattr(handoff.recovery, "_target", lambda: "installation-a")
    def write(path, value):
        path.touch()
        records[path.name] = copy.deepcopy(value)
    monkeypatch.setattr(handoff.recovery, "_write", write)
    monkeypatch.setattr(handoff.recovery, "_read", lambda path: copy.deepcopy(records[path.name]))
    return records


def test_exact_review_changes_and_expiry(store, monkeypatch):
    release = dict(version="1.2.3", runtime_sha256="a" * 64, installer_sha256="b" * 64, signature="signed")
    first = handoff.save_review(release)
    assert handoff.reviewed_release(first["id"]) == release
    handoff.save_review(dict(release, installer_sha256="c" * 64))
    with pytest.raises(handoff.recovery.MaintenanceError, match="expired or changed"):
        handoff.reviewed_release(first["id"])
    monkeypatch.setattr(handoff.time, "time", lambda: store["native-review.json"]["expires_at"] + 1)
    assert handoff.current_review() is None


def test_public_handoff_never_exposes_authority_and_rechecks_actor(store, monkeypatch):
    grant = dict(id="a" * 32, actor="session-bound-admin", operation="upgrade", old_version="1.0.0", expires_at=99999999999, reviewed_new={"version": "1.2.3"})
    monkeypatch.setattr(handoff.recovery, "_grant", lambda token: (None, grant))
    public = handoff.publish("a" * 32 + ":" + "b" * 64, actor_label="Admin A")
    assert "authorization" not in public and "actor" not in public
    assert handoff.inspect_handoff()["actor"] == "session-bound-admin"
    grant["actor"] = "different-session"
    with pytest.raises(handoff.recovery.MaintenanceError, match="no longer matches"):
        handoff.inspect_handoff()


def test_generic_upgrade_cannot_use_protected_handoff(store, monkeypatch):
    monkeypatch.setattr(handoff.recovery, "_grant", lambda token: (None, {"operation": "upgrade"}))
    with pytest.raises(handoff.recovery.MaintenanceError, match="exact reviewed"):
        handoff.publish("unused", actor_label="Admin")


@pytest.mark.parametrize("identifier", ["é" * 32, "\ud800" * 32])
def test_a_non_ascii_review_id_is_a_refusal_not_a_type_error(store, identifier):
    release = dict(version="1.2.3", runtime_sha256="a" * 64, installer_sha256="b" * 64, signature="signed")
    handoff.save_review(release)
    with pytest.raises(handoff.recovery.MaintenanceError, match="expired or changed"):
        handoff.reviewed_release(identifier)


@pytest.mark.parametrize("damage", ["unauthenticated", "unreadable", "malformed"])
def test_an_unusable_review_file_is_no_review_and_never_breaks_the_status_read(store, monkeypatch, damage):
    release = dict(version="1.2.3", runtime_sha256="a" * 64, installer_sha256="b" * 64, signature="signed")
    first = handoff.save_review(release)
    if damage == "malformed":
        store["native-review.json"] = {"kind": "native-release-review", "expires_at": 99999999999}
    else:
        def refuse(path):
            raise handoff.recovery.MaintenanceError("not authentic") if damage == "unauthenticated" else OSError("locked")
        monkeypatch.setattr(handoff.recovery, "_read", refuse)
    assert handoff.current_review() is None
    with pytest.raises(handoff.recovery.MaintenanceError, match="expired or changed"):
        handoff.reviewed_release(first["id"])
