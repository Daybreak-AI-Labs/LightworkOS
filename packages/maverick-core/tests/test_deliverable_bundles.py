"""Native selected-evidence copies, revocation, stale acceptance and portable export."""
import hashlib
import io
import json
import zipfile
from html.parser import HTMLParser

import pytest
from maverick import attachments, audit, config
from maverick.deliverable_bundle_export import export_zip, files_for
from maverick.deliverable_bundles import BundleDenied, DeliverableBundles
from maverick.paths import tenant_scope
from maverick.privacy_ops import RecordConflict
from maverick.world_model import WorldModel


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    monkeypatch.setenv("MAVERICK_ENTERPRISE", "0")
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    monkeypatch.setattr(attachments, "DEFAULT_ROOT", tmp_path / "attachments")
    monkeypatch.setattr(audit, "record", lambda *args, **kwargs: True)
    (tmp_path / "config.toml").write_text("", encoding="utf-8")
    config.reset_config_cache()
    with tenant_scope(tenant="tenant-a"), WorldModel(tmp_path / "world.db") as world:
        goal = world.create_goal("Private work", "Unselected private instructions", owner="user:owner")
        world.set_goal_status(goal, "done", result="Unselected private result")
        chosen = world.add_artifact(goal, kind="table", title="Selected table", content="| Name | Amount |\n| --- | --- |\n| =UNTRUSTED() | 12 |")
        other = world.add_artifact(goal, kind="text", title="Private artifact", content="Never shared")
        grants = {"user:owner": True, "user:recipient": True, "user:other": True}
        def service(actor):
            return DeliverableBundles(world, actor=actor, eligible=lambda who, *_: grants.get(who, False))
        yield world, goal, chosen, other, grants, service
    config.reset_config_cache()


def share(setup, **changes):
    _world, goal, chosen, _other, _grants, service = setup
    choices = {"artifact_ids": [chosen], "attachment_ids": [], "include_result": False,
               "name": "For recipient review", "recipient": "user:recipient",
               "note": "Review the selected numbers.", "unresolved": "Verify factual accuracy.", "lifetime": 86400}
    choices.update(changes)
    owner = service("user:owner")
    preview = owner.prepare(goal, **choices)
    row = owner.create(goal, expected_review=preview["review_version"], operation_id="share-operation-one", **choices)
    return row, choices, preview


def test_only_selected_artifact_is_shared_and_exact_replay_is_one_bundle(setup):
    world, goal, _, _, _, service = setup
    row, choices, preview = share(setup)
    repeated = service("user:owner").create(goal, expected_review=preview["review_version"], operation_id="share-operation-one", **choices)
    assert repeated["id"] == row["id"] and len(service("user:owner").inbox()) == 1
    recipient = service("user:recipient").get(row["id"])
    encoded = json.dumps(recipient)
    assert "Unselected private result" not in encoded and "Never shared" not in encoded
    assert recipient["payload"]["source"]["selection"]["include_result"] is False
    assert world.get_goal(goal).owner == "user:owner"
    with pytest.raises(BundleDenied):
        service("user:other").get(row["id"])


def test_acceptance_is_separate_and_new_artifact_version_makes_it_stale(setup):
    world, goal, _, _, _, service = setup
    row, _, _ = share(setup)
    assert row["acceptance"] is None and not row["acceptance_current"]
    accepted = service("user:recipient").respond(row["id"], action="accept", note="Checked the figures.",
                                                  expected_revision=row["revision"], operation_id="accept-operation-one")
    assert accepted["acceptance_current"]
    world.add_artifact(goal, kind="table", title="Selected table", content="New source version")
    stale = service("user:recipient").get(row["id"])
    assert stale["stale"] and not stale["acceptance_current"] and not stale["can_accept"]
    assert stale["acceptance"]["note"] == "Checked the figures."


def test_revocation_and_current_membership_end_recipient_access(setup):
    _, _, _, _, grants, service = setup
    row, _, _ = share(setup)
    grants["user:recipient"] = False
    with pytest.raises(BundleDenied):
        service("user:recipient").get(row["id"])
    grants["user:recipient"] = True
    revoked = service("user:owner").respond(row["id"], action="revoke", note="",
                                             expected_revision=row["revision"], operation_id="revoke-operation-one")
    assert revoked["status"] == "revoked"
    with pytest.raises(BundleDenied):
        service("user:recipient").get(row["id"])


def test_a_full_bundle_store_archives_revoked_bundles_and_inbox_keeps_working(setup, monkeypatch):
    from maverick import deliverable_bundles

    _, goal, chosen, _, _, service = setup
    monkeypatch.setattr(deliverable_bundles, "_MAX_BUNDLES", 1)
    row, choices, _ = share(setup)
    service("user:owner").respond(row["id"], action="revoke", note="",
                                  expected_revision=row["revision"], operation_id="revoke-operation-one")
    owner = service("user:owner")
    preview = owner.prepare(goal, **choices)
    second = owner.create(goal, expected_review=preview["review_version"],
                          operation_id="share-operation-two", **choices)
    assert [entry["id"] for entry in owner.inbox()] == [second["id"]]


def test_changed_source_or_recipient_cannot_reuse_prepared_share(setup):
    world, goal, chosen, _, _, service = setup
    owner = service("user:owner")
    choices = {"artifact_ids": [chosen], "attachment_ids": [], "include_result": True,
               "name": "Reviewed", "recipient": "user:recipient", "note": "Review", "unresolved": "", "lifetime": 3600}
    preview = owner.prepare(goal, **choices)
    world.set_goal_status(goal, "done", result="Changed result")
    with pytest.raises(RecordConflict):
        owner.create(goal, expected_review=preview["review_version"], operation_id="changed-operation-one", **choices)
    assert not owner.inbox()


def test_selected_evidence_from_another_task_is_refused(setup):
    world, goal, _, _, _, service = setup
    other = world.create_goal("Another person's work", owner="user:other")
    foreign = world.add_artifact(other, kind="text", title="Other evidence", content="Do not share")
    with pytest.raises(BundleDenied):
        service("user:owner").capture(goal, artifact_ids=[foreign], attachment_ids=[], include_result=False)


def test_selected_original_evidence_is_verified_and_copied_without_other_files(setup):
    world, goal, _, _, _, _ = setup
    content = b"Selected private evidence"
    stored = attachments.store(goal, "evidence.txt", "text/plain", content)
    selected = world.add_attachment(goal, "evidence.txt", "text/plain", len(content),
                                    hashlib.sha256(content).hexdigest(), str(stored.path))
    row, _, _ = share(setup, artifact_ids=[], attachment_ids=[selected])
    files = files_for(row)
    originals = [data for name, data in files.items() if name.endswith(".txt")]
    assert originals == [content]


def test_offline_manifest_matches_every_selected_file_and_csv_is_formula_safe(setup):
    row, _, _ = share(setup)
    archive = zipfile.ZipFile(io.BytesIO(export_zip(row)))
    manifest = json.loads(archive.read("manifest.json"))
    for item in manifest["files"]:
        raw = archive.read(item["name"])
        assert len(raw) == item["bytes"] and hashlib.sha256(raw).hexdigest() == item["sha256"]
    csv_name = next(name for name in archive.namelist() if name.endswith(".csv"))
    assert "'=UNTRUSTED()" in archive.read(csv_name).decode("utf-8-sig")
    verifier = archive.read("verify.html").decode()
    assert "crypto.subtle.digest" in verifier and "fetch(" not in verifier
    assert "No current human acceptance" in archive.read("index.html").decode()


def test_safe_render_never_turns_captured_markup_into_active_content(setup):
    world, goal, _, _, _, _ = setup
    artifact = world.add_artifact(goal, kind="text", title="<script>title</script>", content='<img src="https://example.com" onerror="bad()"><script>bad()</script>')
    row, _, _ = share(setup, artifact_ids=[artifact])
    class Elements(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = []
        def handle_starttag(self, tag, attrs):
            self.tags.append(tag)
    parser = Elements()
    parser.feed(files_for(row)["index.html"].decode())
    assert "script" not in parser.tags and "img" not in parser.tags


def test_failed_export_does_not_replace_saved_bundle(setup, monkeypatch):
    row, _, _ = share(setup)
    _, _, _, _, _, service = setup
    monkeypatch.setattr(zipfile.ZipFile, "writestr", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("disk unavailable")))
    with pytest.raises(OSError):
        export_zip(row)
    unchanged = service("user:owner").get(row["id"])
    assert unchanged["revision"] == row["revision"] and unchanged["payload"] == row["payload"]
