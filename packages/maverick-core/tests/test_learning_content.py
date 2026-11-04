"""Employee-derived capabilities retain current ownership at every read/use."""
import hashlib
import json

import pytest
from maverick import learning_content, self_learning
from maverick.connections import bind_principal


def test_ledger_filters_before_limit_and_retains_unknown_legacy(tmp_path):
    path = tmp_path / "learned.ndjson"
    legacy = {"ts": 1, "need": "legacy employee secret", "name": "legacy",
              "kind": "skill", "source": "", "outcome": "acquired"}
    path.write_text(json.dumps(legacy) + "\n", encoding="utf-8")
    with bind_principal("user:alice"):
        assert self_learning.record("alice private need", "skill", "alice_tool", path=path)
    with bind_principal("user:bob"):
        assert self_learning.record("bob private need", "skill", "bob_tool", path=path)
    assert [r.name for r in self_learning.history(path=path, owner="user:alice", limit=1)] == ["alice_tool"]
    assert self_learning.history(path=path, owner="user:admin") == []
    assert self_learning.history(path=path, owner="") == []
    assert "legacy employee secret" in path.read_text(encoding="utf-8")


def test_current_task_ownership_and_learning_exclusion_are_rechecked(monkeypatch):
    record = {"content_version": 1, "owner": "user:alice", "goal_id": 42}
    allowed = {"value": True}
    monkeypatch.setattr("maverick.memory_ownership.source_allowed", lambda gid, owner: allowed["value"])
    assert learning_content.allowed(record, owner="user:alice")
    assert not learning_content.allowed(record, owner="user:admin")
    allowed["value"] = False
    assert not learning_content.allowed(record, owner="user:alice")
    assert not learning_content.allowed({"owner": "user:alice"}, owner="user:alice")


def test_generated_source_is_digest_and_owner_bound(tmp_path):
    target = tmp_path / "private_tool.py"
    source = "# employee derived source"
    target.write_text(source, encoding="utf-8")
    digest = hashlib.sha256(source.encode()).hexdigest()
    assert not learning_content.source_allowed_now(target, digest, owner="user:alice")
    with bind_principal("user:alice"):
        learning_content.publish(target, source, learning_content.lineage())
    assert learning_content.source_allowed_now(target, digest, owner="user:alice")
    assert not learning_content.source_allowed_now(target, digest, owner="user:admin")
    assert not learning_content.source_allowed_now(target, "changed", owner="user:alice")
    learning_content.metadata_path(target).unlink()
    assert not learning_content.source_allowed_now(target, digest, owner="user:alice")


def test_live_generated_proxy_rechecks_owner_before_and_after_effect(tmp_path, monkeypatch):
    monkeypatch.setitem(self_learning.__dict__, "GENERATED_TOOLS_DIR", tmp_path)
    monkeypatch.setattr(self_learning, "_generated_consent_granted", lambda **kw: True)
    source = "# private"
    digest = hashlib.sha256(source.encode()).hexdigest()
    target = tmp_path / "private_tool.py"
    target.write_text(source, encoding="utf-8")
    with bind_principal("user:alice"):
        learning_content.publish(target, source, learning_content.lineage())
        proxy = self_learning._generated_tool_proxy(source=source, digest=digest, tenant="shared", sandbox=None,
            metadata={"name": "private_tool", "description": "private", "input_schema": {}})
    calls = []
    def execute(**kw):
        calls.append(True)
        learning_content.metadata_path(target).unlink()
        return "private answer"
    monkeypatch.setattr(self_learning, "_execute_generated_tool", execute)
    with bind_principal("user:bob"):
        assert "unavailable" in proxy.fn({})
    assert not calls
    with bind_principal("user:alice"):
        assert "unavailable" in proxy.fn({})
    assert calls == [True]


def test_delete_does_not_let_admin_remove_another_owners_source(tmp_path, monkeypatch):
    monkeypatch.setitem(self_learning.__dict__, "GENERATED_TOOLS_DIR", tmp_path)
    target = tmp_path / "private_tool.py"
    target.write_text("# source", encoding="utf-8")
    with bind_principal("user:alice"):
        learning_content.publish(target, "# source", learning_content.lineage())
    with pytest.raises(PermissionError):
        self_learning.delete_generated_tool("private_tool", owner="user:admin")
    assert target.is_file()


def test_delete_checks_reviewed_digest_before_revoking_consent(tmp_path, monkeypatch):
    monkeypatch.setitem(self_learning.__dict__, "GENERATED_TOOLS_DIR", tmp_path)
    target = tmp_path / "private_tool.py"
    target.write_text("# replacement", encoding="utf-8")
    with bind_principal("user:alice"):
        learning_content.publish(target, "# replacement", learning_content.lineage())
    def revoke(*args, **kwargs):
        raise AssertionError("A changed source must not revoke current consent")
    monkeypatch.setattr("maverick.safety.consent.revoke", revoke)
    with pytest.raises(self_learning.GeneratedToolRemovalError, match="changed"):
        self_learning.delete_generated_tool("private_tool", owner="user:alice", expected_digest="old digest")
    assert target.read_text(encoding="utf-8") == "# replacement"
