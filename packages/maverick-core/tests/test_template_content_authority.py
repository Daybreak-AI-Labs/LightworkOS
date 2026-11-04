"""Template previews, catalog publications and private drafts have distinct authority."""
import hashlib
import json

from maverick import templates


def test_template_owner_is_not_an_admin_bypass(tmp_path):
    template = templates.Template("private", "Private title", "private body", owner="user:alice", path=tmp_path / "private.md")
    assert templates.can_read_template(template, "user:alice")
    assert not templates.can_read_template(template, "user:admin")
    assert not templates.can_read_template(template, None)


def test_unknown_user_template_is_not_shared_by_missing_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(templates, "USER_TEMPLATES", tmp_path)
    monkeypatch.setattr(templates, "_BUNDLED_CANDIDATES", [])
    path = tmp_path / "legacy.md"
    path.write_text("legacy private text", encoding="utf-8")
    template = templates.load_template("legacy")
    assert not templates.can_read_template(template, "user:admin")
    assert not templates.can_read_template(template, None)


def test_bundle_allowance_is_exact_not_any_nonuser_path(tmp_path, monkeypatch):
    bundled = tmp_path / "bundled"
    monkeypatch.setattr(templates, "_BUNDLED_CANDIDATES", [bundled])
    monkeypatch.setattr(templates, "USER_TEMPLATES", tmp_path / "user")
    template = templates.Template("start", "Start", "body", path=bundled / "start.md")
    assert templates.can_read_template(template, "user:alice")
    template.path = tmp_path / "other" / "start.md"
    assert not templates.can_read_template(template, "user:alice")
    template.path = bundled / "private-subdir" / "start.md"
    assert not templates.can_read_template(template, "user:alice")


def test_catalog_publication_is_invalidated_by_edits(tmp_path, monkeypatch):
    monkeypatch.setattr(templates, "USER_TEMPLATES", tmp_path)
    monkeypatch.setattr(templates, "_BUNDLED_CANDIDATES", [])
    path = tmp_path / "catalog.md"
    path.write_text("public template", encoding="utf-8")
    (tmp_path / "catalog.publication.json").write_text(json.dumps({"schema": "lightwork.catalog-template-publication.v1", "name": "catalog", "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}), encoding="utf-8")
    assert templates.can_read_template(templates.load_template("catalog"), "user:alice")
    path.write_text("changed to private", encoding="utf-8")
    assert not templates.can_read_template(templates.load_template("catalog"), "user:alice")


def test_admin_cannot_read_private_version_history(tmp_path, monkeypatch):
    import pytest
    from maverick import workflow_versions
    template = templates.Template("private", "Title", "body", owner="user:alice")
    monkeypatch.setattr(workflow_versions, "load_template", lambda name: template)
    with pytest.raises(PermissionError):
        workflow_versions._current("private", "user:admin", admin=True)
