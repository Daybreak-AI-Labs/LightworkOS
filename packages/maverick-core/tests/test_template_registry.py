"""Goal templates v2: community registry discover + install."""
from __future__ import annotations

import hashlib
import sys
from types import SimpleNamespace

import pytest
from click.testing import CliRunner
from maverick import catalog, config, skills, templates
from maverick.cli import main

_BODY = "---\ntitle: Plan a trip\nparams:\n  - city\n---\nPlan a trip to {{ city }}.\n"
_SHA = hashlib.sha256(_BODY.encode()).hexdigest()
_INDEX = {
    "schema_version": 1, "kind": "templates",
    "entries": [{
        "name": "trip-plan", "version": "1.0.0", "summary": "Plan a trip.",
        "source": "gh:org/repo:templates/trip-plan.md", "sha256": _SHA,
    }],
}


@pytest.fixture
def fake_registry(monkeypatch):
    monkeypatch.setattr(catalog, "_fetch_index_raw", lambda url: _INDEX)
    monkeypatch.setattr(skills, "_fetch_skill_source_bytes", lambda source: _BODY.encode())
    return ["https://templates.test"]


def test_templates_is_a_valid_catalog_kind():
    assert "templates" in catalog.VALID_KINDS


def test_budget_strip_handles_crlf_frontmatter():
    # A CRLF-served registry template must still have its remote budgets dropped
    # (the LF-only regex used to no-op on CRLF, persisting attacker budgets).
    crlf = (
        "---\r\ntitle: T\r\nbudget_dollars: 99.0\r\n"
        "budget_wall_seconds: 9999\r\n---\r\nBody\r\n"
    )
    stripped = templates._strip_registry_budget_frontmatter(crlf)
    assert "budget_dollars" not in stripped
    assert "budget_wall_seconds" not in stripped
    # Parse the stripped content: remote budgets fall back to defaults, but
    # other frontmatter (title) is still honored now that CRLF is normalized.
    t = templates.Template.parse(stripped, "x")
    assert t.budget_dollars is None
    assert t.budget_wall_seconds is None
    assert t.title == "T"


def test_browse(fake_registry):
    entries = templates.browse_templates(indexes=fake_registry)
    assert {e.name for e in entries} == {"trip-plan"}


def test_install_fetches_verifies_parses_writes(tmp_path, fake_registry, monkeypatch):
    monkeypatch.setattr(templates, "_verify_registry_template_signature", lambda *a, **k: True)
    t = templates.install_template_from_catalog(
        "trip-plan", indexes=fake_registry, dest=tmp_path)
    assert t.name == "trip-plan" and t.title == "Plan a trip"
    assert t.params == ["city"]
    written = tmp_path / "trip-plan.md"
    assert written.exists() and written.read_text(encoding="utf-8") == _BODY
    # the installed template renders with its param
    title, body = t.render(city="Lisbon")
    assert "Lisbon" in body


def test_install_verifies_the_pin_over_raw_bytes(tmp_path, monkeypatch):
    # A correctly pinned file with a non-UTF-8 byte must still install.
    raw = _BODY.replace("Plan a trip to", "Plan a trip (\xe9t\xe9) to").encode("latin-1")
    index = {**_INDEX, "entries": [{**_INDEX["entries"][0], "sha256": hashlib.sha256(raw).hexdigest()}]}
    monkeypatch.setattr(catalog, "_fetch_index_raw", lambda url: index)
    monkeypatch.setattr(skills, "_fetch_skill_source_bytes", lambda source: raw)
    monkeypatch.setattr(templates, "_verify_registry_template_signature", lambda *a, **k: True)
    t = templates.install_template_from_catalog(
        "trip-plan", indexes=["https://templates.test"], dest=tmp_path)
    assert t.title == "Plan a trip"


def test_install_unknown_name_raises(tmp_path, fake_registry):
    with pytest.raises(ValueError, match="no template named"):
        templates.install_template_from_catalog(
            "absent", indexes=fake_registry, dest=tmp_path)


def test_install_hash_mismatch_refuses(tmp_path, monkeypatch):
    monkeypatch.setattr(catalog, "_fetch_index_raw", lambda url: _INDEX)
    monkeypatch.setattr(skills, "_fetch_skill_source_bytes", lambda source: b"TAMPERED")
    with pytest.raises(ValueError, match="hash mismatch"):
        templates.install_template_from_catalog(
            "trip-plan", indexes=["https://t.test"], dest=tmp_path)
    assert not (tmp_path / "trip-plan.md").exists()  # nothing written on mismatch


def test_invalid_name_rejected(tmp_path, fake_registry):
    with pytest.raises(ValueError):
        templates.install_template_from_catalog(
            "../etc/passwd", indexes=fake_registry, dest=tmp_path)


def test_catalog_install_drops_remote_budget_overrides(tmp_path, monkeypatch):
    body = (
        "---\n"
        "title: Weekly cleanup\n"
        "budget_dollars: 9999\n"
        "budget_wall_seconds: 864000\n"
        "params:\n"
        "  - target\n"
        "---\n"
        "Clean up {{ target }}.\n"
    )
    index = {
        "schema_version": 1, "kind": "templates",
        "entries": [{
            "name": "weekly-cleanup", "version": "1.0.0", "summary": "Clean up.",
            "source": "https://cdn.test/weekly-cleanup.md",
            "sha256": hashlib.sha256(body.encode()).hexdigest(),
        }],
    }
    monkeypatch.setattr(catalog, "_fetch_index_raw", lambda url: index)
    monkeypatch.setattr(skills, "_fetch_skill_source_bytes", lambda source: body.encode())
    monkeypatch.setattr(templates, "_verify_registry_template_signature", lambda *a, **k: True)

    t = templates.install_template_from_catalog(
        "weekly-cleanup", indexes=["https://templates.test"], dest=tmp_path)

    assert t.budget_dollars is None
    assert t.budget_wall_seconds is None
    written = (tmp_path / "weekly-cleanup.md").read_text(encoding="utf-8")
    assert "budget_dollars" not in written
    assert "budget_wall_seconds" not in written
    assert "params:" in written


def test_catalog_install_shield_rejection_writes_nothing(tmp_path, fake_registry, monkeypatch):
    class _Verdict:
        allowed = False
        severity = "high"
        reasons = ["prompt-injection"]

    class _Shield:
        @classmethod
        def from_config(cls):
            return cls()

        def scan_input(self, text):
            assert "Plan a trip" in text
            return _Verdict()

    monkeypatch.setitem(sys.modules, "maverick_shield", SimpleNamespace(Shield=_Shield))
    monkeypatch.setattr(templates, "_verify_registry_template_signature", lambda *a, **k: True)

    with pytest.raises(ValueError, match="template rejected by Shield"):
        templates.install_template_from_catalog(
            "trip-plan", indexes=fake_registry, dest=tmp_path)
    assert not (tmp_path / "trip-plan.md").exists()


def test_catalog_install_requires_signature_when_trust_anchor_configured(
    tmp_path, fake_registry, monkeypatch
):
    monkeypatch.setattr(config, "get_skills", lambda: {
        "trusted_pubkeys": ["aa" * 32],
        "require_signed": False,
        "require_signed_catalog": False,
    })

    with pytest.raises(ValueError, match="unsigned"):
        templates.install_template_from_catalog(
            "trip-plan", indexes=fake_registry, dest=tmp_path)
    assert not (tmp_path / "trip-plan.md").exists()


def test_catalog_install_requires_trusted_signature_without_configured_key(
    tmp_path, fake_registry, monkeypatch
):
    monkeypatch.setattr(config, "get_skills", lambda: {
        "trusted_pubkeys": [], "require_signed": False, "require_signed_catalog": False,
    })
    with pytest.raises(ValueError, match="unsigned|trusted"):
        templates.install_template_from_catalog("trip-plan", indexes=fake_registry, dest=tmp_path)
    assert not (tmp_path / "trip-plan.md").exists()


# ---- CLI ----

def test_cli_browse(monkeypatch):
    entries = [catalog.CatalogEntry(name="trip-plan", version="1.0.0", kind="templates",
                                    summary="Plan a trip.", source="gh:o/r:t.md", sha256="ab")]
    monkeypatch.setattr(templates, "browse_templates", lambda: entries)
    r = CliRunner().invoke(main, ["template", "browse"])
    assert r.exit_code == 0 and "trip-plan" in r.output


def test_cli_add(monkeypatch, tmp_path):
    fake = templates.Template(name="trip-plan", title="Plan a trip", body="...",
                              path=tmp_path / "trip-plan.md")
    monkeypatch.setattr(templates, "install_template_from_catalog", lambda name: fake)
    r = CliRunner().invoke(main, ["template", "add", "trip-plan"])
    assert r.exit_code == 0 and "installed: trip-plan" in r.output
