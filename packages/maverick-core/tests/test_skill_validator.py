"""`maverick skill validate` — pre-publish SKILL.md linter."""
from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner
from maverick.cli import main
from maverick.skills import validate_skill_file

_VALID = """---
name: summarize-url
triggers:
  - summarize a url
  - tldr this page
tools_needed:
  - http_fetch
---

# What this does

Fetch a URL and summarize it in a few sentences.

# Steps

1. Call http_fetch on the url.
2. Summarize the returned text.
"""


def _write(tmp_path: Path, text: str, name: str = "skill.md") -> Path:
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def test_valid_skill_passes(tmp_path):
    r = validate_skill_file(_write(tmp_path, _VALID))
    assert r.ok and r.errors == []


def test_missing_frontmatter_fails(tmp_path):
    r = validate_skill_file(_write(tmp_path, "# just a doc\nno frontmatter here"))
    assert not r.ok and any("frontmatter" in e for e in r.errors)


def test_missing_name_fails(tmp_path):
    text = _VALID.replace("name: summarize-url\n", "")
    r = validate_skill_file(_write(tmp_path, text))
    assert not r.ok and any("name" in e for e in r.errors)


def test_non_kebab_name_fails(tmp_path):
    text = _VALID.replace("summarize-url", "Summarize_URL")
    r = validate_skill_file(_write(tmp_path, text))
    assert not r.ok and any("kebab" in e for e in r.errors)


def test_blank_name_fails_without_crashing(tmp_path):
    text = _VALID.replace("name: summarize-url", "name:")
    r = validate_skill_file(_write(tmp_path, text))
    assert not r.ok and any("kebab" in e for e in r.errors)


def test_list_name_fails_without_crashing(tmp_path):
    text = _VALID.replace("name: summarize-url", "name:\n  - summarize-url")
    r = validate_skill_file(_write(tmp_path, text))
    assert not r.ok and any("kebab" in e for e in r.errors)


def test_invalid_utf8_fails_without_crashing(tmp_path):
    p = tmp_path / "skill.md"
    p.write_bytes(b"---\nname: invalid-utf8\ntriggers:\n  - do x\n---\n\xff")
    r = validate_skill_file(p)
    assert not r.ok and any("cannot read" in e for e in r.errors)


def test_no_triggers_fails(tmp_path):
    text = "---\nname: x-y\ntools_needed:\n  - http_fetch\n---\n\n# Steps\n\n1. do a thing well\n"
    r = validate_skill_file(_write(tmp_path, text))
    assert not r.ok and any("trigger" in e for e in r.errors)


def test_short_body_fails(tmp_path):
    text = "---\nname: x-y\ntriggers:\n  - do x\n---\n\nshort\n"
    r = validate_skill_file(_write(tmp_path, text))
    assert not r.ok and any("too short" in e for e in r.errors)


def test_hardcoded_secret_fails(tmp_path):
    # The canonical AWS example access key id — Lightwork's own secret detector
    # must flag it. It's AWS's published docs example (not a real credential);
    # the pragma keeps the repo's detect-secrets CI gate from treating this
    # test fixture as a newly committed secret.
    text = _VALID + "\nexport AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"  # pragma: allowlist secret
    r = validate_skill_file(_write(tmp_path, text))
    assert not r.ok and any("secret" in e for e in r.errors)


def test_no_tools_is_warning_not_error(tmp_path):
    text = "---\nname: x-y\ntriggers:\n  - do x\n---\n\n# Steps\n\n1. do the thing thoroughly and well\n"
    r = validate_skill_file(_write(tmp_path, text))
    assert r.ok and any("tools_needed" in w for w in r.warnings)


def test_missing_file(tmp_path):
    r = validate_skill_file(tmp_path / "nope.md")
    assert not r.ok and "not found" in r.errors[0]


# ---- CLI ----

def test_cli_validate_ok(tmp_path):
    p = _write(tmp_path, _VALID)
    res = CliRunner().invoke(main, ["skill", "validate", str(p)])
    assert res.exit_code == 0 and "valid for publishing" in res.output


def test_cli_validate_blank_name_reports_invalid(tmp_path):
    p = _write(tmp_path, _VALID.replace("name: summarize-url", "name:"))
    res = CliRunner().invoke(main, ["skill", "validate", str(p)])
    assert res.exit_code == 1 and "INVALID" in res.output and "Traceback" not in res.output


def test_cli_validate_invalid_utf8_reports_invalid(tmp_path):
    p = tmp_path / "skill.md"
    p.write_bytes(b"---\nname: invalid-utf8\ntriggers:\n  - do x\n---\n\xff")
    res = CliRunner().invoke(main, ["skill", "validate", str(p)])
    assert res.exit_code == 1 and "cannot read" in res.output and "Traceback" not in res.output


def test_cli_validate_invalid_exits_nonzero(tmp_path):
    p = _write(tmp_path, "no frontmatter")
    res = CliRunner().invoke(main, ["skill", "validate", str(p)])
    assert res.exit_code == 1 and "INVALID" in res.output
