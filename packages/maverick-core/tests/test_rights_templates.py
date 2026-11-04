"""Rights-request email templates: defaults, placeholders, versions."""
from __future__ import annotations

import pytest
from maverick import rights_templates as rt
from maverick.rights_deadlines import FAMILIES


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_ENCRYPT_AT_REST", "0")
    from maverick import config
    config.reset_config_cache()


def test_every_family_ships_every_kind_with_known_placeholders_only():
    for family in FAMILIES:
        for kind in rt.KINDS:
            tpl = rt.get_template(family, kind)
            assert tpl["source"] == "default" and tpl["version"] == 0
            used = rt.placeholders_in(tpl["subject"]) | rt.placeholders_in(tpl["body"])
            assert used <= set(rt.PLACEHOLDERS), (family, kind, used)
            assert "{reference}" in tpl["subject"] or "{reference}" in tpl["body"]
    assert len(rt.list_templates()) == len(FAMILIES) * len(rt.KINDS)


def test_render_fills_placeholders_and_blanks_missing_ones():
    tpl = rt.get_template("gdpr", "extension")
    out = rt.render(tpl, {"reference": "DSAR-1", "extended_until_date": "2027-01-09",
                          "extension_reason": "many records", "organisation": "Acme"})
    assert "DSAR-1" in out["subject"]
    assert "2027-01-09" in out["body"] and "many records" in out["body"]
    assert "{" not in out["body"]  # the unknown ones are blank, not literal


def test_save_versions_and_refuses_unknown_placeholders():
    with pytest.raises(rt.RightsTemplateError, match="unknown placeholder"):
        rt.save_template("us_state", "refusal", subject="Hi {reference}",
                         body="Because {lawful_bases}", actor="admin")
    with pytest.raises(rt.RightsTemplateError):
        rt.save_template("us_state", "refusal", subject="a\nb", body="x", actor="admin")
    with pytest.raises(rt.RightsTemplateError):
        rt.save_template("klingon", "refusal", subject="a", body="x", actor="admin")
    v1 = rt.save_template("us_state", "refusal", subject="Decision {reference}",
                          body="Reason: {lawful_basis}", actor="admin")
    assert v1["version"] == 1 and v1["source"] == "custom"
    v2 = rt.save_template("us_state", "refusal", subject="Decision {reference}",
                          body="Reason: {lawful_basis}. Appeal by reply.", actor="admin2")
    assert v2["version"] == 2 and v2["saved_by"] == "admin2"
    assert [h["version"] for h in rt.history("us_state", "refusal")] == [1, 2]
    assert rt.get_template("us_state", "refusal")["body"].endswith("reply.")
    # Other kinds and families are untouched.
    assert rt.get_template("us_state", "extension")["source"] == "default"
    assert rt.get_template("gdpr", "refusal")["source"] == "default"
    back = rt.reset_template("us_state", "refusal", actor="admin")
    assert back["version"] == 3
    assert back["body"] == rt.DEFAULTS["us_state"]["refusal"]["body"]
