"""Typed input defaults and validation; deliberately no provider calls."""
import pytest
from maverick.template_parameters import normalize_schema, resolve_parameters
from maverick.templates import Template, load_template, save_user_template


def schema():
    return normalize_schema({"version": 1, "fields": {
        "format": {"type": "enum", "required": False, "choices": ["Brief", "Full"], "default": "Brief"},
        "due": {"type": "date", "required": True},
    }}, ["format", "due"])


def test_optional_choice_default_and_required_date_resolve():
    assert resolve_parameters(["format", "due"], schema(), {"due": "2026-10-01"}) == {"format": "Brief", "due": "2026-10-01"}


@pytest.mark.parametrize("values", [{"due": "2026-02-30"}, {"due": "2026-10-01", "format": "Invented"}, {}])
def test_invalid_inputs_refuse_before_render(values):
    with pytest.raises(ValueError):
        resolve_parameters(["format", "due"], schema(), values)


def test_legacy_template_behavior_is_unchanged():
    template = Template.parse("---\nparams:\n  - topic\n---\nDiscuss {{topic}}", "legacy")
    assert template.render(topic="") == ("legacy", "Discuss ")
    with pytest.raises(ValueError):
        template.render()


def test_typed_definition_round_trips_without_losing_default(tmp_path, monkeypatch):
    monkeypatch.setattr("maverick.templates.USER_TEMPLATES", tmp_path)
    save_user_template("typed", title="Report", body="{{format}} due {{due}}", params=["format", "due"], parameter_schema=schema())
    saved = load_template("typed")
    assert saved.parameter_schema == schema()
    assert saved.render(due="2026-10-01")[1] == "Brief due 2026-10-01"


def test_hidden_field_is_not_required_or_substituted():
    definitions = normalize_schema({"version": 1, "fields": {"detail": {
        "type": "text", "required": True, "show_when": {"field": "mode", "value": "Full"}
    }}}, ["mode", "detail"])
    assert resolve_parameters(["mode", "detail"], definitions, {"mode": "Brief", "detail": "private"})["detail"] == ""
