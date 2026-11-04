"""Connect-and-trigger importers (Zapier, Notion) + the shared manual translator.

These platforms don't expose automation definitions over an API, so fetch()
raises with connect guidance and translate() lowers a hand-authored IR-shaped
description into a Lightwork template.
"""
from __future__ import annotations

import pytest
from maverick import automation_import as ai
from maverick.automation_import import ir, manual

DESC = {
    "name": "New Zapier lead → CRM + Slack",
    "trigger": {"kind": "webhook", "description": "Zap posts a new lead"},
    "steps": [
        {"name": "Add to CRM", "app": "hubspot", "operation": "create_contact",
         "description": "create the contact from the lead payload",
         "params": {"source": "zapier"}},
        {"name": "Notify", "app": "slack", "action": "post_message"},
    ],
}


class TestManualTranslate:
    def test_full_description(self):
        a = manual.translate(DESC, source="zapier")
        assert a.source == "zapier"
        assert a.trigger.kind == ir.TRIGGER_WEBHOOK
        assert [s.name for s in a.steps] == ["Add to CRM", "Notify"]
        assert a.steps[0].app == "hubspot" and a.steps[0].operation == "create_contact"
        # "action" alias maps to operation
        assert a.steps[1].operation == "post_message"

    def test_defaults_to_webhook_trigger(self):
        a = manual.translate({"name": "x", "steps": []}, source="notion")
        assert a.trigger.kind == ir.TRIGGER_WEBHOOK

    def test_schedule_trigger_with_cron(self):
        a = manual.translate(
            {"name": "x", "trigger": {"kind": "schedule", "cron": "0 8 * * *"}, "steps": []},
            source="notion",
        )
        assert a.trigger.kind == ir.TRIGGER_SCHEDULE and a.trigger.cron == "0 8 * * *"

    def test_missing_name_or_steps_raises(self):
        with pytest.raises(ai.ImporterError):
            manual.translate({"steps": []}, source="zapier")
        with pytest.raises(ai.ImporterError):
            manual.translate({"name": "x"}, source="zapier")


class TestConnectImporters:
    @pytest.mark.parametrize("source", ["zapier", "notion"])
    def test_registered_as_connect_only(self, source):
        imp = ai.get_importer(source)
        assert imp.can_fetch_definitions is False

    @pytest.mark.parametrize("source", ["zapier", "notion"])
    def test_fetch_explains_the_limitation(self, source):
        imp = ai.get_importer(source)
        with pytest.raises(ai.ImporterError) as ei:
            imp.fetch()
        assert "inbound webhook" in str(ei.value).lower()

    def test_zapier_translate_and_materialize(self, tmp_path, monkeypatch):
        import maverick.templates as t
        monkeypatch.setattr(t, "USER_TEMPLATES", tmp_path / "templates")
        a = ai.get_importer("zapier").translate(DESC)
        res = ai.materialize(a)
        assert res.created_template is True
        # webhook trigger -> suggested webhook wiring
        assert res.suggested_trigger["kind"] == "webhook"
        from maverick.templates import load_template
        _, body = load_template(res.template_name).render()
        assert "Add to CRM" in body
