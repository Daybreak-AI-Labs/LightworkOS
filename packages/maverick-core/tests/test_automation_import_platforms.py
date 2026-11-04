"""Definition-import translators for Make, Power Automate, Workato, UiPath.

Each translate() is a pure function over the platform's native definition JSON;
these fixtures mirror the real shapes. Materialization onto Lightwork templates
is covered generically in test_automation_import.py.
"""
from __future__ import annotations

import json

import pytest
from maverick import automation_import as ai
from maverick.automation_import import ir, make, n8n, power_automate, uipath, workato


class TestMake:
    BLUEPRINT = {
        "response": {"blueprint": {
            "id": 55,
            "name": "Lead to Slack",
            "flow": [
                {"id": 1, "module": "gateway:CustomWebHook", "mapper": {}},
                {"id": 2, "module": "slack:CreateMessage",
                 "mapper": {"channel": "#sales", "text": "hi"},
                 "metadata": {"designer": {"name": "Notify sales"}}},
                {"id": 3, "module": "builtin:BasicRouter", "routes": [
                    {"flow": [{"id": 4, "module": "hubspot:createContact", "mapper": {}}]},
                ]},
            ],
        }},
    }

    def test_blueprint_envelope_and_router_flatten(self):
        a = make.translate(self.BLUEPRINT)
        assert a.source == "make" and a.source_id == "55"
        assert a.trigger.kind == ir.TRIGGER_WEBHOOK
        # router child flattened in; trigger excluded from steps
        assert [s.name for s in a.steps] == ["Notify sales", "hubspot createContact"]
        assert a.steps[0].app == "slack" and a.steps[0].operation == "CreateMessage"
        assert a.steps[1].app == "hubspot"

    def test_bare_blueprint_accepted(self):
        a = make.translate({"name": "x", "flow": [{"id": 1, "module": "clock:Scheduler"}]})
        assert a.trigger.kind == ir.TRIGGER_SCHEDULE
        assert a.steps == []

    def test_no_flow_raises(self):
        with pytest.raises(ai.ImporterError):
            make.translate({"name": "empty"})


class TestPowerAutomate:
    FLOW = {
        "name": "shared-flow-id",
        "properties": {
            "displayName": "Notify + log",
            "definition": {
                "triggers": {"manual": {"type": "Request", "kind": "Http"}},
                "actions": {
                    "Create_row": {
                        "type": "OpenApiConnection",
                        "runAfter": {"Post_to_Teams": ["Succeeded"]},
                        "inputs": {"host": {"apiId": "/providers/.../apis/shared_excelonline",
                                            "operationId": "AddRow"}, "parameters": {}},
                    },
                    "Post_to_Teams": {
                        "type": "OpenApiConnection",
                        "runAfter": {},
                        "inputs": {"host": {"connectionName": "shared_teams",
                                            "operationId": "PostMessage"},
                                   "parameters": {"body": "hi"}},
                    },
                },
            },
        },
    }

    def test_request_trigger_and_runafter_order(self):
        a = power_automate.translate(self.FLOW)
        assert a.source == "power_automate"
        assert a.name == "Notify + log"
        assert a.trigger.kind == ir.TRIGGER_WEBHOOK
        # Post_to_Teams has empty runAfter -> comes first; Create_row depends on it.
        assert [s.name for s in a.steps] == ["Post to Teams", "Create row"]
        assert a.steps[0].app == "teams" and a.steps[0].operation == "PostMessage"
        assert a.steps[1].app == "excelonline"

    def test_recurrence_trigger_is_schedule(self):
        flow = {"definition": {
            "triggers": {"Recurrence": {"type": "Recurrence",
                                        "recurrence": {"frequency": "Day", "interval": 1}}},
            "actions": {},
        }}
        a = power_automate.translate(flow)
        assert a.trigger.kind == ir.TRIGGER_SCHEDULE
        assert "Day" in a.trigger.description

    def test_null_action_value_does_not_crash(self):
        # A hand-edited definition with a null action value must not AttributeError.
        flow = {"definition": {
            "triggers": {"m": {"type": "Request"}},
            "actions": {"Broken": None, "Ok": {"type": "Compose", "runAfter": {}}},
        }}
        a = power_automate.translate(flow)
        assert {s.name for s in a.steps} == {"Broken", "Ok"}

    def test_empty_raises(self):
        with pytest.raises(ai.ImporterError):
            power_automate.translate({"definition": {}})

    def test_live_fetch_explains(self):
        with pytest.raises(ai.ImporterError):
            power_automate.PowerAutomateImporter().fetch()


class TestWorkato:
    RECIPE = {
        "id": 99, "name": "New SFDC lead → Slack", "running": True,
        "code": json.dumps({
            "provider": "salesforce", "name": "new_object", "as": "trigger",
            "block": [
                {"provider": "slack", "name": "post_message",
                 "input": {"channel": "#sales"}, "as": "step1"},
                {"provider": "if", "name": "condition", "block": [
                    {"provider": "gmail", "name": "send_email", "input": {}, "as": "step2"},
                ]},
            ],
        }),
    }

    def test_code_string_parsed_and_block_flattened(self):
        a = workato.translate(self.RECIPE)
        assert a.source == "workato" and a.source_id == "99"
        assert a.trigger.kind == ir.TRIGGER_EVENT
        assert a.trigger.app == "salesforce"
        names_apps = [(s.app, s.operation) for s in a.steps]
        # the if-step itself + its nested gmail step both appear, in order
        assert ("slack", "post_message") in names_apps
        assert ("gmail", "send_email") in names_apps

    def test_clock_trigger_is_schedule(self):
        r = {"id": 1, "name": "cron", "code": json.dumps(
            {"provider": "clock", "name": "scheduled_event", "block": []})}
        a = workato.translate(r)
        assert a.trigger.kind == ir.TRIGGER_SCHEDULE

    def test_bad_code_raises(self):
        with pytest.raises(ai.ImporterError):
            workato.translate({"id": 1, "name": "x", "code": "{not json"})
        with pytest.raises(ai.ImporterError):
            workato.translate({"id": 1, "name": "x"})


class TestUiPath:
    def test_release_is_one_step_manual(self):
        rel = {"Key": "abc", "Name": "InvoiceBot", "ProcessKey": "InvoiceBot",
               "ProcessVersion": "1.0.2"}
        a = uipath.translate(rel)
        assert a.source == "uipath" and a.name == "InvoiceBot"
        assert a.trigger.kind == ir.TRIGGER_MANUAL
        assert len(a.steps) == 1
        assert a.steps[0].app == "uipath" and a.steps[0].operation == "start_job"
        assert a.steps[0].params["process"] == "InvoiceBot"

    def test_schedule_captures_quartz_without_auto_cron(self):
        sched = {"Id": 7, "Name": "Nightly invoices", "ReleaseName": "InvoiceBot",
                 "StartProcessCron": "0 0 2 * * ?", "Enabled": True}
        a = uipath.translate(sched)
        assert a.trigger.kind == ir.TRIGGER_SCHEDULE
        assert a.trigger.cron is None  # Quartz != 5-field; not auto-scheduled
        assert a.trigger.config["quartz_cron"] == "0 0 2 * * ?"
        assert a.steps[0].params["process"] == "InvoiceBot"

    def test_bad_input_raises(self):
        with pytest.raises(ai.ImporterError):
            uipath.translate([1, 2, 3])  # type: ignore[arg-type]


class TestN8nSchedule:
    """The modern scheduleTrigger encodes schedules as interval RULES, not a raw
    cron; we should still recover a 5-field cron so a schedule can be armed."""

    def _wf(self, interval: dict) -> dict:
        return {
            "id": "s", "name": "Digest", "active": True,
            "nodes": [
                {"name": "Every", "type": "n8n-nodes-base.scheduleTrigger",
                 "parameters": {"rule": {"interval": [interval]}}},
                {"name": "Send", "type": "n8n-nodes-base.emailSend",
                 "parameters": {"operation": "send"}},
            ],
            "connections": {"Every": {"main": [[{"node": "Send"}]]}},
        }

    def test_explicit_cron_still_wins(self):
        a = n8n.translate(self._wf({"field": "cronExpression", "expression": "0 9 * * 1"}))
        assert a.trigger.kind == ir.TRIGGER_SCHEDULE and a.trigger.cron == "0 9 * * 1"

    @pytest.mark.parametrize("interval,expected", [
        ({"field": "minutes", "minutesInterval": 15}, "*/15 * * * *"),
        ({"field": "hours", "hoursInterval": 2, "triggerAtMinute": 30}, "30 */2 * * *"),
        ({"field": "hours", "hoursInterval": 1}, "0 * * * *"),
        ({"field": "days", "triggerAtHour": 9, "triggerAtMinute": 5}, "5 9 * * *"),
        ({"field": "weeks", "triggerAtDay": [1, 3], "triggerAtHour": 9}, "0 9 * * 1,3"),
        ({"field": "months", "triggerAtDayOfMonth": 1, "triggerAtHour": 8}, "0 8 1 * *"),
    ])
    def test_interval_rules_recover_cron(self, interval, expected):
        a = n8n.translate(self._wf(interval))
        assert a.trigger.cron == expected

    def test_subminute_leaves_no_cron(self):
        a = n8n.translate(self._wf({"field": "seconds", "secondsInterval": 30}))
        assert a.trigger.kind == ir.TRIGGER_SCHEDULE and a.trigger.cron is None


class TestRegistry:
    def test_all_definition_importers_registered(self):
        for s in ("make", "power_automate", "uipath", "workato"):
            assert s in ai.available_sources()
        for s in ("make", "uipath", "workato"):
            assert ai.get_importer(s).can_fetch_definitions is True
        # Power Automate definitions import from an exported file only: live
        # enumeration is environment-specific, so it does not claim to fetch.
        assert ai.get_importer("power_automate").can_fetch_definitions is False
        with pytest.raises(ai.ImporterError, match="--from-file"):
            ai.get_importer("power_automate").fetch()

    @pytest.mark.parametrize("source,raw", [
        ("make", TestMake.BLUEPRINT),
        ("power_automate", TestPowerAutomate.FLOW),
        ("workato", TestWorkato.RECIPE),
        ("uipath", {"Name": "Bot", "ProcessKey": "Bot"}),
    ])
    def test_materialize_round_trip(self, source, raw, tmp_path, monkeypatch):
        import maverick.templates as t
        monkeypatch.setattr(t, "USER_TEMPLATES", tmp_path / "templates")
        a = ai.get_importer(source).translate(raw)
        res = ai.materialize(a)
        assert res.created_template is True
        from maverick.templates import load_template
        assert load_template(res.template_name) is not None
