"""Independent native guard for policy changes during decision receipt I/O."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from maverick import audit, config

_spec = importlib.util.spec_from_file_location(
    "choice_runtime_review_fixture", Path(__file__).with_name("test_flow_action_choices_runtime.py"))
_fixture = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_fixture)
native = _fixture.native
_OPEN, _execute = _fixture._OPEN, _fixture._execute


@pytest.mark.parametrize("feature", ["action_recipes", "action_recipe_transforms", "action_recipe_choices"])
def test_terminal_receipt_cannot_carry_withdrawn_feature_permission_into_dispatch(native, monkeypatch, feature):
    original_record, original_flags = audit.record, config.get_flows
    revoked = []

    def record(kind, **payload):
        result = original_record(kind, **payload)
        if (kind == audit.EventKind.FLOW_ACTION_RECIPE_DECISION
                and payload.get("status") == "selected" and payload.get("step_index") == 1):
            assert result is True
            revoked.append(feature)
            monkeypatch.setattr(config, "get_flows", lambda: {**original_flags(), feature: False})
        return result

    monkeypatch.setattr(audit, "record", record)
    run = _execute(native)
    assert revoked == [feature]
    assert run.status == "indeterminate", run.error
    assert "feature_disabled" in run.error
    assert native[1] == [(_OPEN, {"amount": 3})]
    assert run.data["_recipe_step_0"] == {"ticket": 23}
    assert "_recipe_step_1" not in run.data
    # An already completed prefix remains quarantined under the same run ID.
    again = _execute(native)
    assert again.status == "indeterminate"
    assert native[1] == [(_OPEN, {"amount": 3})]
    events = [event for event in audit.iter_events(all_days=True, strict=True, verify=True)
              if event["kind"] == audit.EventKind.FLOW_ACTION_RECIPE_DECISION]
    assert not any(event.get("step_index") == 1 and event.get("status") == "completed" for event in events)
    assert any(event.get("step_index") == 1 and event.get("status") == "blocked"
               and event.get("reason") == "feature_disabled" for event in events)
