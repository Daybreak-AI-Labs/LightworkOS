"""Typed tool outcomes remain safe at flow recipe and evidence boundaries."""
import pytest
from maverick.flow.action_episodes import _result_object
from maverick.flow.action_recipe import parse_result
from maverick.tool_results import ToolResultState, ToolResultText


def test_successful_typed_json_can_be_captured_and_used_by_recipes():
    result = ToolResultText('{"value": 3}', ToolResultState.SUCCEEDED)
    assert _result_object(result) == {"value": 3}
    assert parse_result(result) == {"value": 3}


@pytest.mark.parametrize("state", [ToolResultState.FAILED, ToolResultState.INDETERMINATE,
                                    ToolResultState.REFUSED, ToolResultState.PREVIEW])
def test_non_success_typed_json_cannot_become_evidence_or_recipe_data(state):
    result = ToolResultText('{"value": 3}', state)
    with pytest.raises(ValueError):
        _result_object(result)
    with pytest.raises(ValueError):
        parse_result(result)


def test_typed_json_still_rejects_duplicate_keys():
    result = ToolResultText('{"value": 1, "value": 2}', ToolResultState.SUCCEEDED)
    with pytest.raises(ValueError, match="duplicate"):
        _result_object(result)
    with pytest.raises(ValueError, match="duplicate"):
        parse_result(result)
