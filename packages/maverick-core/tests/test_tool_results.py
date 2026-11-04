"""Shared semantic contract for string-based tool results."""
import copy
import pickle

from maverick.tool_results import (
    ToolOutcome,
    ToolResultState,
    classify_tool_result,
    tool_result_failed,
)


def test_typed_outcome_keeps_explicit_state_separate_from_content():
    result = ToolOutcome(ToolResultState.SUCCEEDED, "ERROR is part of the document")
    assert ToolOutcome.from_legacy(result) is result
    assert result.state is ToolResultState.SUCCEEDED
    assert result.content == "ERROR is part of the document"
    assert classify_tool_result(result) is ToolResultState.SUCCEEDED
    assert not tool_result_failed(result)


def test_typed_unknown_cannot_be_mistaken_for_success():
    result = ToolOutcome(ToolResultState.INDETERMINATE, "receipt missing")
    assert classify_tool_result(result) is ToolResultState.INDETERMINATE
    assert tool_result_failed(result)


def test_typed_text_state_survives_copy_and_pickle():
    result = ToolOutcome(ToolResultState.SUCCEEDED, "ERROR is content").as_text()
    for restored in (copy.deepcopy(result), pickle.loads(pickle.dumps(result))):
        assert restored == result
        assert classify_tool_result(restored) is ToolResultState.SUCCEEDED


def test_external_write_reconciliation_uses_explicit_result_state():
    from maverick.grc_sync import _response_is_uncertain

    success = ToolOutcome(ToolResultState.SUCCEEDED, "INDETERMINATE: a document title")
    missing_receipt = ToolOutcome(ToolResultState.INDETERMINATE, "receipt missing")
    assert not _response_is_uncertain(success, op="post")
    assert _response_is_uncertain(missing_receipt, op="post")
    assert _response_is_uncertain("INDETERMINATE: receipt missing", op="post")


def test_connector_receipt_state_survives_metadata_removal():
    from maverick.connector_attempts import ConnectorAttempt, ConnectorResult, public_result

    confirmed = ConnectorResult("ERROR is customer data", ConnectorAttempt(
        request_id="read", attempt=1, operation="safe_read", status_code=200,
    ))
    lost = ConnectorResult("ordinary preview", ConnectorAttempt(
        request_id="write", attempt=1, operation="mutation", outcome_unknown=True,
    ))
    for result in (confirmed, public_result(confirmed)):
        assert classify_tool_result(result) is ToolResultState.SUCCEEDED
    for result in (lost, public_result(lost)):
        assert classify_tool_result(result) is ToolResultState.INDETERMINATE

    # The textual prefix alone must not erase the state marker that audit
    # consumers use to distinguish a lost response from a known failure.
    prefixed = ConnectorResult("INDETERMINATE: acknowledgment lost", ConnectorAttempt(
        request_id="write", attempt=1, operation="mutation", outcome_unknown=True,
    ))
    assert public_result(prefixed).tool_execution_unknown is True


def test_legacy_outcome_preserves_security_frame_and_state():
    value = '<tool_output trust="untrusted">\nINDETERMINATE: receipt lost\n</tool_output>'
    result = ToolOutcome.from_legacy(value)
    assert result.state is ToolResultState.INDETERMINATE
    assert result.content == value


def test_classifies_reserved_result_states():
    assert classify_tool_result("created") is ToolResultState.SUCCEEDED
    assert classify_tool_result("ERROR: timeout") is ToolResultState.FAILED
    assert classify_tool_result("REFUSED (governed): approval missing") is ToolResultState.REFUSED
    assert classify_tool_result("⚠ BLOCKED by hook") is ToolResultState.REFUSED
    assert classify_tool_result("BLOCKED by Shield") is ToolResultState.REFUSED
    assert classify_tool_result("DRY RUN: would POST /accounts") is ToolResultState.PREVIEW
    assert classify_tool_result("INDETERMINATE: may have committed") is ToolResultState.INDETERMINATE


def test_classification_looks_through_security_frame():
    framed = '<tool_output trust="untrusted">\nINDETERMINATE: receipt lost\n</tool_output>'
    assert classify_tool_result(framed) is ToolResultState.INDETERMINATE
    assert tool_result_failed(framed) is True


def test_natural_language_is_not_misclassified():
    assert tool_result_failed("The customer refused the offer") is False


def test_workflow_stops_on_preview_refusal_or_indeterminate_result():
    from maverick.workflow import Step, Workflow

    class Registry:
        def __init__(self, result):
            self.result = result
            self.calls = []

        async def run(self, name, args):
            self.calls.append(name)
            return self.result

    for reserved in (
        "DRY RUN: would write without confirm",
        "REFUSED (governed): approval missing",
        "INDETERMINATE (governed): write may have committed",
    ):
        registry = Registry(reserved)
        result = Workflow([
            Step("write", "connector"),
            Step("notify", "notify", depends_on=["write"]),
        ]).run(registry)
        assert result.failed is True
        assert registry.calls == ["connector"]
        assert result.steps[0].error == reserved
