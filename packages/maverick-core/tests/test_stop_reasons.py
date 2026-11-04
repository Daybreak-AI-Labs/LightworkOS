"""One mapper turns a run's internal stop text into plain words, the right
next step and a link; raw exception text is admin-only technical detail."""
from __future__ import annotations

import pytest
from maverick.stop_reasons import RAW_TEXT_LIMIT, exception_stop_text, explain_stop

RAW_TENANT = ("over quota: tenant policy unavailable or inactive: "
              "tenant is suspended or unknown: 'owner-browser'")


def test_tenant_suspended_or_unknown_maps_to_workspaces():
    stop = explain_stop(RAW_TENANT)
    assert stop.kind == "workspace_paused"
    assert stop.message == "This workspace is paused or hasn't been set up. Open Workspaces to resume it."
    assert stop.link == "/workspaces"
    assert "owner-browser" not in stop.message + stop.action
    assert "tenant" not in (stop.message + stop.action).lower()
    assert stop.technical == RAW_TENANT


@pytest.mark.parametrize("raw", [
    "over quota: principal 'user:local' is over its daily spend quota ($10.00 >= $5.00)",
    "over quota: tenant 'acme' is over its daily spend cap ($12.00 >= $5.00)",
    "over quota: Your spending limit of $5.00 per day has been reached ($6.00 spent today). "
    "An administrator can change it in Admin > Spending limits.",
    "Paused: the organization spending allowance cannot admit the next call.\nDetail: x",
    "Stopped: budget exhausted ($1.00 of $1.00 cap). Raise the cap and resume: maverick resume 3",
])
def test_real_spending_failures_get_the_spending_limit_advice(raw):
    stop = explain_stop(raw)
    assert stop.kind == "spending_limit"
    assert stop.link == "/spending-limits"
    assert "user:local" not in stop.message and "'acme'" not in stop.message


def test_workspace_failure_is_not_mistaken_for_a_spending_limit():
    # The raw text starts with "over quota:" but the cause is the workspace.
    assert explain_stop(RAW_TENANT).kind != "spending_limit"


def test_unpriced_model_points_to_known_price_setup_without_exposing_the_id():
    raw = ("unpriced model: no verified USD price for model "
           "'openai_compatible:private-gateway-id'; refusing to bill at an estimate")
    stop = explain_stop(raw)
    assert stop.kind == "unpriced_model"
    assert "needs a price" in stop.message
    assert "choose a priced model" in stop.action
    assert stop.link == "/settings#settings-model-prices"
    assert "private-gateway-id" not in stop.message + stop.action
    assert "strict_pricing=false" not in stop.message + stop.action
    assert stop.technical == raw


def test_missing_specialist_action_explains_setup_without_exposing_internal_names():
    raw = ("domain 'legal_research' agent build failed: Domain 'legal_research' "
           "cannot deploy: required workflow tools unavailable: web_search. "
           "Configure/enable the named adapter or MCP connection, or revise the workflow "
           "to read an operator-approved workspace export with read_file. No model work has started.")
    stop = explain_stop(raw)
    assert stop.kind == "specialist_needs_web_search"
    assert "Web search" in stop.message
    assert "No work was started" in stop.message
    assert stop.link == "/settings/all?id=capabilities.web_search"
    assert "legal_research" not in stop.message + stop.action
    assert "MCP" not in stop.message + stop.action
    assert stop.technical == raw


AI_PROVIDER_KEYS = "/settings?focus=ai-provider#settings-integrations"


@pytest.mark.parametrize("raw", [
    "provider not ready: ANTHROPIC_API_KEY is not set",
    "httpx.ConnectError: [Errno 111] connection refused",
    "The selected AI model route is incomplete (anthropic: api_key)",
])
def test_provider_problems_link_to_the_ai_provider_keys(raw):
    # AI keys live in Settings > Connections > Provider keys, not on the
    # Connections page (connected accounts), which may even be turned off.
    stop = explain_stop(raw)
    assert stop.kind == "provider_not_ready"
    assert stop.link == AI_PROVIDER_KEYS
    assert "ConnectError" not in stop.message


@pytest.mark.parametrize("raw", [
    "provider_error:authentication", "provider_error:model_not_found",
    "provider_error:connection", "provider_error:configuration",
    "provider_error:rate_limit", "provider_error:unavailable",
    "provider not ready: OPENAI_API_KEY is not set",
])
def test_every_ai_connection_stop_opens_the_provider_keys_with_the_row_focused(raw):
    stop = explain_stop(raw)
    assert stop.link == AI_PROVIDER_KEYS
    assert stop.link_label in {"Open AI provider keys", "Connect an AI service", "Check AI connection"}
    assert "/connections" not in stop.link


@pytest.mark.parametrize(("missing", "kind"), [
    ("ap_read_invoice, ap_read_po, ap_read_receipt, gl_read_subledger, stage_payment_batch",
     "specialist_needs_connection"),
    ("web_search", "specialist_needs_web_search"),
])
def test_a_specialist_that_cannot_start_says_why_and_what_is_safe(missing, kind):
    raw = (f"domain 'finance_ap' agent build failed: Domain 'finance_ap' cannot deploy: "
           f"required workflow tools unavailable: {missing}. Configure/enable the named "
           "adapter or MCP connection, or revise the workflow to read an operator-approved "
           "workspace export with read_file. No model work has started.. Refusing to run "
           "without the requested domain capability envelope.")
    stop = explain_stop(raw)
    assert stop.kind == kind
    assert stop.message != "Something went wrong inside Lightwork."
    assert "No work was started" in stop.message + stop.action
    for word in ("finance_ap", "read_file", "MCP", "envelope", "ap_read_invoice", "web_search"):
        assert word not in stop.message + stop.action, word
    assert stop.link and stop.link_label
    assert stop.technical == raw


@pytest.mark.parametrize("raw", [
    "PermissionError: insufficient role for this action",
    "BLOCKED: goal is bound to a different execution principal",
    "permission denied: user:bob may not use suite finance",
])
def test_permission_denied_says_who_can_grant_it(raw):
    stop = explain_stop(raw)
    assert stop.kind == "permission_denied"
    assert "administrator" in stop.action.lower()
    assert stop.link == "/users"
    assert "user:bob" not in stop.message + stop.action


def test_halt_and_internal_errors_are_plain():
    assert explain_stop("halted").kind == "halted"
    stop = explain_stop("internal error")
    assert stop.kind == "internal_error"
    assert "Traceback" not in stop.message
    stop = explain_stop("Traceback (most recent call last):\n  File \"/x.py\"\nKeyError: 'q'")
    assert stop.kind == "internal_error"
    assert "KeyError" not in stop.message


def test_recovered_crash_explains_saved_work_without_exposing_partial_result():
    raw = "Customer-private partial answer [process restarted mid-run]"
    stop = explain_stop(raw)
    assert stop.kind == "process_restart"
    assert "restarted" in stop.message.lower()
    assert "Review the saved work" in stop.action
    assert "Customer-private" not in stop.message + stop.action
    assert stop.as_dict()["kind"] == "process_restart"


def test_plain_kernel_sentences_pass_through_and_technical_ones_do_not():
    plain = ("Paused: the review checkpoint stopped this run at step 3 because "
             "the reviewer did not approve continuing.")
    assert explain_stop(plain).message == plain
    technical = "RuntimeError: /home/user/.maverick/tenants/acme/world.db is locked"
    stop = explain_stop(technical)
    assert stop.kind == "internal_error"
    assert "/home/user" not in stop.message and "RuntimeError" not in stop.message
    assert stop.technical == technical


@pytest.mark.parametrize("raw", [
    "Stopped: the assistant ran into an error and couldn't finish.\nDetail: private failure\n"
    "You can try again with: maverick resume 7\n[100 input tokens, $0.03 cap]",
    "Paused: waiting for you to answer 1 question.\nAnswer with: maverick answer 3",
    "Paused: the assistant said it needs more information, but no question was filed. "
    "You can resume with `maverick resume 7`.",
])
def test_stopped_task_never_shows_terminal_instructions_or_usage_dump(raw):
    stop = explain_stop(raw)
    assert stop.message and stop.action
    assert "maverick" not in stop.message + stop.action
    assert "input tokens" not in stop.message + stop.action
    assert "private failure" not in stop.message + stop.action


def test_prepared_pilot_has_a_distinct_start_state():
    stop = explain_stop("Prepared for a workflow pilot. Start this task after the pilot plan is frozen.")
    assert stop.kind == "pilot_prepared"
    assert stop.link == "/outcome-pilots"


def test_empty_result_is_a_generic_stop_with_no_technical_text():
    stop = explain_stop(None)
    assert stop.kind == "other"
    assert stop.message and stop.technical == ""
    assert stop.as_dict() == {"kind": "other", "message": stop.message, "action": stop.action,
                              "link": None, "link_label": None}
    assert "technical" in stop.as_dict(include_technical=True)


def test_technical_text_is_bounded():
    stop = explain_stop("x" * (RAW_TEXT_LIMIT * 3))
    assert len(stop.technical) <= RAW_TEXT_LIMIT


@pytest.mark.parametrize(("name", "status", "kind"), [
    ("AuthenticationError", 401, "provider_authentication"),
    ("RateLimitError", 429, "provider_rate_limit"),
    ("InternalServerError", 500, "provider_unavailable"),
    ("NotFoundError", 404, "provider_model_not_found"),
    ("APIConnectionError", None, "provider_connection"),
])
def test_sdk_failure_has_a_specific_safe_customer_remedy(name, status, kind):
    error_type = type(name, (Exception,), {"__module__": "openai"})
    error = error_type("secret-provider-response user:alice")
    error.status_code = status
    saved = exception_stop_text(error)
    stop = explain_stop(saved)
    assert stop.kind == kind
    assert "secret-provider-response" not in saved + stop.message + stop.action
    assert stop.action


def test_legacy_provider_500_is_not_described_as_a_lightwork_internal_error():
    stop = explain_stop("internal error: InternalServerError: Error code: 500")
    assert stop.kind == "provider_unavailable"
    assert "Try again" in stop.action


def test_non_provider_exception_stays_generic_without_its_text():
    assert exception_stop_text(RuntimeError("private path C:\\keys\\ai")) == "internal error"


def test_failed_run_finalization_keeps_provider_cause_and_safe_work_log():
    from types import SimpleNamespace

    from maverick.orchestrator import _RunLifecycle

    class World:
        def __init__(self):
            self.goal = SimpleNamespace(status="active")
            self.events = []

        def get_goal(self, _goal_id):
            return self.goal

        def set_goal_status(self, _goal_id, status, result=None):
            self.goal.status = status
            self.goal.result = result

        def append_event(self, _goal_id, _agent, kind, content):
            self.events.append((kind, content))

    world = World()
    lifecycle = _RunLifecycle(world, 7, None)
    lifecycle.started = True
    error_type = type("InternalServerError", (Exception,), {"__module__": "openai"})
    error = error_type("secret provider payload")
    error.status_code = 500
    lifecycle.finish(error)
    assert world.goal.status == "failed"
    assert explain_stop(world.goal.result).kind == "provider_unavailable"
    assert world.events == [("error", "The AI service is not responding.")]
    assert "secret provider payload" not in lifecycle.summary + world.goal.result


def test_a_paused_ai_service_reads_as_paused_not_as_a_lightwork_fault():
    from maverick.circuit_breaker import CircuitOpen

    saved = exception_stop_text(CircuitOpen("llm:anthropic breaker OPEN; skipping dispatch"))
    assert saved == "provider_error:paused"
    stop = explain_stop(saved)
    assert stop.kind == "provider_paused"
    assert "paused after repeated errors" in stop.message and "kept" in stop.message
    assert "checks again" in stop.action
    assert "anthropic" not in stop.message + stop.action
