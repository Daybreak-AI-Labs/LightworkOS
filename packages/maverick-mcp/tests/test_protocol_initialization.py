"""Protocol negotiation is independent of the application server state."""
from maverick_mcp.protocol import PROTOCOL_VERSION, initialize_response


def test_negotiation_and_transport_task_capability():
    response = initialize_response("2025-06-18", tasks_enabled=False)
    assert response["protocolVersion"] == "2025-06-18"
    assert set(response["capabilities"]) == {"tools", "resources", "prompts"}

    tasks = initialize_response("unknown", tasks_enabled=True)
    assert tasks["protocolVersion"] == PROTOCOL_VERSION
    assert tasks["capabilities"]["tasks"]["requests"] == {"tools": {"call": {}}}


def test_initialize_response_is_independent_for_each_session():
    first = initialize_response(None, tasks_enabled=True)
    first["capabilities"]["resources"]["subscribe"] = False
    first["capabilities"]["tasks"]["requests"].clear()
    second = initialize_response(None, tasks_enabled=True)
    assert second["capabilities"]["resources"]["subscribe"] is True
    assert second["capabilities"]["tasks"]["requests"] == {"tools": {"call": {}}}
