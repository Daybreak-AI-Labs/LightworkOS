"""Structured remedy construction; authored now, execution deferred."""
import pytest
from maverick_dashboard.product_errors import error_detail, next_action, product_error


def test_structured_budget_error_preserves_field_remedy():
    error = product_error(400, "budget_ceiling", "Choose a lower spending limit.",
                          field_errors={"max_dollars": "The workspace allows up to $10.00."},
                          next_action=next_action("Review spending", "/chat/goal/4#halt-resume-form"))
    assert error.status_code == 400
    assert error.detail["field_errors"]["max_dollars"].endswith("$10.00.")
    assert error.detail["next_action"]["href"] == "/chat/goal/4#halt-resume-form"
    assert error.detail["retryable"] is False


@pytest.mark.parametrize("href", ["https://elsewhere.invalid/", "//elsewhere.invalid/", "/%2felsewhere.invalid/", "/\\evil", "/%5cevil", "/%0aevil"])
def test_remedies_cannot_link_outside_the_application(href):
    with pytest.raises(ValueError):
        next_action("Continue", href)


def test_contract_rejects_exception_objects_and_unbounded_copy():
    with pytest.raises(ValueError):
        error_detail("failure", ValueError("private provider response"))
    with pytest.raises(ValueError):
        error_detail("failure", "x" * 1201)
