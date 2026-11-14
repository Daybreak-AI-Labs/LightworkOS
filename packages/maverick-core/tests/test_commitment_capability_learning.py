"""Input validation for bounded capability-model learning."""
from __future__ import annotations

import pytest
from maverick.commitment_capability_learning import validate


def test_unhashable_requirement_values_are_a_validation_error():
    model = {
        "offers": [{"id": "offer-a", "label": "Extra order", "units": 5, "due_at": 1_900_000_000}],
        "requirements": {"material_per_unit": [[1]], "capacity_per_unit": [1], "shared_setup": [0]},
        "additions": [], "max_addition_cost": 0, "test_limit": 0, "test_effort": 0,
        "test_cost": 1, "expires_at": 1_900_000_000, "basis": "a reported basis",
    }
    with pytest.raises(ValueError):
        validate(model)
