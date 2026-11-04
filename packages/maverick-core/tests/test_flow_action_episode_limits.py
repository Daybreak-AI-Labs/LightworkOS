"""Client-supplied retention bounds must reject without numeric overflow."""
from __future__ import annotations

import pytest
from maverick.flow.action_episode_review import _schema


@pytest.mark.parametrize("kind", ["integer", "number"])
@pytest.mark.parametrize("sign", [-1, 1])
def test_oversized_json_integer_bound_is_an_invalid_request(kind, sign):
    # JSON permits these finite integers; converting them to a platform float
    # first raises OverflowError, which escapes the API's invalid-request path.
    schema = {
        "type": "object", "required": ["quantity"], "additionalProperties": False,
        "properties": {"quantity": {"type": kind,
            "minimum": sign * 10**400, "maximum": 10**401}},
    }
    with pytest.raises(ValueError, match="finite|limit|bound"):
        _schema(schema)
