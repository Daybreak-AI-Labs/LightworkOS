"""Model-facing tool outputs must serialize JSON compactly.

Connector tools return JSON that re-enters the context window as a
tool_result, usually truncated to a char budget (``[:3000]``-style).
``indent=2`` there wastes tokens on whitespace AND spends the truncation
budget on indentation instead of data — a 3000-char pretty dump can carry
~40% less payload than the compact form. These tests pin the compact
behavior of the shared helpers and ratchet ``indent=`` out of the model-
facing serialization sites under ``maverick/tools/``.
"""
from __future__ import annotations

import re
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[1] / "maverick" / "tools"

# Files whose json.dumps(indent=...) never reaches the model: oauth_helper
# pretty-prints a credentials file on disk for humans to inspect.
_INDENT_OK = {"oauth_helper.py"}

_INDENT_RE = re.compile(r"\bjson\.dumps\([^)]*\bindent\s*=", re.DOTALL)


def test_no_pretty_printed_json_in_tool_modules():
    offenders = []
    for path in sorted(TOOLS_DIR.glob("*.py")):
        if path.name in _INDENT_OK:
            continue
        if _INDENT_RE.search(path.read_text(encoding="utf-8")):
            offenders.append(path.name)
    assert not offenders, (
        "json.dumps(indent=...) in model-facing tool modules wastes context "
        "tokens and truncation budget; use maverick.fastjson.dumps_compact "
        f"instead (or allowlist a genuinely human-facing file): {offenders}"
    )


def test_mongodb_dump_is_compact_and_caps_after_serializing():
    from maverick.tools.mongodb_tool import _dump

    out = _dump({"a": 1, "rows": [{"x": "y"}]})
    assert out == '{"a":1,"rows":[{"x":"y"}]}'
    # the cap applies to the compact form, so the budget carries real data
    big = _dump({"k": "v" * 5000}, max_chars=100)
    assert big.endswith("... (truncated)") and len(big) <= 100 + len("\n... (truncated)")


def test_dynamodb_dump_is_compact():
    from maverick.tools.dynamodb_tool import _dump

    assert _dump({"a": [1, 2], "b": None}) == '{"a":[1,2],"b":null}'


def test_huggingface_format_body_is_compact():
    from maverick.tools.huggingface import _format_body

    assert _format_body({"gen": ["a", "b"]}) == '{"gen":["a","b"]}'
    assert _format_body("plain text") == "plain text"


def test_synthetic_data_json_rows_are_compact():
    from maverick.tools.synthetic_data import synthetic_data

    tool = synthetic_data()
    out = tool.fn({
        "rows": 2,
        "seed": 7,
        "fields": [{"name": "n", "type": "int", "min": 1, "max": 9}],
    })
    # dense JSON: no ": " / ", " separators anywhere in the payload
    assert '"n":' in out and '": ' not in out


def test_capability_query_list_is_compact_json():
    from maverick.fastjson import loads
    from maverick.tools.capability_query import capability_query

    out = capability_query("alice").fn({"op": "list"})
    assert '": ' not in out and "\n" not in out
    assert loads(out)["principal"] == "alice"
