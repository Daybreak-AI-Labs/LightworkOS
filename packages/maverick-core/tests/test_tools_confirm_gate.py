"""Destructive / costly tool ops must require a REAL boolean confirm.

Regression: gated tools used ``bool(args.get("confirm"))``. ``bool("false")``
is True in Python, so a stringy ``"false"`` (from a loose LLM or a
non-conforming MCP client) fired the live action — refunds, deletes,
sends. The shared ``as_bool()`` fails closed: only a real boolean ``True``
authorises the op; everything else is a dry run.
"""
import asyncio
import inspect

import pytest
from maverick.tools import as_bool
from maverick.tools.s3_tool import s3_tool
from maverick.tools.shopify_tool import shopify_tool


def test_as_bool_only_real_true_passes():
    assert as_bool(True) is True
    assert as_bool(False) is False
    assert as_bool("false") is False  # the bug: bool("false") was True
    assert as_bool("true") is False   # strings never authorise (fail closed)
    assert as_bool("1") is False
    assert as_bool(1) is False
    assert as_bool(0) is False
    assert as_bool(None) is False


def _run(tool, args):
    res = tool.fn(args)
    if inspect.iscoroutine(res):
        res = asyncio.run(res)
    return res


def test_s3_delete_with_string_false_is_dry_run():
    pytest.importorskip("boto3")  # s3 tool short-circuits without the SDK
    out = _run(s3_tool(), {
        "op": "delete", "bucket": "b", "key": "k", "confirm": "false",
    })
    assert "DRY RUN" in out


def test_shopify_refund_with_string_false_is_dry_run():
    out = _run(shopify_tool(), {
        "op": "refund_create", "order_id": 1, "amount_cents": 100,
        "currency": "usd", "confirm": "false",
    })
    assert "DRY RUN" in out
