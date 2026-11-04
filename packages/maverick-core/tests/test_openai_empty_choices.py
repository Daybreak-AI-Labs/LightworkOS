"""Regression: an OpenAI-compatible response with an empty ``choices`` list
must raise a clear, actionable error rather than a cryptic IndexError.

Some gateways (and OpenAI/Azure content-filter) return ``choices: []`` on an
upstream/filter error. ``_from_response`` is a staticmethod, so it can be
exercised without constructing a real client.
"""
from __future__ import annotations

import pytest
from maverick.providers.openai_provider import OpenAIClient


class _EmptyResp:
    choices: list = []
    usage = None


class _MissingChoices:
    usage = None  # no ``choices`` attribute at all


def test_empty_choices_raises_clear_error():
    with pytest.raises(RuntimeError, match="no choices"):
        OpenAIClient._from_response(_EmptyResp(), None)


def test_absent_choices_attr_raises_clear_error():
    with pytest.raises(RuntimeError, match="no choices"):
        OpenAIClient._from_response(_MissingChoices(), None)
