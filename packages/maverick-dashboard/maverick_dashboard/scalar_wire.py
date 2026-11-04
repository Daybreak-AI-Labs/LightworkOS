"""Exact ordinary integer values across the browser's numeric boundary."""
from __future__ import annotations

import re


def whole_number(value):
    if type(value) is str and re.fullmatch(r"-?[0-9]{1,25}", value):
        return int(value)
    return value


def exact_integers(value):
    if type(value) is int and abs(value) > 2**53 - 1:
        return str(value)
    if type(value) is dict:
        return {key: exact_integers(item) for key, item in value.items()}
    if type(value) in {list, tuple}:
        return [exact_integers(item) for item in value]
    return value
