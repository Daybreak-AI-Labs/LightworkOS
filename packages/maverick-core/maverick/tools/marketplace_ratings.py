"""Marketplace ratings + install verification.

Two pure, offline helpers for a plugin/tool marketplace: aggregate user star
ratings into a robust ranking score, and verify a downloaded artifact against its
declared hash. Deterministic; stdlib math + hashlib only; no network.

ops:
  - aggregate(ratings:[1..5]) -> mean, count, star histogram, and a Wilson
    lower-bound score in [0,1] (the "confidence-adjusted" rank used so a 5-star
    item with 1 vote doesn't outrank a 4.8-star item with 1000).
  - verify_install(declared_sha256, content | computed_sha256) -> VERIFIED /
    MISMATCH. Pass ``content`` to hash the artifact here (sha256) and check it
    against the declared digest; or pass a precomputed ``computed_sha256``.
    Constant-time hex compare.
"""
from __future__ import annotations

import hmac
import json
import math
from typing import Any

from . import Tool

# z for a 95% confidence interval — the standard constant for the Wilson score.
_WILSON_Z = 1.959963984540054


def _wilson_lower_bound(positive: float, total: int, z: float = _WILSON_Z) -> float:
    """Wilson score interval lower bound for a Bernoulli proportion.

    ``positive`` is the (possibly fractional) count of "successes" — here, stars
    normalised to 0..1 and summed — and ``total`` the number of ratings.
    """
    if total <= 0:
        return 0.0
    phat = positive / total
    denom = 1.0 + (z * z) / total
    centre = phat + (z * z) / (2.0 * total)
    margin = z * math.sqrt((phat * (1.0 - phat) + (z * z) / (4.0 * total)) / total)
    return (centre - margin) / denom


def _aggregate(args: dict[str, Any]) -> str:
    ratings = args.get("ratings")
    if not isinstance(ratings, list) or not ratings:
        return "ERROR: ratings (a non-empty array of 1..5) is required"
    histogram = {str(s): 0 for s in range(1, 6)}
    total_stars = 0
    for r in ratings:
        try:
            star = int(r)
        except (TypeError, ValueError):
            return f"ERROR: rating {r!r} is not an integer 1..5"
        if star < 1 or star > 5:
            return f"ERROR: rating {star} out of range (expected 1..5)"
        histogram[str(star)] += 1
        total_stars += star

    count = len(ratings)
    mean = total_stars / count
    # Normalise each star to 0..1 (so 5 stars -> 1.0, 1 star -> 0.0) and sum;
    # that fractional "positive" mass feeds the Wilson lower bound for ranking.
    positive = sum((s - 1) / 4.0 for s in (int(x) for x in ratings))
    wilson = _wilson_lower_bound(positive, count)

    out = {
        "count": count,
        "mean": round(mean, 4),
        "histogram": histogram,
        "wilson_lower_bound": round(wilson, 6),
    }
    return json.dumps(out, sort_keys=True)


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _verify_install(args: dict[str, Any]) -> str:
    declared = args.get("declared_sha256")
    if not isinstance(declared, str) or not declared.strip():
        return "ERROR: declared_sha256 is required"
    # Prefer hashing the actual artifact bytes when provided ("content"), so the
    # tool genuinely verifies a downloaded artifact rather than trusting a hash
    # the caller computed. Falls back to a precomputed "computed_sha256".
    computed = args.get("computed_sha256")
    content = args.get("content")
    if isinstance(content, str) and content != "":
        import hashlib
        computed = hashlib.sha256(content.encode("utf-8")).hexdigest()
    if not isinstance(computed, str) or not computed.strip():
        return ("ERROR: provide 'content' (the artifact text to hash) or a "
                "precomputed 'computed_sha256'")
    a = declared.strip().lower()
    b = computed.strip().lower()
    if not all(_is_sha256_hex(v) for v in (a, b)):
        return "ERROR: sha256 digests must be 64 hexadecimal characters"
    if hmac.compare_digest(a.encode(), b.encode()):
        return f"VERIFIED: sha256 {a}"
    return f"MISMATCH: declared {a} != computed {b}"


def _run(args: dict[str, Any]) -> str:
    op = args.get("op")
    if op == "aggregate":
        return _aggregate(args)
    if op == "verify_install":
        return _verify_install(args)
    return f"ERROR: unknown op {op!r} (expected aggregate or verify_install)"


_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "op": {"type": "string", "enum": ["aggregate", "verify_install"]},
        "ratings": {
            "type": "array",
            "description": "for op=aggregate; star ratings, each an integer 1..5",
            "items": {"type": "integer", "minimum": 1, "maximum": 5},
        },
        "declared_sha256": {
            "type": "string",
            "description": "for op=verify_install; the publisher's declared digest",
        },
        "computed_sha256": {
            "type": "string",
            "description": "for op=verify_install; a precomputed local digest "
                           "(use 'content' instead to hash the artifact here)",
        },
        "content": {
            "type": "string",
            "description": "for op=verify_install; the downloaded artifact text "
                           "to hash (sha256) and check against declared_sha256",
        },
    },
    "required": ["op"],
}


def marketplace_ratings() -> Tool:
    return Tool(
        name="marketplace_ratings",
        description=(
            "Marketplace ratings + install verification. op=aggregate {ratings: "
            "[1..5]} -> JSON {count, mean, histogram, wilson_lower_bound} (the "
            "Wilson lower bound is the confidence-adjusted rank). op=verify_install "
            "{declared_sha256, content | computed_sha256} -> VERIFIED/MISMATCH "
            "(hashes 'content' here, or compares a precomputed digest; constant-time "
            "compare). Deterministic; offline; stdlib math+hashlib only."
        ),
        input_schema=_SCHEMA,
        fn=_run,
        parallel_safe=True,
    )
