"""Shared feature boundary for privacy register operations."""
from __future__ import annotations


def privacy_ops_or_403():
    """Return the native service only while privacy operations are enabled."""
    from maverick import privacy_ops

    from .feature_gate import feature_off

    if not privacy_ops.enabled():
        raise feature_off("privacy_ops", "The privacy register")
    return privacy_ops
