"""Copilot reaches the same protected complete safety-settings review."""
from . import runtime_policy_recovery_ops as native
from .product_operations import Adapter, EmptyInput, Preview, Snapshot


def _snapshot(request, original):
    context = native.authority(request)
    return Snapshot(context, "Saved installation safety settings",
        "Open Help to choose and completely review an exact retained safety-settings copy, or read your original restoration. Copilot does not replace settings or disclose connection secrets.",
        details={"runtime_policy_recovery": {"context": context, "original": original}})


def restore(request, _selection):
    return _snapshot(request, False)


def originals(request, _selection):
    return _snapshot(request, True)


def prepare(request, selection, _arguments):
    value = restore(request, selection)
    return Preview(value.summary, native=value.details)


def prepare_original(request, selection, _arguments):
    value = originals(request, selection)
    return Preview(value.summary, native=value.details)


def entries():
    return (Adapter("preferences.runtime_policy_recovery", "Restore saved installation safety settings", "preferences",
        "/help#runtime-policy-recovery", ("/help",), EmptyInput, restore, prepare,
        aliases=("repair saved safety settings", "restore installation policy")),
        Adapter("preferences.runtime_policy_original_results", "Read my original safety-settings restoration", "preferences",
        "/help#runtime-policy-recovery", ("/help",), EmptyInput, originals, prepare_original,
        aliases=("safety settings restore lost reply", "original policy restoration")))
