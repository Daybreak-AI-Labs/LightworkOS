"""Deterministic marking for reviewed AI evidence output."""
from __future__ import annotations

from collections.abc import Mapping
from typing import Any


def render_text(
    generated_text: str,
    *,
    receipt_id: str,
    settings: Mapping[str, Any],
    human_interaction: bool,
    apply_interaction_disclosure: bool,
    synthetic_content: bool,
    deepfake: bool,
    public_interest_text: bool,
    editorial_exception: Mapping[str, Any] | None,
    state_error: type[Exception],
) -> tuple[str, dict[str, Any]]:
    # Delivery is the human-facing boundary in v1. The approved disclosure is
    # applied on every delivery because the caller cannot independently attest
    # that an earlier response was actually presented to the user.
    disclosure_required = bool(settings["require_interaction_disclosure"])
    if apply_interaction_disclosure and not disclosure_required:
        raise state_error(
            "interaction disclosure cannot be applied when it is not required"
        )
    disclosure_applied = apply_interaction_disclosure
    machine_mark_applied = bool(
        synthetic_content and settings["require_machine_readable_marking"]
    )
    visible_required = bool(
        settings["require_visible_marking"] or deepfake or public_interest_text
    )
    visible_mark_applied = bool(visible_required and editorial_exception is None)
    delivered = generated_text
    if disclosure_applied:
        delivered = f"{settings['disclosure_text']}\n\n{delivered}"
    suffixes: list[str] = []
    if machine_mark_applied:
        suffixes.append(
            str(settings["machine_marker"]).replace("{receipt_id}", receipt_id)
        )
    if visible_mark_applied:
        suffixes.append(str(settings["visible_marker"]))
    if suffixes:
        delivered = f"{delivered}\n\n" + "\n".join(suffixes)
    decision = {
        "human_interaction": human_interaction,
        "synthetic_content": synthetic_content,
        "deepfake": deepfake,
        "public_interest_text": public_interest_text,
        "interaction_disclosure_required": disclosure_required,
        "interaction_disclosure_applied": disclosure_applied,
        "machine_readable_marking_required": bool(
            synthetic_content and settings["require_machine_readable_marking"]
        ),
        "machine_readable_marking_applied": machine_mark_applied,
        "visible_marking_required": visible_required,
        "visible_marking_applied": visible_mark_applied,
        "editorial_exception": (
            None if editorial_exception is None else dict(editorial_exception)
        ),
        "rendering_policy": "deterministic_text_v1",
    }
    return delivered, decision
