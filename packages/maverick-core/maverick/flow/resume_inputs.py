"""Prepare submitted values for a paused flow without changing reviewed data."""
from __future__ import annotations


def prepare_resume_inputs(flow, prior, inputs: dict | None) -> tuple[dict, dict]:
    """Return the original submission for binding and the merged execution data.

    A declared form accepts only its named fields; a formless pause accepts new
    fields for compatibility. Neither can overwrite a value from the saved run.
    The original submission must remain available for approval verification.
    """
    submitted = dict(inputs or {})
    data = dict(prior.data)
    if inputs:
        paused = flow.node(prior.cursor) if prior.cursor else None
        declared = [str(field.get("name")) for field in getattr(paused, "form", None) or []
                    if isinstance(field, dict) and field.get("name")]
        allowed = set(declared) if declared else set(inputs)
        data.update({key: value for key, value in inputs.items()
                     if key in allowed and key not in data})
    return submitted, data
