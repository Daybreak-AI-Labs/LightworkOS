"""A task's own AI choice, retained in its existing sealed admission receipt."""
from __future__ import annotations

import re
from contextlib import contextmanager
from contextvars import ContextVar

_CURRENT = ContextVar("task_model_selection", default=None)
_VALID = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
EFFORT_LABELS = {"low": "Quick", "medium": "Balanced", "high": "Thorough",
                 "xhigh": "Very thorough", "max": "Deepest"}


def effort_choices(spec):
    from .effort import effort_for_model
    from .llm import _parse_spec

    provider, model = _parse_spec(spec)
    return [{"value": level, "label": label} for level, label in EFFORT_LABELS.items()
            if provider == "anthropic" and effort_for_model(level, model) == level]


def catalog():
    """Only installed model choices with current, offline provider prerequisites."""
    from .config import config_source_errors, load_config
    from .llm import (
        ROLE_MODELS,
        _canonical_spec,
        _parse_spec,
        catalog_specs,
        offline_model_for_role,
    )
    from .operator_preflight import _route_configuration_missing
    from .runtime_overrides import allowed_models

    cfg = load_config()
    if config_source_errors(include_tenant=True):
        raise ValueError("AI choices could not be read. Open Settings before starting this task.")
    models = cfg.get("models") or {}
    if not isinstance(models, dict):
        raise ValueError("AI model settings could not be read.")
    options = dict(catalog_specs())
    custom = models.get("catalog") or []
    if not isinstance(custom, list) or len(custom) > 1000:
        raise ValueError("The installed model list could not be read completely.")
    for spec in custom:
        if not isinstance(spec, str) or not _VALID.fullmatch(spec):
            raise ValueError("An installed AI model choice is invalid. Open Settings to repair it.")
        options[spec] = "Custom model"
    token = _CURRENT.set(None)
    try:
        for role in set(ROLE_MODELS) | {key for key, value in models.items() if isinstance(value, str)}:
            options[offline_model_for_role(role, config=cfg)] = "Installed model"
    finally:
        _CURRENT.reset(token)
    allowed = {_canonical_spec(spec) for spec in allowed_models()}
    if allowed:
        for spec in allowed:
            options.setdefault(spec, "Allowed model")
    result = {}
    from .providers import KNOWN_PROVIDERS
    for spec in options:
        if not _VALID.fullmatch(spec):
            continue
        canonical = _canonical_spec(spec)
        provider, model = _parse_spec(canonical)
        if provider not in KNOWN_PROVIDERS or (allowed and canonical not in allowed):
            continue
        if _route_configuration_missing(provider, cfg):
            continue
        # Keep exact configured names, including deployment/local names. This
        # is a choice of an installed route, not a claim of a live model test.
        result[canonical] = {"value": canonical, "provider": provider,
                             "label": model, "efforts": effort_choices(canonical)}
    return list(result.values())


def validate(value):
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {"model", "effort"}:
        raise ValueError("Choose an AI model and thinking depth from the task controls.")
    model, effort = value["model"], value["effort"]
    if not isinstance(model, str) or not isinstance(effort, str):
        raise ValueError("Choose an AI model and thinking depth from the task controls.")
    if not model and not effort:
        return None
    choice = next((row for row in catalog() if row["value"] == model), None)
    if choice is None:
        raise ValueError("That AI model is no longer available here. Choose a current model before starting.")
    if effort and effort not in {row["value"] for row in choice["efforts"]}:
        raise ValueError("That thinking depth is not supported by this model. Choose one of its listed options.")
    return {"model": model, "effort": effort}


def recorded(world, goal_id):
    from .attachment_submissions import SubmissionStore
    receipt = SubmissionStore(world).for_goal(goal_id)
    value = receipt["detail"].get("task_model_selection") if receipt else None
    return validate(value)


@contextmanager
def run_scope(world, goal_id):
    token = _CURRENT.set(recorded(world, goal_id))
    try:
        yield
    finally:
        _CURRENT.reset(token)


def current_model():
    value = _CURRENT.get()
    return validate(value)["model"] if value is not None else None


def current_effort():
    value = _CURRENT.get()
    return (validate(value)["effort"] or None) if value is not None else None
