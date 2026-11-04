"""Deterministic, restrictive policy exports from the regulatory compiler.

The compiler's :mod:`maverick.regulatory_compiler` remains the authority for
Lightwork's runtime policy.  This module is deliberately a *one-way export*
of that compiler's public description and compiled policy: it does not accept
free-form rules, silently ignore a profile name, or claim that another policy
engine provides an equivalently complete deployment.

The exported OPA program and Cedar fragment are restrictive overlays.  They
need a gateway-specific identity, resource, and human-approval integration;
they are not a full authorization policy and are not a compliance, legal, or
certification determination.
"""
from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from . import regulatory_compiler
from .governance import evaluate

POLICY_EXPORT_SCHEMA = "lightwork.regulatory-policy-export.v1"
JSON_VERDICT_TABLE_SCHEMA = "lightwork.regulatory-json-verdict-table.v1"
POLICY_EXPORT_NOTICE = (
    "This is a deterministic restrictive policy export from Lightwork's "
    "runtime compiler. It is an operational integration artifact, not legal "
    "advice, a compliance determination, or a certification."
)

_OBLIGATION_FIELDS = (
    "id",
    "regulation",
    "article",
    "title",
    "effect",
    "actions",
    "min_risk",
    "deny_tools",
    "source_url",
)
_RISK_ORDER = ("low", "medium", "high")


class PolicyExportError(ValueError):
    """The requested compiler export cannot be made safely."""


def _canonical_json(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def normalize_profiles(keys: Sequence[str]) -> tuple[str, ...]:
    """Return a canonical, released profile selection or fail closed.

    ``compile_obligations`` intentionally ignores unknown keys for compatibility
    with permissive config parsing.  An external export is a boundary artifact,
    so accepting a typo there would create a silent, less restrictive policy.
    Only the public released-profile registry is accepted here.
    """
    if isinstance(keys, (str, bytes)) or not isinstance(keys, Sequence):
        raise PolicyExportError("profiles must be a sequence of released profile keys")
    shipped = tuple(regulatory_compiler.shipped_profile_keys())
    if len(shipped) != len(set(shipped)) or not all(
        isinstance(key, str) and key for key in shipped
    ):
        raise PolicyExportError("compiler released-profile registry is invalid")
    selected: set[str] = set()
    for raw in keys:
        if not isinstance(raw, str):
            raise PolicyExportError("profile keys must be strings")
        key = raw.strip().lower()
        if not key:
            raise PolicyExportError("profile keys must be non-empty")
        if key not in shipped:
            raise PolicyExportError(f"unrecognized released profile {key!r}")
        selected.add(key)
    if not selected:
        raise PolicyExportError("at least one released profile is required")
    # Shipped order is the stable public release order. It makes equivalent
    # profile selections byte-identical regardless of caller ordering.
    return tuple(key for key in shipped if key in selected)


def _obligation_catalog(description: Mapping[str, Any]) -> list[dict[str, Any]]:
    raw = description.get("obligations")
    if not isinstance(raw, list):
        raise PolicyExportError("compiler description omitted obligations")
    catalog: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw:
        if not isinstance(item, Mapping):
            raise PolicyExportError("compiler emitted a malformed obligation")
        if any(field not in item for field in _OBLIGATION_FIELDS):
            raise PolicyExportError("compiler obligation omitted source metadata")
        obligation_id = item["id"]
        if not isinstance(obligation_id, str) or not obligation_id or obligation_id in seen:
            raise PolicyExportError("compiler obligation identifiers are invalid")
        source_url = item["source_url"]
        if not isinstance(source_url, str) or not source_url.startswith("https://"):
            raise PolicyExportError(
                f"{obligation_id}: compiler obligation source URL is invalid"
            )
        if item["effect"] not in {
            regulatory_compiler.EFFECT_DENY,
            regulatory_compiler.EFFECT_REQUIRE_HUMAN,
            regulatory_compiler.EFFECT_ATTENUATE,
        }:
            raise PolicyExportError(f"{obligation_id}: compiler obligation effect is invalid")
        if not all(
            isinstance(item[field], list)
            and all(isinstance(value, str) and value for value in item[field])
            for field in ("actions", "deny_tools")
        ):
            raise PolicyExportError(f"{obligation_id}: compiler obligation scope is invalid")
        if item["min_risk"] is not None and item["min_risk"] not in _RISK_ORDER:
            raise PolicyExportError(f"{obligation_id}: compiler obligation risk floor is invalid")
        catalog.append({field: item[field] for field in _OBLIGATION_FIELDS})
        seen.add(obligation_id)
    return sorted(catalog, key=lambda item: item["id"])


def _compiled_components(
    keys: Sequence[str],
) -> tuple[tuple[str, ...], dict[str, Any], Any, list[dict[str, Any]]]:
    profiles = normalize_profiles(keys)
    description = regulatory_compiler.describe(profiles)
    if not isinstance(description, Mapping) or tuple(description.get("profiles", ())) != profiles:
        raise PolicyExportError("compiler description does not preserve the requested profiles")
    catalog = _obligation_catalog(description)
    compiled = regulatory_compiler.compile_obligations(profiles)
    if tuple(compiled.policy.compliance_profiles) != profiles:
        raise PolicyExportError("compiled policy does not preserve the requested profiles")
    return profiles, dict(description), compiled, catalog


def _enforced_ids(tags: Mapping[str, Any]) -> list[str]:
    if "obligation_evidence_error" in tags:
        raise PolicyExportError("compiler obligation evidence is unavailable")
    raw = tags.get("obligations_enforced", ())
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise PolicyExportError("compiler emitted malformed enforced-obligation evidence")
    ids: list[str] = []
    for item in raw:
        if not isinstance(item, Mapping) or not isinstance(item.get("obligation_id"), str):
            raise PolicyExportError("compiler emitted malformed enforced-obligation evidence")
        ids.append(item["obligation_id"])
    return sorted(set(ids))


def build_json_verdict_table(keys: Sequence[str]) -> dict[str, Any]:
    """Build a deterministic, closed JSON table for every classified action."""
    profiles, description, compiled, catalog = _compiled_components(keys)
    valid_ids = {item["id"] for item in catalog}
    verdicts: list[dict[str, Any]] = []
    for action in sorted(regulatory_compiler.classified_tools()):
        risk = regulatory_compiler.action_risk(action)
        if risk not in _RISK_ORDER:
            raise PolicyExportError(f"compiler action {action!r} has no valid risk tier")
        verdict = evaluate(action, policy=compiled.policy)
        checked = regulatory_compiler.obligations_checked(action, keys=profiles)
        if not isinstance(checked, list) or any(
            not isinstance(obligation_id, str) or obligation_id not in valid_ids
            for obligation_id in checked
        ):
            raise PolicyExportError("compiler emitted malformed checked-obligation evidence")
        tags = regulatory_compiler.audit_tags(action, verdict.rule, keys=profiles)
        if not isinstance(tags, Mapping):
            raise PolicyExportError("compiler emitted malformed verdict evidence")
        enforced = _enforced_ids(tags)
        if any(obligation_id not in valid_ids for obligation_id in enforced):
            raise PolicyExportError("compiler emitted unknown enforced obligation evidence")
        verdicts.append(
            {
                "action": action,
                "risk": risk,
                "decision": verdict.decision.value,
                "rule": verdict.rule,
                "checked_obligation_ids": sorted(set(checked)),
                "enforced_obligation_ids": enforced,
            }
        )
    return {
        "schema": JSON_VERDICT_TABLE_SCHEMA,
        "notice": POLICY_EXPORT_NOTICE,
        "profiles": list(profiles),
        "compiler_description_sha256": _sha256(description),
        "obligations": catalog,
        "policy": description["policy"],
        "attenuation": description["attenuation"],
        "verdicts": verdicts,
    }


def render_json_verdict_table(keys: Sequence[str]) -> str:
    """Render :func:`build_json_verdict_table` as canonical UTF-8 JSON text."""
    return _canonical_json(build_json_verdict_table(keys)) + "\n"


def render_opa_rego(keys: Sequence[str]) -> str:
    """Render an OPA/Rego v1 restrictive overlay for a compiler selection.

    The input contract is closed: ``input.action`` must be a known classified
    action and ``input.risk`` must be ``low``, ``medium``, or ``high``. Unknown
    values deny rather than silently becoming a default allow. The export emits
    ``require_human`` as a verdict for the gateway to pause and route through
    its human-approval control; OPA itself does not enact that workflow.
    """
    table = build_json_verdict_table(keys)
    policy = table["policy"]
    known_actions = [row["action"] for row in table["verdicts"]]
    risk_ranks = {risk: index for index, risk in enumerate(_RISK_ORDER)}

    def value(item: object) -> str:
        return _canonical_json(item)

    lines = [
        "# Generated by maverick.policy_exports; do not hand-edit.",
        "# Restrictive overlay only; not a compliance or certification determination.",
        "package lightwork.regulatory",
        "",
        "import rego.v1",
        "",
        f"profiles := {value(table['profiles'])}",
        f"compiler_description_sha256 := {value(table['compiler_description_sha256'])}",
        f"obligations := {value(table['obligations'])}",
        f"known_actions := {value(known_actions)}",
        f"deny_actions := {value(policy['deny_actions'])}",
        f"require_human_actions := {value(policy['require_human_actions'])}",
        f"risk_rank := {value(risk_ranks)}",
        "",
        "valid_action if {",
        "    is_string(input.action)",
        "    input.action in known_actions",
        "}",
        "",
        "valid_risk if {",
        "    is_string(input.risk)",
        f"    input.risk in {value(list(_RISK_ORDER))}",
        "}",
        "",
        'decision := {"decision":"deny","rule":"invalid_action"} if {',
        "    not valid_action",
        "}",
        'else := {"decision":"deny","rule":"invalid_risk"} if {',
        "    not valid_risk",
        "}",
        'else := {"decision":"deny","rule":"deny_actions"} if {',
        "    input.action in deny_actions",
        "}",
    ]
    deny_floor = policy["deny_min_risk"]
    if deny_floor is not None:
        lines += [
            'else := {"decision":"deny","rule":"deny_min_risk"} if {',
            f"    risk_rank[input.risk] >= {risk_ranks[deny_floor]}",
            "}",
        ]
    lines += [
        'else := {"decision":"require_human","rule":"require_human_actions"} if {',
        "    input.action in require_human_actions",
        "}",
    ]
    human_floor = policy["require_human_min_risk"]
    if human_floor is not None:
        lines += [
            'else := {"decision":"require_human","rule":"require_human_min_risk"} if {',
            f"    risk_rank[input.risk] >= {risk_ranks[human_floor]}",
            "}",
        ]
    lines += [
        'else := {"decision":"allow","rule":"default"}',
        "",
    ]
    return "\n".join(lines)


def _cedar_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _cedar_annotations(obligation: Mapping[str, Any], *, suffix: str) -> list[str]:
    effect = str(obligation["effect"])
    cedar_id = f"lightwork.{obligation['id']}.{suffix}"
    if effect == regulatory_compiler.EFFECT_REQUIRE_HUMAN:
        contract = (
            "Cedar returns forbid; the integrating gateway must interpret this "
            "annotated restriction as a human-approval pause before retry."
        )
    elif effect == regulatory_compiler.EFFECT_ATTENUATE:
        contract = (
            "Cedar returns forbid; the integrating gateway must also remove this "
            "action from derived capability grants."
        )
    else:
        contract = "Cedar forbid is the compiled deny effect."
    return [
        f"@id({_cedar_string(cedar_id)})",
        f"@lightwork_obligation_id({_cedar_string(str(obligation['id']))})",
        f"@lightwork_regulation({_cedar_string(str(obligation['regulation']))})",
        f"@lightwork_article({_cedar_string(str(obligation['article']))})",
        f"@lightwork_source_url({_cedar_string(str(obligation['source_url']))})",
        f"@lightwork_effect({_cedar_string(effect)})",
        f"@lightwork_adapter_contract({_cedar_string(contract)})",
    ]


def render_cedar(keys: Sequence[str]) -> str:
    """Render a Cedar restrictive-overlay fragment with provenance annotations.

    Cedar's native outcomes are ``permit`` and ``forbid``. Every exported
    compiler restriction is therefore a ``forbid``; its exact original effect
    and source are carried in arbitrary Cedar annotations. An integration must
    supply an ``Action`` entity for every classified action and a string
    ``context.risk`` field before loading this fragment.
    """
    _, _, _, catalog = _compiled_components(keys)
    lines = [
        "// Generated by maverick.policy_exports; do not hand-edit.",
        "// Restrictive overlay only. It needs separate permit policies and a schema",
        "// with Action entities plus context.risk: String.",
        "// @lightwork_effect preserves Lightwork's runtime semantics; it is not a",
        "// certification or a claim that Cedar implements human approval by itself.",
        "",
    ]
    for obligation in catalog:
        targets = obligation["actions"]
        if obligation["effect"] == regulatory_compiler.EFFECT_ATTENUATE:
            targets = obligation["deny_tools"]
        if targets:
            lines.extend(_cedar_annotations(obligation, suffix="actions"))
            action_entities = ", ".join(
                f"Action::{_cedar_string(action)}" for action in sorted(targets)
            )
            lines += [
                "forbid(",
                "  principal,",
                f"  action in [{action_entities}],",
                "  resource",
                ");",
                "",
            ]
        if obligation["min_risk"] is not None:
            floor_index = _RISK_ORDER.index(obligation["min_risk"])
            values = " || ".join(
                f"context.risk == {_cedar_string(risk)}"
                for risk in _RISK_ORDER[floor_index:]
            )
            lines.extend(_cedar_annotations(obligation, suffix="risk-floor"))
            lines += [
                "forbid(",
                "  principal,",
                "  action,",
                "  resource",
                ")",
                "when {",
                f"  {values}",
                "};",
                "",
            ]
    return "\n".join(lines)


def build_policy_export(keys: Sequence[str]) -> dict[str, Any]:
    """Return all deterministic external-policy representations together."""
    table = build_json_verdict_table(keys)
    # Re-use the canonical profile selection from the table so all renderers are
    # byte-stable together even when callers supplied a different ordering.
    profiles = tuple(table["profiles"])
    return {
        "schema": POLICY_EXPORT_SCHEMA,
        "notice": POLICY_EXPORT_NOTICE,
        "profiles": list(profiles),
        "compiler_description_sha256": table["compiler_description_sha256"],
        "obligations": table["obligations"],
        "json_verdict_table": table,
        "opa_rego": render_opa_rego(profiles),
        "cedar": render_cedar(profiles),
    }


__all__ = [
    "JSON_VERDICT_TABLE_SCHEMA",
    "POLICY_EXPORT_NOTICE",
    "POLICY_EXPORT_SCHEMA",
    "PolicyExportError",
    "build_json_verdict_table",
    "build_policy_export",
    "normalize_profiles",
    "render_cedar",
    "render_json_verdict_table",
    "render_opa_rego",
]
