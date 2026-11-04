"""Local reviewed-example authoring of native action sequence drafts."""
from __future__ import annotations

import json
import os
import stat
import time
from pathlib import Path

import click

from ._flow_operator_groups import (
    _JSON_FILE,
    _read_json,
    _reject_constant,
    _unique_object,
    _write_new_json,
    flow_group,
)


@flow_group.group("recipe")
def recipe_group() -> None:
    """Learn typed dataflow from reviewed action episodes; never dispatch tools.

    Files retain private examples. Review flags are local assertions, not proof
    of identity or native execution. Publishing and running remain separate.
    """


@recipe_group.command("learn")
@click.option("--episodes", type=_JSON_FILE, required=True)
@click.option("--allow-tool", multiple=True, required=True,
              help="Exact permitted tool name; repeat for each tool.")
@click.option("--transforms", is_flag=True,
              help="Learn bounded argument expressions as a v2 recipe; requires --domain.")
@click.option("--choices", is_flag=True,
              help="Learn one shared action followed by a binary terminal action choice; requires --domain.")
@click.option("--domain", type=_JSON_FILE,
              help="Complete bounded schemas for --transforms or the prefix/branches schemas for --choices.")
@click.option("--max-operations", type=click.IntRange(1, 4), default=None,
              help="Maximum operations per expression with --transforms or --choices (default: 2).")
@click.option("--operators", default=None,
              help="Comma-separated expression operations; omitted uses all supported operations.")
@click.option("--constants", type=_JSON_FILE,
              help="JSON array of explicit expression constants (at most eight).")
@click.option("--reviewed", is_flag=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def learn_recipe(episodes: Path, allow_tool: tuple[str, ...], transforms: bool, choices: bool,
                 domain: Path | None, max_operations: int | None, operators: str | None,
                 constants: Path | None, reviewed: bool, output: Path) -> None:
    """Infer complete bindings, transformed arguments or a bounded action choice."""
    from ..flow.action_recipe import synthesize

    if not reviewed:
        raise click.ClickException("review the action episodes, then pass --reviewed")
    if transforms and choices:
        raise click.ClickException("--choices and --transforms are mutually exclusive learning modes")
    if not (transforms or choices) and any(value is not None for value in (domain, max_operations, operators, constants)):
        raise click.ClickException("--domain, --max-operations, --operators and --constants require --transforms or --choices")
    if (transforms or choices) and domain is None:
        raise click.ClickException("--choices requires --domain with prefix/branches schemas" if choices
                                   else "--transforms requires --domain with complete bounded schemas")
    try:
        if transforms or choices:
            artifact = _learn_transformed(episodes, allow_tool, domain, max_operations, operators, constants,
                                          choices=choices)
        else:
            artifact = synthesize(_read_json(episodes), allowed_tools=list(allow_tool))
    except (ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    _write_new_json(output, artifact)
    if choices:
        click.echo("Retained all consistent guards and argument expressions: one shared action, "
                   "then one of two terminal actions. This does not authenticate the supplied execution or review.")
    else:
        click.echo(f"Retained {artifact['candidate_binding_count']} argument alternatives summed across leaves. "
                   "This does not authenticate the supplied execution or review.")


def _learn_transformed(episodes, allow_tool, domain, max_operations, operators, constants, *, choices=False):
    from ..flow.action_recipe_transforms import synthesize_transformed

    learner = synthesize_transformed
    if choices:
        from ..flow.action_choice import synthesize_choice

        learner = synthesize_choice
    selected = None if operators is None else [name.strip() for name in operators.split(",")]
    if selected is not None and (any(not name for name in selected) or len(set(selected)) != len(selected)):
        raise click.ClickException("--operators requires unique nonempty comma-separated names")
    return learner(
        _read_json(episodes), allowed_tools=list(allow_tool), domain=_read_json(domain),
        max_operations=2 if max_operations is None else max_operations, operators=selected,
        constants=None if constants is None else _read_json(constants),
    )


@recipe_group.command("refine")
@click.option("--artifact", type=_JSON_FILE, required=True)
@click.option("--episodes", type=_JSON_FILE, required=True)
@click.option("--reviewed", is_flag=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def refine_recipe(artifact: Path, episodes: Path, reviewed: bool, output: Path) -> None:
    """Add reviewed executions while retaining earlier evidence."""
    from ..flow.action_recipe import refine

    if not reviewed:
        raise click.ClickException("review the additional episodes, then pass --reviewed")
    try:
        revised = refine(_read_json(artifact), _read_json(episodes))
    except (ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    _write_new_json(output, revised)


@recipe_group.command("draft")
@click.option("--artifact", type=_JSON_FILE, required=True)
@click.option("--flow-id", required=True)
@click.option("--name", required=True)
@click.option("--teach-choices", is_flag=True,
              help="Add a real-prefix human teaching pause for choice ambiguity; governed lineage is required at runtime.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def draft_recipe(artifact: Path, flow_id: str, name: str, teach_choices: bool, output: Path) -> None:
    """Export an unsaved native Flow with an approval before every action."""
    from ..flow.ir import partition_draft_validation_errors
    from ..flow.recipe_flow import make_flow

    try:
        flow = make_flow(_read_json(artifact), flow_id=flow_id, name=name, teaching=teach_choices)
        blocking, unclassified = partition_draft_validation_errors(flow.validate())
        if blocking:
            raise ValueError("; ".join(blocking))
    except (ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    _write_new_json(output, flow.to_dict())
    if unclassified:
        click.echo("Draft only: classify its tools through the existing policy before saving or running.")
    if teach_choices:
        click.echo("Teaching inspection draft only: native teaching requires governed lineage and explicit feature opt-ins. "
                   "The teaching marker grants no execution authority.")
    click.echo("Not saved, published or executed. Review the retained examples and proposed actions.")


@recipe_group.command("verify-bundle")
@click.option("--bundle", type=_JSON_FILE, required=True)
@click.option("--trust", type=_JSON_FILE, required=True,
              help="Independently provisioned issuer/tenant public-key policy; never trust a bundle-provided key.")
@click.option("--tenant", required=True, help="Exact expected tenant identity.")
def verify_recipe_bundle(bundle: Path, trust: Path, tenant: str) -> None:
    """Verify a service attestation offline; later withdrawal is not checked."""
    from ..flow.action_provenance import verify_bundle

    try:
        result = verify_bundle(_read_json(bundle), trust=_read_json(trust),
                               expected_tenant=tenant, now=time.time())
    except (ValueError, TypeError, PermissionError) as exc:
        raise click.ClickException("bundle verification refused") from exc
    public = {key: result[key] for key in (
        "body_sha256", "signature_sha256", "trust_sha256", "key_fingerprint",
        "signature_status", "commitments_status", "time_status", "live_status",
    )}
    click.echo(json.dumps(public, sort_keys=True))


@recipe_group.command("learn-verified")
@click.option("--bundles", type=_JSON_FILE, required=True, help="JSON array of complete signed reviewed bundles.")
@click.option("--trust", type=_JSON_FILE, required=True)
@click.option("--tenant", required=True)
@click.option("--allow-tool", multiple=True, required=True)
@click.option("--choices", is_flag=True, help="Learn a shared prefix and binary terminal choice; requires --domain.")
@click.option("--domain", type=_JSON_FILE, help="Complete domain opts into v2 learning, or choice learning with --choices.")
@click.option("--max-operations", type=click.IntRange(1, 4), default=None)
@click.option("--operators", default=None)
@click.option("--constants", type=_JSON_FILE)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def learn_verified_recipe(bundles: Path, trust: Path, tenant: str, allow_tool: tuple[str, ...], choices: bool,
                          domain: Path | None, max_operations: int | None,
                          operators: str | None, constants: Path | None, output: Path) -> None:
    """Learn a lineage package from signed evidence; does not grant governed admission."""
    from ..flow.recipe_lineage import learn_from_verified_bundles

    if choices and domain is None:
        raise click.ClickException("--choices requires --domain with prefix/branches schemas")
    if domain is None and any(value is not None for value in (max_operations, operators, constants)):
        raise click.ClickException("transformed grammar options require --domain")
    selected = None if operators is None else [name.strip() for name in operators.split(",")]
    if selected is not None and (any(not name for name in selected) or len(set(selected)) != len(selected)):
        raise click.ClickException("--operators requires unique nonempty comma-separated names")
    try:
        learner = learn_from_verified_bundles
        if choices:
            from ..flow.recipe_lineage import learn_choice_from_verified_bundles

            learner = learn_choice_from_verified_bundles
        package = learner(
            _read_lineage_json(bundles), trust=_read_json(trust), expected_tenant=tenant, now=time.time(),
            allowed_tools=list(allow_tool), domain=None if domain is None else _read_json(domain),
            max_operations=2 if max_operations is None else max_operations, operators=selected,
            constants=None if constants is None else _read_json(constants),
        )
    except (ValueError, TypeError, PermissionError) as exc:
        raise click.ClickException("verified recipe learning refused") from exc
    _write_lineage_json(output, package)
    click.echo("Signatures and commitments verified under the supplied trust policy; live status not checked. "
               "Not governed-admitted, published or executed. Service attestations are not personal reviewer signatures.")


@recipe_group.command("learn-workflow-verified")
@click.option("--bundles", type=_JSON_FILE, required=True, help="JSON array of complete signed reviewed bundles.")
@click.option("--trust", type=_JSON_FILE, required=True, help="Independently provisioned evidence trust policy.")
@click.option("--tenant", required=True, help="Exact expected tenant identity.")
@click.option("--allow-tool", multiple=True, required=True)
@click.option("--domain", type=_JSON_FILE, required=True, help="Bounded inputs and per-tool arguments/result schemas.")
@click.option("--max-operations", type=click.IntRange(1, 2), default=1, show_default=True)
@click.option("--max-steps", type=click.IntRange(1, 8), default=8, show_default=True)
@click.option("--operators", default=None, help="Unique comma-separated expression operations.")
@click.option("--constants", type=_JSON_FILE, help="JSON array of explicit expression constants.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def learn_workflow_verified(bundles: Path, trust: Path, tenant: str, allow_tool: tuple[str, ...], domain: Path,
                            max_operations: int, max_steps: int, operators: str | None,
                            constants: Path | None, output: Path) -> None:
    """Infer bounded next actions and completion from signed observed histories."""
    from ..flow.recipe_lineage import learn_transducer_from_verified_bundles

    selected = None if operators is None else [name.strip() for name in operators.split(",")]
    if selected is not None and (any(not name for name in selected) or len(set(selected)) != len(selected)):
        raise click.ClickException("--operators requires unique nonempty comma-separated names")
    try:
        package = learn_transducer_from_verified_bundles(
            _read_lineage_json(bundles), trust=_read_json(trust), expected_tenant=tenant, now=time.time(),
            allowed_tools=list(allow_tool), domain=_read_json(domain), max_operations=max_operations,
            operators=selected, constants=None if constants is None else _read_json(constants), max_steps=max_steps,
        )
    except (ValueError, TypeError, PermissionError) as exc:
        raise click.ClickException("verified workflow learning refused") from exc
    _write_lineage_json(output, package)
    click.echo(f"Learned next actions and completion over bounded observed histories, up to {max_steps} actions. "
               "Signatures and commitments verified under the supplied trust policy; live status not checked. "
               "Not governed-admitted, published or executed. Service attestations do not prove business correctness.")


@recipe_group.command("learn-memory-verified")
@click.option("--bundles", type=_JSON_FILE, required=True, help="JSON array of complete signed reviewed bundles.")
@click.option("--trust", type=_JSON_FILE, required=True, help="Independently provisioned evidence trust policy.")
@click.option("--tenant", required=True, help="Exact expected tenant identity.")
@click.option("--allow-tool", multiple=True, required=True)
@click.option("--domain", type=_JSON_FILE, required=True, help="Bounded inputs and per-tool arguments/result schemas.")
@click.option("--max-operations", type=click.IntRange(1, 2), default=1, show_default=True)
@click.option("--max-steps", type=click.IntRange(1, 8), default=8, show_default=True)
@click.option("--operators", default=None, help="Unique comma-separated decision and argument expression operations.")
@click.option("--constants", type=_JSON_FILE, help="JSON array of explicit expression constants.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def learn_memory_verified(bundles: Path, trust: Path, tenant: str, allow_tool: tuple[str, ...], domain: Path,
                          max_operations: int, max_steps: int, operators: str | None,
                          constants: Path | None, output: Path) -> None:
    """Infer bounded integer history accumulators from signed observed executions."""
    from ..flow.recipe_lineage import learn_memory_from_verified_bundles

    selected = None if operators is None else [name.strip() for name in operators.split(",")]
    if selected is not None and (any(not name for name in selected) or len(set(selected)) != len(selected)):
        raise click.ClickException("--operators requires unique nonempty comma-separated names")
    try:
        package = learn_memory_from_verified_bundles(
            _read_lineage_json(bundles), trust=_read_json(trust), expected_tenant=tenant, now=time.time(),
            allowed_tools=list(allow_tool), domain=_read_json(domain), max_operations=max_operations,
            operators=selected, constants=None if constants is None else _read_json(constants), max_steps=max_steps,
        )
    except (ValueError, TypeError, PermissionError) as exc:
        raise click.ClickException("verified workflow memory learning refused") from exc
    _write_lineage_json(output, package)
    click.echo("Learned bounded integer history accumulator models; all consistent models remain. "
               "Signatures and commitments verified under the supplied trust policy; live status not checked. "
               "Not governed-admitted, published or executed. Service attestations do not prove business correctness.")


@recipe_group.command("refine-verified")
@click.option("--package", type=_JSON_FILE, required=True)
@click.option("--bundles", type=_JSON_FILE, required=True)
@click.option("--trust", type=_JSON_FILE, required=True)
@click.option("--tenant", required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def refine_verified_recipe(package: Path, bundles: Path, trust: Path, tenant: str, output: Path) -> None:
    """Retain earlier signed evidence while adding independently verified bundles."""
    from ..flow.recipe_lineage import refine_package

    try:
        result = refine_package(_read_lineage_json(package), _read_lineage_json(bundles), trust=_read_json(trust),
                                expected_tenant=tenant, now=time.time())
    except (ValueError, TypeError, PermissionError) as exc:
        raise click.ClickException("verified recipe refinement refused") from exc
    _write_lineage_json(output, result)
    click.echo("Retained signed lineage; live status not checked. This new package requires governed admission.")


@recipe_group.command("draft-verified")
@click.option("--package", type=_JSON_FILE, required=True)
@click.option("--trust", type=_JSON_FILE, required=True)
@click.option("--tenant", required=True)
@click.option("--flow-id", required=True)
@click.option("--name", required=True)
@click.option("--teach-choices", is_flag=True,
              help="Inspect a choice-teaching graph; governed admission remains required for native teaching.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True)
def draft_verified_recipe(package: Path, trust: Path, tenant: str, flow_id: str, name: str,
                          teach_choices: bool, output: Path) -> None:
    """Inspect a verified package as an unsaved draft; governed admission remains separate."""
    from ..flow.action_recipe import MEMORY_SCHEMA
    from ..flow.recipe_flow import make_flow
    from ..flow.recipe_lineage import validate_package

    try:
        snapshot = _read_lineage_json(package)
        validate_package(snapshot, trust=_read_json(trust), expected_tenant=tenant, now=time.time())
        flow = make_flow(snapshot["artifact"], flow_id=flow_id, name=name, teaching=teach_choices)
    except (ValueError, TypeError, PermissionError) as exc:
        raise click.ClickException("verified recipe draft refused") from exc
    if snapshot["artifact"]["schema"] == MEMORY_SCHEMA:
        _write_memory_flow_json(output, flow.to_dict())
    else:
        _write_new_json(output, flow.to_dict())
    click.echo("Unadmitted inspection draft: no trusted governed lineage reference was assigned. "
               "Preserve the original package and use authenticated admission/draft for governed use. "
               "Not saved, published or executed; live status not checked.")


def _write_memory_flow_json(path: Path, value) -> None:
    """Keep the existing native definition bound for larger memory drafts."""
    from ..flow.store import _MAX_FLOW_DEFINITION_BYTES, _assert_safe_definition

    try:
        _assert_safe_definition(value)
        raw = (json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > _MAX_FLOW_DEFINITION_BYTES:
            raise ValueError("memory draft exceeds the native definition limit")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except FileExistsError as exc:
        raise click.ClickException(f"output already exists: {path}; choose a new --output path") from exc
    except (OSError, ValueError, TypeError, RecursionError) as exc:
        raise click.ClickException("cannot write memory draft within the native 1000000-byte definition limit") from exc
    click.echo(f"Wrote {path}")


def _read_lineage_json(path: Path):
    """Lineage packages carry bounded signed bundles in addition to the recipe."""
    from ..flow.recipe_lineage import MAX_PACKAGE_BYTES, _canonical

    try:
        with path.open("rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("expected a regular JSON file")
            raw = stream.read(MAX_PACKAGE_BYTES + 1)
        if len(raw) > MAX_PACKAGE_BYTES:
            raise ValueError("lineage file exceeds its byte limit")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        _canonical(value)
        return value
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException("cannot read bounded lineage JSON") from exc


def _write_lineage_json(path: Path, value) -> None:
    from ..flow.recipe_lineage import MAX_PACKAGE_BYTES, _canonical

    try:
        raw = (_canonical(value) + "\n").encode("utf-8")
        if len(raw) > MAX_PACKAGE_BYTES:
            raise ValueError("lineage output exceeds its byte limit")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except FileExistsError as exc:
        raise click.ClickException(f"output already exists: {path}; choose a new --output path") from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException("cannot write bounded lineage JSON") from exc
    click.echo(f"Wrote {path}")
