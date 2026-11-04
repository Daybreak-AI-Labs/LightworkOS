"""File-only authoring and inspection for bounded learned pure operators."""
from __future__ import annotations

import json
import math
import os
import stat
from dataclasses import asdict
from pathlib import Path

import click

from . import main

_MAX_JSON_BYTES = 262_144
_JSON_FILE = click.Path(exists=True, dir_okay=False, path_type=Path)


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    out: dict = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key: {key!r}")
        out[key] = value
    return out


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number: {value}")


def _read_json(path: Path):
    """Read one bounded regular file, rejecting ambiguous/nonstandard JSON."""
    try:
        with path.open("rb") as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("expected a regular JSON file")
            raw = stream.read(_MAX_JSON_BYTES + 1)
        if len(raw) > _MAX_JSON_BYTES:
            raise ValueError(f"JSON file exceeds {_MAX_JSON_BYTES} bytes")
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                           parse_constant=_reject_constant)
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 40:
                raise ValueError("JSON nesting exceeds 40 levels")
            if isinstance(item, float) and not math.isfinite(item):
                raise ValueError("non-finite JSON number")
            if isinstance(item, dict):
                pending.extend((v, depth + 1) for v in item.values())
            elif isinstance(item, list):
                pending.extend((v, depth + 1) for v in item)
        return value
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(f"cannot read {path}: {exc}") from exc


def _write_new_json(path: Path, value) -> None:
    """Create an explicitly named output; never replace an existing file."""
    try:
        raw = (json.dumps(value, ensure_ascii=False, allow_nan=False,
                          separators=(",", ":")) + "\n").encode("utf-8")
        if len(raw) > _MAX_JSON_BYTES:
            raise ValueError(f"output exceeds {_MAX_JSON_BYTES} bytes")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    except FileExistsError as exc:
        raise click.ClickException(
            f"output already exists: {path}; choose a new --output path"
        ) from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise click.ClickException(f"cannot write {path}: {exc}") from exc
    click.echo(f"Wrote {path}")


@main.group("flow")
def flow_group() -> None:
    """Author flow drafts. These commands do not publish or execute a flow."""


@flow_group.group("operator")
def operator_group() -> None:
    """Learn bounded pure expressions from reviewed scalar input/output examples.

    Files are UTF-8 JSON, at most 262144 bytes, with unique object keys.
    Artifacts contain the raw examples: keep them within their tenant's access
    boundary. Agreement is not proof of correctness or authorization for actions.
    """


@operator_group.command("learn")
@click.option("--spec", "spec_path", type=_JSON_FILE, required=True,
              help="Declared scalar input types/bounds, output type and constants.")
@click.option("--examples", "examples_path", type=_JSON_FILE, required=True,
              help="Array of reviewed {inputs: {...}, output: scalar} records.")
@click.option("--reviewed", is_flag=True,
              help="Confirm you reviewed the supplied input/output examples.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True,
              help="New artifact file; existing files are never overwritten.")
def learn(spec_path: Path, examples_path: Path, reviewed: bool, output: Path) -> None:
    """Retain every expression in the fixed grammar matching supplied examples."""
    from ..flow.learned_operator import synthesize
    from ..flow.operator_artifacts import candidate_count

    if not reviewed:
        raise click.ClickException("review the examples, then pass --reviewed")
    try:
        artifact = synthesize(_read_json(spec_path), _read_json(examples_path))
    except (ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    _write_new_json(output, artifact)
    click.echo(f"Retained {candidate_count(artifact)} candidate expressions. "
               "This records supplied examples, not verified correctness.")


@operator_group.command("learn-composed")
@click.option("--spec", "spec_path", type=_JSON_FILE, required=True,
              help="Declared scalar input types/bounds, output type and constants.")
@click.option("--examples", "examples_path", type=_JSON_FILE, required=True,
              help="Reviewed end-to-end {inputs: {...}, output: scalar} records.")
@click.option("--max-operations", default=3, type=click.IntRange(1, 4), show_default=True,
              help="Maximum operator applications in each composed expression.")
@click.option("--operators", default=None,
              help="Comma-separated allowed operator names; omitted uses engine defaults.")
@click.option("--reviewed", is_flag=True,
              help="Confirm you reviewed the supplied input/output examples.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True,
              help="New packed artifact file; existing files are never overwritten.")
def learn_composed(spec_path: Path, examples_path: Path, max_operations: int,
                   operators: str | None, reviewed: bool, output: Path) -> None:
    """Infer bounded composed expressions without intermediate example labels."""
    from ..flow.composed_operator import synthesize
    from ..flow.operator_artifacts import candidate_count

    if not reviewed:
        raise click.ClickException("review the examples, then pass --reviewed")
    selected = None if operators is None else [name.strip() for name in operators.split(",")]
    if selected is not None and (any(not name for name in selected)
                                 or len(set(selected)) != len(selected)):
        raise click.ClickException("--operators requires unique nonempty comma-separated names")
    try:
        artifact = synthesize(_read_json(spec_path), _read_json(examples_path),
                              max_operations=max_operations, operators=selected)
    except (ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    _write_new_json(output, artifact)
    click.echo(f"Retained {candidate_count(artifact)} composed candidate expressions. "
               "This records supplied examples, not verified correctness.")


@operator_group.command("evaluate")
@click.option("--artifact", "artifact_path", type=_JSON_FILE, required=True)
@click.option("--input", "input_path", type=_JSON_FILE, required=True,
              help="Raw input object; declared fields must meet their types/bounds.")
def evaluate_operator(artifact_path: Path, input_path: Path) -> None:
    """Print a JSON decision without running the fallback agent or any tools."""
    from ..flow.operator_artifacts import evaluate, validate_artifact

    artifact = _read_json(artifact_path)
    data = _read_json(input_path)
    if not isinstance(data, dict):
        raise click.ClickException("input JSON must be an object")
    try:
        validate_artifact(artifact)
        decision = evaluate(artifact, data)
    except (ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    click.echo(json.dumps(asdict(decision), ensure_ascii=False, allow_nan=False))


@operator_group.command("refine")
@click.option("--artifact", "artifact_path", type=_JSON_FILE, required=True)
@click.option("--examples", "examples_path", type=_JSON_FILE, required=True,
              help="Additional reviewed examples; previous examples are retained.")
@click.option("--reviewed", is_flag=True,
              help="Confirm you reviewed the additional input/output examples.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True,
              help="New artifact file; the original artifact stays unchanged.")
def refine_operator(artifact_path: Path, examples_path: Path,
                    reviewed: bool, output: Path) -> None:
    """Rebuild with additional examples, retaining previous evidence."""
    from ..flow.operator_artifacts import candidate_count, refine

    if not reviewed:
        raise click.ClickException("review the additional examples, then pass --reviewed")
    try:
        artifact = refine(_read_json(artifact_path), _read_json(examples_path))
    except (ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    _write_new_json(output, artifact)
    click.echo(f"Retained {candidate_count(artifact)} candidate expressions "
               f"from {artifact['example_count']} supplied examples. "
               "Review and reattach the new artifact before publication.")


@operator_group.command("question")
@click.option("--artifact", "artifact_path", type=_JSON_FILE, required=True)
@click.option("--max-probes", default=256, type=click.IntRange(1, 4096), show_default=True,
              help="Bounded search budget; the engine also enforces a hard maximum.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True,
              help="New question JSON file; existing files are never overwritten.")
def question_operator(artifact_path: Path, max_probes: int, output: Path) -> None:
    """Find an input on which retained expressions disagree, without labeling it.

    search_exhausted means no witness was found within the search budget.
    Only a complete supported finite-domain census can establish equivalence.
    """
    from ..flow.operator_queries import propose_question

    try:
        question = propose_question(_read_json(artifact_path), max_probes=max_probes)
    except (ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    _write_new_json(output, question)
    click.echo(f"Question status: {question['status']}. "
               "A proposed input is not a verified label or an execution approval.")


@operator_group.command("answer")
@click.option("--artifact", "artifact_path", type=_JSON_FILE, required=True)
@click.option("--question", "question_path", type=_JSON_FILE, required=True)
@click.option("--answer", "answer_path", type=_JSON_FILE, required=True,
              help="One reviewed JSON scalar (integer, string or boolean).")
@click.option("--reviewed", is_flag=True,
              help="State that you reviewed the label; does not authenticate a reviewer.")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True,
              help="New refined artifact; original artifact and question stay unchanged.")
def answer_operator(artifact_path: Path, question_path: Path, answer_path: Path,
                    reviewed: bool, output: Path) -> None:
    """Validate an exact artifact-bound question and add your reviewed answer.

    Local file authoring does not authenticate who supplied the label or publish
    a flow. Use the authenticated review service for attributed review records.
    """
    from ..flow.operator_queries import answer_question, validate_question

    if not reviewed:
        raise click.ClickException("review the answer, then pass --reviewed")
    answer = _read_json(answer_path)
    if type(answer) not in (str, int, bool):
        raise click.ClickException("answer must be one JSON integer, string or boolean")
    try:
        artifact = _read_json(artifact_path)
        question = _read_json(question_path)
        validate_question(artifact, question)
        refined = answer_question(artifact, question, answer)
    except (ValueError, TypeError) as exc:
        raise click.ClickException(str(exc)) from exc
    _write_new_json(output, refined)
    click.echo("Saved a refined artifact from your supplied label. "
               "No authenticated reviewer identity or publication is implied.")


def _change_draft(flow_path: Path, node_id: str, output: Path,
                  artifact_path: Path | None) -> None:
    from ..flow.evolve import attach_learned_operator, remove_learned_operator
    from ..flow.ir import Flow

    raw = _read_json(flow_path)
    if not isinstance(raw, dict):
        raise click.ClickException("flow JSON must be an object")
    try:
        nodes = raw.get("nodes")
        if not isinstance(nodes, list) or any(not isinstance(n, dict) for n in nodes):
            raise ValueError("flow nodes must be an array of objects")
        ids = [n.get("id") for n in nodes]
        if any(not isinstance(nid, str) or not nid for nid in ids) or len(set(ids)) != len(ids):
            raise ValueError("flow node IDs must be unique nonempty strings")
        flow = Flow.from_dict(raw)
        if artifact_path is None:
            draft = remove_learned_operator(flow, node_id)
        else:
            draft = attach_learned_operator(flow, node_id, _read_json(artifact_path))
        _write_new_json(output, draft.to_dict())
    except (KeyError, ValueError, TypeError, AttributeError) as exc:
        raise click.ClickException(f"invalid flow draft or operator: {exc}") from exc
    click.echo("Draft only: review and publish through the normal flow controls.")


@operator_group.command("attach")
@click.argument("flow_path", type=_JSON_FILE)
@click.argument("node_id")
@click.option("--artifact", "artifact_path", type=_JSON_FILE, required=True)
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True,
              help="New flow draft JSON; source and published flows stay unchanged.")
def attach(flow_path: Path, node_id: str, artifact_path: Path, output: Path) -> None:
    """Attach to an agent node with a brief and output, retaining its fallback."""
    _change_draft(flow_path, node_id, output, artifact_path)


@operator_group.command("remove")
@click.argument("flow_path", type=_JSON_FILE)
@click.argument("node_id")
@click.option("--output", type=click.Path(dir_okay=False, path_type=Path), required=True,
              help="New flow draft JSON; existing files are never overwritten.")
def remove(flow_path: Path, node_id: str, output: Path) -> None:
    """Remove an attachment in a new draft, keeping the original agent node."""
    _change_draft(flow_path, node_id, output, None)
