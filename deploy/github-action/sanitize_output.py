#!/usr/bin/env python3
"""Sanitize untrusted Lightwork output before it reaches GitHub channels.

The composite action captures the model/agent process privately, then invokes
this helper.  Nothing read from ``--input`` is written to stdout: the caller
decides how to expose the sanitized files while GitHub workflow commands are
disabled.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import json
import math
import os
import re
import runpy
import secrets as random_secrets
import stat
import unicodedata
from pathlib import Path

# Load the adjacent registry by exact path.  A normal import would depend on
# ``sys.path`` even though the public action intentionally invokes this helper
# with ``python -I -S``.  Keeping the registry action-local also avoids pulling
# runtime configuration, plugins, or third-party packages into this boundary.
_REGISTRY = runpy.run_path(
    str(Path(__file__).with_name("secret_env_registry.py"))
)
SECRET_ENV_NAMES = tuple(_REGISTRY["SECRET_ENV_NAMES"])
SECRET_FILE_ENV_NAMES = tuple(_REGISTRY["SECRET_FILE_ENV_NAMES"])
REVIEWED_NON_SECRET_ENV_NAMES = frozenset(
    _REGISTRY["REVIEWED_NON_SECRET_ENV_NAMES"]
)
is_secret_env_name = _REGISTRY["is_secret_env_name"]

_MAX_SECRET_FILE_BYTES = 1024 * 1024
_MAX_SECRET_ENV_VALUE_BYTES = 256 * 1024
_MAX_SECRET_ENV_TOTAL_BYTES = 4 * 1024 * 1024
_MAX_SECRET_ENV_ENTRIES = 2048
# A newline-normalized variant can be almost twice the source file size. Read
# this fixed extra window before sanitizing so an admitted secret file cannot
# straddle the exposed-output boundary and evade exact replacement.
_SECRET_BOUNDARY_OVERLAP_BYTES = _MAX_SECRET_FILE_BYTES * 2
_SECRET_SNAPSHOT_VERSION = 2
_MAX_SECRET_SNAPSHOT_BYTES = (
    4
    * (
        (
            _MAX_SECRET_ENV_TOTAL_BYTES
            + len(SECRET_FILE_ENV_NAMES) * _MAX_SECRET_FILE_BYTES
            + 2
        )
        // 3
    )
    + (_MAX_SECRET_ENV_ENTRIES + len(SECRET_FILE_ENV_NAMES)) * 256
    + 64 * 1024
)

_CREDENTIAL_PATTERNS = (
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b"),
    re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    # Compact JWT/JWS protected headers are base64url JSON and therefore begin
    # with "eyJ". Requiring that prefix plus substantial payload/signature
    # segments avoids treating ordinary dotted versions (1.2.3) as secrets.
    re.compile(
        r"(?<![A-Za-z0-9_-])"
        r"eyJ[A-Za-z0-9_-]{5,}\."
        r"(?:[A-Za-z0-9_-]{8,})?\."
        r"[A-Za-z0-9_-]{16,}"
        r"(?![A-Za-z0-9_-])"
    ),
)
_ANSI_ESCAPE_RE = re.compile(
    r"\x1B(?:"
    r"\[[0-?]*[ -/]*[@-~]"
    r"|\][^\x07\x1B]*(?:\x07|\x1B\\)"
    r"|[@-_]"
    r")"
)
_AUTHORIZATION_RE = re.compile(
    r"(?i)(\bauthorization\s*:\s*(?:bearer|basic)\s+)\S+"
)
_SECRET_ASSIGNMENT_RE = re.compile(
    r"(?i)\b("
    r"api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|"
    r"password|passwd|secret|token"
    r")(\s*[:=]\s*)([\"']?)((?!\[REDACTED_)[^\s,;\"']{4,})([\"']?)"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?"
    r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_UNTERMINATED_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*\Z",
    re.DOTALL,
)
_WORKFLOW_COMMAND_RE = re.compile(r"(?m)^::")


def _read_bounded_regular_file(path_value: str, max_bytes: int) -> bytes | None:
    """Read one regular file through a bounded descriptor, or return ``None``."""
    if not path_value:
        return None
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path_value, flags)
        try:
            file_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_stat.st_mode)
                or file_stat.st_size > max_bytes
            ):
                return None
            remaining = max_bytes + 1
            chunks: list[bytes] = []
            while remaining:
                chunk = os.read(descriptor, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.close(descriptor)
    except (OSError, ValueError):
        return None
    raw = b"".join(chunks)
    if len(raw) > max_bytes:
        return None
    return raw


def _secret_values_from_bytes(raw: bytes) -> set[str]:
    """Return exact and newline-equivalent text forms of one secret file."""
    text = raw.decode("utf-8", errors="ignore")
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    windows_newlines = normalized.replace("\n", "\r\n")
    return {
        value
        for value in (
            text,
            text.strip(),
            normalized,
            normalized.strip(),
            windows_newlines,
            windows_newlines.strip(),
        )
        if len(value) >= 4
    }


def _secret_file_values(path_value: str) -> set[str]:
    """Read one admitted secret file without surfacing path/read errors."""
    if len(path_value) < 4:
        return set()
    raw = _read_bounded_regular_file(path_value, _MAX_SECRET_FILE_BYTES)
    return set() if raw is None else _secret_values_from_bytes(raw)


def _secret_file_blobs_from_environment() -> dict[str, bytes]:
    blobs: dict[str, bytes] = {}
    for name in SECRET_FILE_ENV_NAMES:
        path_value = os.environ.get(name, "")
        if len(path_value) < 4:
            continue
        raw = _read_bounded_regular_file(path_value, _MAX_SECRET_FILE_BYTES)
        if raw is not None and len(raw) >= 4:
            blobs[name] = raw
    return blobs


def _secret_environment_values_from_environment() -> dict[str, str]:
    """Collect bounded values whose names the canonical registry classifies."""
    values: dict[str, str] = {}
    total_bytes = 0
    for name, value in os.environ.items():
        if not is_secret_env_name(name) or len(value) < 4:
            continue
        try:
            raw = value.encode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ValueError(
                "a secret environment value is not valid UTF-8"
            ) from exc
        if len(raw) > _MAX_SECRET_ENV_VALUE_BYTES:
            raise ValueError("a secret environment value exceeds the size cap")
        total_bytes += len(raw)
        if total_bytes > _MAX_SECRET_ENV_TOTAL_BYTES:
            raise ValueError("secret environment values exceed the aggregate cap")
        values[name] = value
        if len(values) > _MAX_SECRET_ENV_ENTRIES:
            raise ValueError("too many secret environment values")
    return values


def _environment_secrets(
    snapshot_values: tuple[str, ...] = (),
    snapshot_blobs: tuple[bytes, ...] = (),
) -> list[str]:
    """Return nontrivial configured secrets, longest first."""
    values = {
        value
        for value in _secret_environment_values_from_environment().values()
        if len(value) >= 4
    }
    for name in SECRET_FILE_ENV_NAMES:
        path_value = os.environ.get(name, "")
        values.update(_secret_file_values(path_value))
    values.update(value for value in snapshot_values if len(value) >= 4)
    for raw in snapshot_blobs:
        values.update(_secret_values_from_bytes(raw))
    return sorted(values, key=len, reverse=True)


def _strip_control_characters(text: str) -> str:
    """Canonicalize controls before any secret or credential matching."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_ESCAPE_RE.sub("", text)
    return "".join(
        character
        if character in {"\n", "\t"}
        or unicodedata.category(character) not in {"Cc", "Cf", "Cs"}
        else ""
        for character in text
    )


def sanitize_text(text: str, *, secrets: list[str] | None = None) -> str:
    """Redact credentials and neutralize GitHub mentions/control characters."""
    # Remove ANSI sequences, NULs, bidi marks, and other prohibited controls
    # before matching. Otherwise they can split a credential during matching
    # and disappear later, leaving a visually/reconstructably intact secret.
    text = _strip_control_characters(text)
    raw_secrets = _environment_secrets() if secrets is None else secrets
    configured_secrets = sorted(
        {
            canonical
            for secret in raw_secrets
            if len(canonical := _strip_control_characters(secret)) >= 4
        },
        key=len,
        reverse=True,
    )
    for secret in configured_secrets:
        text = text.replace(secret, "[REDACTED_SECRET]")
    text = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    # Any BEGIN marker left after complete-key replacement has no matching
    # footer in the captured window. Redact through the tail rather than
    # emitting a key prefix when a producer or our bounded read cuts it short.
    text = _UNTERMINATED_PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", text)
    text = _AUTHORIZATION_RE.sub(r"\1[REDACTED_CREDENTIAL]", text)
    for pattern in _CREDENTIAL_PATTERNS:
        text = pattern.sub("[REDACTED_CREDENTIAL]", text)

    def redact_assignment(match: re.Match[str]) -> str:
        quote = match.group(3)
        closing_quote = match.group(5) if quote == match.group(5) else ""
        return (
            f"{match.group(1)}{match.group(2)}{quote}"
            f"[REDACTED_CREDENTIAL]{closing_quote}"
        )

    text = _SECRET_ASSIGNMENT_RE.sub(redact_assignment, text)
    # Keep the exported result safe if a downstream step later echoes it
    # without using stop-commands. The action also disables command parsing
    # around its own log as a second, independent boundary.
    text = _WORKFLOW_COMMAND_RE.sub("\N{FULLWIDTH COLON}:", text)
    # Result output is commonly posted to issues or pull requests. Prevent an
    # untrusted model response from notifying users or teams.
    return text.replace("@", "\N{FULLWIDTH COMMERCIAL AT}")


def _read_bounded(
    path: Path,
    max_chars: int,
    *,
    secret_overlap_bytes: int,
) -> tuple[str, bool]:
    """Read the output window plus bounded overlap before secret replacement."""
    byte_limit = (max_chars * 4) + secret_overlap_bytes
    with path.open("rb") as stream:
        raw = stream.read(byte_limit + 1)
    source_truncated = len(raw) > byte_limit
    if source_truncated:
        raw = raw[:byte_limit]
    return raw.decode("utf-8", errors="replace"), source_truncated


def _bound_text(text: str, max_chars: int, source_truncated: bool) -> str:
    marker = (
        "\n\n[Lightwork output truncated; additional captured output was "
        "discarded.]\n"
    )
    needs_truncation = source_truncated or len(text) > max_chars
    if needs_truncation:
        keep = max(0, max_chars - len(marker))
        return text[:keep].rstrip("\n") + marker
    if not text.endswith("\n"):
        text += "\n"
    return text


def _write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(0o600)


def _write_secret_file_snapshot(path: Path) -> None:
    """Persist bounded pre-run environment values and secret-file bytes."""
    environment = _secret_environment_values_from_environment()
    blobs = _secret_file_blobs_from_environment()
    payload = {
        "version": _SECRET_SNAPSHOT_VERSION,
        "environment": [
            {
                "name": name,
                "value": base64.b64encode(value.encode("utf-8")).decode("ascii"),
            }
            for name, value in sorted(environment.items())
        ],
        "files": [
            {
                "name": name,
                "value": base64.b64encode(raw).decode("ascii"),
            }
            for name, raw in sorted(blobs.items())
        ],
    }
    _write_private(
        path,
        json.dumps(payload, ensure_ascii=True, separators=(",", ":")),
    )


def _load_secret_file_snapshot(
    path: Path,
) -> tuple[tuple[str, ...], tuple[bytes, ...]]:
    """Load and strictly validate the private pre-run secret snapshot."""
    raw = _read_bounded_regular_file(str(path), _MAX_SECRET_SNAPSHOT_BYTES)
    if raw is None:
        raise ValueError("snapshot is missing, non-regular, or oversized")
    try:
        payload = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("snapshot is not valid UTF-8 JSON") from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"version", "environment", "files"}
        or payload.get("version") != _SECRET_SNAPSHOT_VERSION
        or not isinstance(payload.get("environment"), list)
        or not isinstance(payload.get("files"), list)
        or len(payload["environment"]) > _MAX_SECRET_ENV_ENTRIES
        or len(payload["files"]) > len(SECRET_FILE_ENV_NAMES)
    ):
        raise ValueError("snapshot schema or version is invalid")

    environment_values: list[str] = []
    environment_bytes = 0
    seen_environment: set[str] = set()
    for entry in payload["environment"]:
        if not isinstance(entry, dict) or set(entry) != {"name", "value"}:
            raise ValueError("snapshot environment entry is invalid")
        name = entry["name"]
        encoded = entry["value"]
        if (
            not isinstance(name, str)
            or not 1 <= len(name) <= 255
            or not is_secret_env_name(name)
            or name in seen_environment
            or not isinstance(encoded, str)
        ):
            raise ValueError("snapshot environment entry is untrusted")
        try:
            value_bytes = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError(
                "snapshot environment entry is not valid base64"
            ) from exc
        if not 4 <= len(value_bytes) <= _MAX_SECRET_ENV_VALUE_BYTES:
            raise ValueError("snapshot environment entry has an invalid size")
        environment_bytes += len(value_bytes)
        if environment_bytes > _MAX_SECRET_ENV_TOTAL_BYTES:
            raise ValueError("snapshot environment entries exceed the size cap")
        try:
            value = value_bytes.decode("utf-8", errors="strict")
        except UnicodeError as exc:
            raise ValueError(
                "snapshot environment entry is not valid UTF-8"
            ) from exc
        seen_environment.add(name)
        environment_values.append(value)

    blobs: list[bytes] = []
    seen_files: set[str] = set()
    for entry in payload["files"]:
        if not isinstance(entry, dict) or set(entry) != {"name", "value"}:
            raise ValueError("snapshot file entry is invalid")
        name = entry["name"]
        encoded = entry["value"]
        if (
            not isinstance(name, str)
            or name not in SECRET_FILE_ENV_NAMES
            or name in seen_files
            or not isinstance(encoded, str)
        ):
            raise ValueError("snapshot file entry is untrusted")
        try:
            blob = base64.b64decode(encoded, validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("snapshot file entry is not valid base64") from exc
        if not 4 <= len(blob) <= _MAX_SECRET_FILE_BYTES:
            raise ValueError("snapshot file entry has an invalid size")
        seen_files.add(name)
        blobs.append(blob)
    return tuple(environment_values), tuple(blobs)


def sanitize_files(
    input_path: Path,
    output_path: Path,
    summary_path: Path,
    *,
    max_chars: int,
    secret_file_snapshot: Path | None = None,
    run_result: Path | None = None,
    deliverable: Path | None = None,
    github_output: Path | None = None,
    result_key: Path | None = None,
) -> None:
    snapshot_values: tuple[str, ...] = ()
    snapshot_blobs: tuple[bytes, ...] = ()
    if secret_file_snapshot is not None:
        snapshot_values, snapshot_blobs = _load_secret_file_snapshot(
            secret_file_snapshot
        )
    secrets = _environment_secrets(snapshot_values, snapshot_blobs)
    native = _load_run_result(run_result, result_key) if run_result is not None else None
    if native is not None and native["release_status"] != "released":
        # Runtime logs can contain a retained draft or private source bytes.
        # An unsuccessful/held run publishes only fixed native status facts.
        raw_text = f"Task status: {native['status']}. Output release: {native['release_status']}."
        source_truncated = False
    else:
        raw_text, source_truncated = _read_bounded(
            input_path, max_chars, secret_overlap_bytes=_SECRET_BOUNDARY_OVERLAP_BYTES,
        )
    sanitized = _bound_text(
        sanitize_text(raw_text, secrets=secrets),
        max_chars=max_chars,
        source_truncated=source_truncated,
    )
    _write_private(output_path, sanitized)
    _write_private(
        summary_path,
        f"<pre>\n{html.escape(sanitized, quote=False)}</pre>\n",
    )
    if native is not None:
        path = ""
        if native["release_status"] == "released":
            answer = _bound_text(sanitize_text(native["answer"], secrets=secrets), max_chars, False)
            _write_private(deliverable, answer)
            path = str(deliverable)
        values = {"goal-id": str(native["goal_id"]) if native["goal_id"] is not None else "",
                  "status": native["status"],
                  "spend-recorded-usd": format(native["spend_recorded_usd"], ".12g") if native["spend_recorded_usd"] is not None else "",
                  "release-status": native["release_status"], "deliverable-file": path}
        if any(any(ord(char) < 32 or ord(char) == 127 for char in value) for value in values.values()):
            raise ValueError("structured output paths must fit one ordinary line")
        with github_output.open("a", encoding="utf-8", newline="\n") as stream:
            for name, value in values.items():
                stream.write(f"{name}={value}\n")


def _unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate native result property")
        result[name] = value
    return result


def _load_run_result(path: Path, key_path: Path) -> dict:
    """Validate private CLI facts; never trust a log or model-authored envelope."""
    if not os.path.lexists(path):
        # Preflight refusal/interruption before goal/result admission. Unknown
        # spending is not silently represented as zero or a complete invoice.
        return {"goal_id": None, "status": "unavailable", "spend_recorded_usd": None,
                "release_status": "unavailable", "answer": None}
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
        raise ValueError("native result must be a regular private file")
    raw = _read_bounded_regular_file(str(path), 32 * 1024 * 1024)
    if raw is None:
        raise ValueError("native result is unavailable or exceeds 32 MiB")
    result = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=_unique_object)
    if not isinstance(result, dict) or set(result) != {"schema", "goal_id", "status", "spend_recorded_usd", "release_status", "answer", "signature"}:
        raise ValueError("native result has an unsupported schema")
    key = _read_bounded_regular_file(str(key_path), 32)
    signature = result.pop("signature")
    if key is None or len(key) != 32 or not isinstance(signature, str) or not re.fullmatch(r"[a-f0-9]{64}", signature):
        raise ValueError("native result origin is unavailable")
    encoded = json.dumps(result, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not hmac.compare_digest(signature, hmac.new(key, encoded, hashlib.sha256).hexdigest()):
        raise ValueError("native result does not belong to this action run")
    if result["schema"] != "lightwork.cli-run-result.v1" or type(result["goal_id"]) is not int or not 1 <= result["goal_id"] < 2**63:
        raise ValueError("native result identity is invalid")
    if not isinstance(result["status"], str) or result["status"] not in {"pending", "draft", "active", "running", "blocked", "done", "failed", "cancelled", "paused", "waiting", "unavailable"}:
        raise ValueError("native task status is invalid")
    amount = result["spend_recorded_usd"]
    if type(amount) not in {int, float} or amount < 0 or amount > 1e18 or not math.isfinite(amount):
        raise ValueError("native recorded spending is invalid")
    if not isinstance(result["release_status"], str) or result["release_status"] not in {"released", "not_completed", "pending_signoff", "policy_unavailable"}:
        raise ValueError("native output release is invalid")
    if result["release_status"] == "released":
        if result["status"] != "done" or not isinstance(result["answer"], str):
            raise ValueError("only a completed released answer is available")
    elif result["answer"] is not None:
        raise ValueError("unreleased native results must not contain answer bytes")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--max-chars", type=int, default=50_000)
    parser.add_argument("--write-secret-file-snapshot", type=Path)
    parser.add_argument("--secret-file-snapshot", type=Path)
    parser.add_argument("--run-result", type=Path)
    parser.add_argument("--deliverable", type=Path)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--result-key", type=Path)
    parser.add_argument("--write-result-key", type=Path)
    parser.add_argument("--workspace-root", type=Path)
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.write_result_key is not None:
        if any(value is not None for value in (args.input, args.output, args.summary, args.write_secret_file_snapshot, args.secret_file_snapshot, args.run_result, args.deliverable, args.github_output, args.result_key)):
            raise SystemExit("--write-result-key cannot be combined with capture arguments")
        if args.workspace_root is not None and args.write_result_key.parent.resolve().is_relative_to(args.workspace_root.resolve()):
            raise SystemExit("private action capture must be outside the container workspace")
        with os.fdopen(os.open(str(args.write_result_key), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600), "wb") as stream:
            stream.write(random_secrets.token_bytes(32))
        return 0
    if args.write_secret_file_snapshot is not None:
        if any(
            value is not None
            for value in (
                args.input,
                args.output,
                args.summary,
                args.secret_file_snapshot,
                args.run_result,
                args.deliverable,
                args.github_output,
                args.result_key,
                args.workspace_root,
            )
        ):
            raise SystemExit(
                "--write-secret-file-snapshot cannot be combined with "
                "sanitization arguments"
            )
        try:
            _write_secret_file_snapshot(args.write_secret_file_snapshot)
        except ValueError as exc:
            raise SystemExit(
                f"secret snapshot creation failed: {exc}"
            ) from exc
        return 0
    missing = [
        flag
        for flag, value in (
            ("--input", args.input),
            ("--output", args.output),
            ("--summary", args.summary),
        )
        if value is None
    ]
    if missing:
        raise SystemExit(f"missing required arguments: {', '.join(missing)}")
    if args.workspace_root is not None:
        raise SystemExit("--workspace-root is valid only with --write-result-key")
    if args.max_chars < 256:
        raise SystemExit("--max-chars must be at least 256")
    structured = (args.run_result, args.deliverable, args.github_output, args.result_key)
    if any(value is not None for value in structured) and not all(value is not None for value in structured):
        raise SystemExit("--run-result, --deliverable, --github-output and --result-key must be supplied together")
    try:
        sanitize_files(
            args.input,
            args.output,
            args.summary,
            max_chars=args.max_chars,
            secret_file_snapshot=args.secret_file_snapshot,
            run_result=args.run_result, deliverable=args.deliverable, github_output=args.github_output,
            result_key=args.result_key,
        )
    except ValueError as exc:
        raise SystemExit(f"private capture validation failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
