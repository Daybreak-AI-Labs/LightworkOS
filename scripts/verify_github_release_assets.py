#!/usr/bin/env python3
"""Verify the exact byte inventory of a Lightwork GitHub release."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping
from pathlib import Path, PurePosixPath
from urllib.parse import unquote, urlparse

# ``python -I`` deliberately omits both the current directory and the script
# directory from sys.path.  Release workflows execute this verifier in isolated
# mode, so add only its trusted, checked-out sibling directory before importing
# the canonical tag parser.
_SCRIPT_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPT_DIR))
from release_version import validate_tag  # noqa: E402

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_REVISION_RE = re.compile(r"[0-9a-f]{40}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def require_digest_matching_subset(
    existing: Mapping[str, str],
    expected: Mapping[str, str],
    *,
    label: str,
) -> list[str]:
    """Allow an exact published subset while rejecting extras and conflicts."""
    unexpected = sorted(set(existing) - set(expected))
    conflicting = {
        filename: {
            "existing": existing[filename],
            "expected": expected[filename],
        }
        for filename in sorted(set(existing) & set(expected))
        if existing[filename] != expected[filename]
    }
    if unexpected or conflicting:
        raise ValueError(
            f"{label} differs from this build: "
            f"unexpected={unexpected}, conflicting={conflicting}"
        )
    return sorted(set(expected) - set(existing))


def require_matching_pypi_sdist(
    payload: Mapping[str, object],
    *,
    version: str,
    expected_filename: str,
    expected_sha256: str,
) -> tuple[str, str]:
    """Return the exact signed sdist URL/digest or reject PyPI metadata drift."""
    if (
        PurePosixPath(expected_filename).name != expected_filename
        or _DIGEST_RE.fullmatch(expected_sha256) is None
    ):
        raise ValueError("signed sdist authority is malformed")

    info = payload.get("info")
    urls = payload.get("urls")
    if not isinstance(info, Mapping) or not isinstance(urls, list):
        raise ValueError("PyPI metadata is malformed")
    project = info.get("name")
    published_version = info.get("version")
    if (
        not isinstance(project, str)
        or re.sub(r"[-_.]+", "-", project).casefold() != "maverick-agent"
    ):
        raise ValueError("PyPI metadata returned a different project")
    if published_version != version:
        raise ValueError("PyPI metadata returned a different version")

    sdists = [
        item
        for item in urls
        if isinstance(item, Mapping) and item.get("packagetype") == "sdist"
    ]
    if len(sdists) != 1:
        raise ValueError(f"expected one published sdist, found {len(sdists)}")
    sdist = sdists[0]
    url = sdist.get("url")
    digests = sdist.get("digests")
    actual_filename = sdist.get("filename")
    if not isinstance(url, str) or not isinstance(digests, Mapping):
        raise ValueError("PyPI returned malformed sdist metadata")
    sha256 = digests.get("sha256")
    if not isinstance(sha256, str):
        raise ValueError("PyPI returned malformed sdist metadata")

    try:
        parsed_url = urlparse(url)
        explicit_port = parsed_url.port
    except ValueError as exc:
        raise ValueError("PyPI returned an unsafe sdist URL or digest") from exc
    if (
        parsed_url.scheme != "https"
        or parsed_url.hostname != "files.pythonhosted.org"
        or parsed_url.username is not None
        or parsed_url.password is not None
        or explicit_port is not None
        or parsed_url.query
        or parsed_url.fragment
        or any(ord(character) < 32 or ord(character) == 127 for character in url)
        or '"' in url
        or _DIGEST_RE.fullmatch(sha256) is None
    ):
        raise ValueError("PyPI returned an unsafe sdist URL or digest")
    path_filename = unquote(PurePosixPath(parsed_url.path).name)
    if (
        actual_filename != expected_filename
        or path_filename != expected_filename
        or sha256 != expected_sha256
    ):
        raise ValueError("PyPI sdist differs from the signed exact-release authority")
    return url, sha256


def _checksum_records(path: Path) -> dict[str, str]:
    records: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        digest, separator, name = line.partition("  ")
        if (
            not separator
            or _DIGEST_RE.fullmatch(digest) is None
            or PurePosixPath(name).name != name
            or name in records
        ):
            raise ValueError(f"invalid checksum entry: {line!r}")
        records[name] = digest
    if not records:
        raise ValueError(f"empty checksum file: {path.name}")
    return records


def _verify_records(root: Path, records: dict[str, str], label: str) -> None:
    for name, expected in records.items():
        target = root / name
        if not target.is_file():
            raise ValueError(f"{label} is missing {name}")
        actual = _sha256(target)
        if actual != expected:
            raise ValueError(
                f"{label} digest mismatch for {name}: {actual} != {expected}"
            )


def _python_records(
    root: Path,
    manifest_path: Path,
    *,
    revision: str,
    version: str,
    cohort_path: Path,
) -> dict[str, str]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if set(manifest) != {
        "schema_version",
        "source_revision",
        "version",
        "artifacts",
    }:
        raise ValueError("Python release manifest has unexpected fields")
    if manifest["schema_version"] != 1:
        raise ValueError("unsupported Python release-manifest schema")
    if manifest["source_revision"] != revision:
        raise ValueError("Python evidence is bound to a different revision")
    if manifest["version"] != version:
        raise ValueError("Python evidence version differs from the release tag")

    cohort = tomllib.loads(cohort_path.read_text(encoding="utf-8"))
    expected_distributions = {
        item["distribution"] for item in cohort.get("packages", [])
    }
    if cohort.get("version") != version or len(expected_distributions) != 8:
        raise ValueError("release cohort does not match this release")

    records: dict[str, str] = {}
    kinds = {
        distribution: {"wheel": 0, "sdist": 0}
        for distribution in expected_distributions
    }
    expected_keys = {
        "distribution",
        "filename",
        "kind",
        "publish_prefix",
        "sha256",
        "version",
    }
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 16:
        raise ValueError("Python evidence must describe exactly 16 artifacts")
    for item in artifacts:
        if not isinstance(item, dict) or set(item) != expected_keys:
            raise ValueError("Python artifact record has unexpected fields")
        name = item["filename"]
        distribution = item["distribution"]
        kind = item["kind"]
        digest = item["sha256"]
        if (
            not isinstance(name, str)
            or PurePosixPath(name).name != name
            or name in records
            or distribution not in expected_distributions
            or kind not in {"wheel", "sdist"}
            or _DIGEST_RE.fullmatch(str(digest)) is None
            or item["version"] != version
        ):
            raise ValueError(f"invalid Python artifact record: {item!r}")
        kinds[distribution][kind] += 1
        records[name] = digest
    if any(counts != {"wheel": 1, "sdist": 1} for counts in kinds.values()):
        raise ValueError("Python cohort needs one wheel and one sdist per package")
    _verify_records(root, records, "Python release artifacts")
    return records


def verify_release_assets(
    *,
    root: Path,
    metadata_path: Path,
    tag: str,
    revision: str,
    expected_state: str,
    cohort_path: Path,
) -> dict[str, int | str]:
    """Verify metadata, checksums, manifests, and the exact asset-name set."""
    release = validate_tag(tag)
    if _REVISION_RE.fullmatch(revision) is None:
        raise ValueError("release revision must be a full lowercase commit SHA")
    if expected_state not in {"draft", "published"}:
        raise ValueError("expected state must be draft or published")
    if not root.is_dir():
        raise ValueError("release asset root is missing")

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if metadata.get("tagName") != tag:
        raise ValueError("exact-tag release metadata mismatch")
    if not isinstance(metadata.get("isDraft"), bool) or not isinstance(
        metadata.get("isPrerelease"),
        bool,
    ):
        raise ValueError("release metadata has invalid state fields")
    actual_state = "draft" if metadata["isDraft"] else "published"
    if actual_state != expected_state:
        raise ValueError(
            f"release is {actual_state}, expected {expected_state}"
        )
    if metadata.get("isPrerelease") is not release.prerelease:
        raise ValueError("release prerelease state differs from its tag")
    metadata_assets = metadata.get("assets")
    if not isinstance(metadata_assets, list) or any(
        not isinstance(item, dict) or not isinstance(item.get("name"), str)
        for item in metadata_assets
    ):
        raise ValueError("release metadata has no valid asset inventory")
    metadata_names = [item["name"] for item in metadata_assets]
    if len(metadata_names) != len(set(metadata_names)):
        raise ValueError("release metadata contains duplicate asset names")

    actual_assets = {
        path.name for path in root.iterdir() if path.is_file()
    }
    if actual_assets != set(metadata_names):
        raise ValueError("downloaded assets differ from release metadata")

    release_checksum = root / f"maverick-release-{tag}.sha256"
    if not release_checksum.is_file():
        raise ValueError("release checksum manifest is missing")
    upstream_records = _checksum_records(release_checksum)
    _verify_records(root, upstream_records, "release artifacts")
    expected_upstream = {
        "maverick-linux-x86_64",
        "maverick-macos-arm64",
        "maverick-windows-x86_64.exe",
        f"maverick-container-{tag}.json",
        f"maverick-sbom-{tag}.cdx.json",
    }
    if set(upstream_records) != expected_upstream:
        raise ValueError(
            "release checksum inventory is not the exact upstream cohort: "
            f"missing={sorted(expected_upstream - set(upstream_records))}, "
            f"extra={sorted(set(upstream_records) - expected_upstream)}"
        )

    python_manifest = root / "release-manifest.json"
    python_sums = root / "SHA256SUMS"
    if not python_manifest.is_file() or not python_sums.is_file():
        raise ValueError("signed Python evidence is missing")
    python_records = _python_records(
        root,
        python_manifest,
        revision=revision,
        version=release.version,
        cohort_path=cohort_path,
    )
    if _checksum_records(python_sums) != python_records:
        raise ValueError("Python checksum file and release manifest disagree")

    upstream_signed = set(upstream_records) | {release_checksum.name}
    expected_assets = upstream_signed | {
        f"{name}{suffix}"
        for name in upstream_signed
        for suffix in (".sig", ".pem")
    }
    python_signed = set(python_records) | {
        python_sums.name,
        python_manifest.name,
    }
    expected_assets |= python_signed | {
        f"{name}.cosign.bundle" for name in python_signed
    }
    if actual_assets != expected_assets:
        raise ValueError(
            "release asset inventory differs from the signed state: "
            f"missing={sorted(expected_assets - actual_assets)}, "
            f"extra={sorted(actual_assets - expected_assets)}"
        )
    return {
        "asset_count": len(actual_assets),
        "python_artifact_count": len(python_records),
        "state": actual_state,
        "upstream_artifact_count": len(upstream_records),
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asset-root", required=True, type=Path)
    parser.add_argument("--metadata", required=True, type=Path)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument(
        "--expected-state",
        required=True,
        choices=("draft", "published"),
    )
    parser.add_argument(
        "--cohort",
        type=Path,
        default=Path("release-cohort.toml"),
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        summary = verify_release_assets(
            root=args.asset_root,
            metadata_path=args.metadata,
            tag=args.tag,
            revision=args.revision,
            expected_state=args.expected_state,
            cohort_path=args.cohort,
        )
    except (OSError, ValueError, json.JSONDecodeError, KeyError, TypeError) as exc:
        raise SystemExit(str(exc)) from exc
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
