#!/usr/bin/env python3
"""Validate Lightwork's canonical public release versions.

Public tags deliberately use one strict, three-component PEP 440 subset. This
keeps the GitHub prerelease flag, PyPI artifact versions, GHCR aliases, and the
Homebrew formula on one spelling instead of letting each workflow normalize a
different tag.
"""

from __future__ import annotations

import argparse
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

_VERSION_RE = re.compile(
    r"(?P<major>0|[1-9][0-9]*)\."
    r"(?P<minor>0|[1-9][0-9]*)\."
    r"(?P<patch>0|[1-9][0-9]*)"
    r"(?:(?P<pre>a|b|rc)(?P<pre_number>0|[1-9][0-9]*))?"
    r"(?:\.post(?P<post_number>0|[1-9][0-9]*))?"
    r"(?:\.dev(?P<dev_number>0|[1-9][0-9]*))?"
)


@dataclass(frozen=True)
class ReleaseVersion:
    tag: str
    version: str
    prerelease: bool


def validate_version(value: str) -> ReleaseVersion:
    """Return canonical release metadata or reject an ambiguous spelling."""
    version = value.strip()
    match = _VERSION_RE.fullmatch(version)
    if match is None:
        raise ValueError(
            "release version must be canonical "
            "MAJOR.MINOR.PATCH[rcN|aN|bN][.postN][.devN]"
        )
    prerelease = bool(match.group("pre") or match.group("dev_number"))
    return ReleaseVersion(
        tag=f"v{version}",
        version=version,
        prerelease=prerelease,
    )


def validate_tag(value: str) -> ReleaseVersion:
    """Validate a canonical ``v``-prefixed release tag."""
    tag = value.strip()
    if not tag.startswith("v"):
        raise ValueError("release tag must start with v")
    result = validate_version(tag[1:])
    if result.tag != tag:
        raise ValueError("release tag is not canonical")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--tag")
    source.add_argument("--version")
    parser.add_argument(
        "--github-output",
        type=Path,
        help="Append tag/version/prerelease fields to a GitHub output file.",
    )
    return parser


def main() -> int:
    args = _parser().parse_args()
    try:
        result = (
            validate_tag(args.tag)
            if args.tag is not None
            else validate_version(args.version)
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    if args.github_output is not None:
        with args.github_output.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(f"tag={result.tag}\n")
            stream.write(f"version={result.version}\n")
            stream.write(f"prerelease={str(result.prerelease).lower()}\n")
    print(json.dumps(asdict(result), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
