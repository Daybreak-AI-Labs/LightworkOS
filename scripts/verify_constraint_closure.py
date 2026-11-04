#!/usr/bin/env python3
"""Fail when the active Python environment escapes the reviewed CI lock."""

from __future__ import annotations

import argparse
import importlib.metadata
import sys
from collections.abc import Iterable, Mapping, Sequence
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - exercised by Python 3.10 CI
    import tomli as tomllib

from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version


def active_constraints(
    path: Path,
    *,
    environment: Mapping[str, str] | None = None,
) -> dict[str, Requirement]:
    """Return the one active exact constraint for each normalized project."""
    marker_environment = dict(environment or default_environment())
    constraints: dict[str, Requirement] = {}
    for line_number, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        requirement = Requirement(line)
        if requirement.url:
            raise ValueError(f"{path}:{line_number}: URL constraints are not exact pins")
        specifiers = list(requirement.specifier)
        if (
            len(specifiers) != 1
            or specifiers[0].operator != "=="
            or "*" in specifiers[0].version
        ):
            raise ValueError(
                f"{path}:{line_number}: constraint must contain one exact == pin"
            )
        if requirement.marker and not requirement.marker.evaluate(marker_environment):
            continue
        name = canonicalize_name(requirement.name)
        if name in constraints:
            raise ValueError(
                f"{path}:{line_number}: duplicate active constraint for {name}"
            )
        constraints[name] = requirement
    return constraints


def release_cohort_names(path: Path) -> set[str]:
    """Load the first-party distributions that are allowed outside the lock."""
    cohort = tomllib.loads(path.read_text(encoding="utf-8"))
    packages = cohort.get("packages", [])
    if not packages:
        raise ValueError(f"{path}: release cohort is empty")
    return {
        canonicalize_name(str(package["distribution"]))
        for package in packages
    }


def installed_versions(
    distributions: Iterable[importlib.metadata.Distribution] | None = None,
) -> dict[str, set[str]]:
    """Collect every installed distribution, preserving duplicate versions."""
    result: dict[str, set[str]] = {}
    candidates = (
        importlib.metadata.distributions()
        if distributions is None
        else distributions
    )
    for distribution in candidates:
        name = distribution.metadata.get("Name")
        if not name:
            continue
        result.setdefault(canonicalize_name(name), set()).add(distribution.version)
    return result


def closure_errors(
    installed: Mapping[str, set[str]],
    constraints: Mapping[str, Requirement],
    *,
    allowed_unconstrained: set[str],
) -> list[str]:
    """Describe missing pins, version drift, and ambiguous duplicate installs."""
    errors: list[str] = []
    for name in sorted(installed):
        versions = installed[name]
        if len(versions) != 1:
            errors.append(f"{name}: multiple installed versions {sorted(versions)}")
            continue
        if name in allowed_unconstrained:
            continue
        requirement = constraints.get(name)
        version = next(iter(versions))
        if requirement is None:
            errors.append(f"{name}=={version}: no active constraint")
            continue
        expected = next(iter(requirement.specifier)).version
        try:
            matches = Version(version) == Version(expected)
        except InvalidVersion:
            matches = version == expected
        if not matches:
            errors.append(f"{name}=={version}: expected {requirement.specifier}")
    return errors


def build_parser() -> argparse.ArgumentParser:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--constraints",
        type=Path,
        default=root / "requirements" / "ci.txt",
    )
    parser.add_argument(
        "--release-cohort",
        type=Path,
        default=root / "release-cohort.toml",
    )
    parser.add_argument(
        "--allow-unconstrained",
        action="append",
        default=[],
        metavar="DISTRIBUTION",
        help=(
            "allow an additional first-party distribution outside the lock; "
            "repeat for multiple distributions"
        ),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    constraints = active_constraints(args.constraints)
    allowed_unconstrained = release_cohort_names(args.release_cohort)
    allowed_unconstrained.update(
        canonicalize_name(name)
        for name in args.allow_unconstrained
    )
    installed = installed_versions()
    errors = closure_errors(
        installed,
        constraints,
        allowed_unconstrained=allowed_unconstrained,
    )
    if errors:
        print("Dependency constraint closure FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)
        return 1
    external_count = len(set(installed) - allowed_unconstrained)
    print(
        "Dependency constraint closure OK: "
        f"{external_count} external distributions exactly pinned"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
