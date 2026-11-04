from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
from packaging.markers import default_environment
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[3]


def _load_verifier():
    path = REPO_ROOT / "scripts" / "verify_constraint_closure.py"
    spec = importlib.util.spec_from_file_location("verify_constraint_closure", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _requirement(value: str) -> Requirement:
    return Requirement(value)


def test_active_constraints_respect_markers_and_reject_ranges(tmp_path):
    verifier = _load_verifier()
    constraints = tmp_path / "constraints.txt"
    constraints.write_text(
        "\n".join(
            (
                "always==1.0",
                'legacy==2.0; python_version < "3.11"',
                'modern==3.0; python_version >= "3.11"',
            )
        )
        + "\n",
        encoding="utf-8",
    )
    environment = default_environment()
    environment["python_version"] = "3.10"

    active = verifier.active_constraints(
        constraints,
        environment=environment,
    )

    assert set(active) == {"always", "legacy"}

    constraints.write_text("floating>=1.0\n", encoding="utf-8")
    with pytest.raises(ValueError, match="one exact == pin"):
        verifier.active_constraints(constraints, environment=environment)

    constraints.write_text("wildcard==1.*\n", encoding="utf-8")
    with pytest.raises(ValueError, match="one exact == pin"):
        verifier.active_constraints(constraints, environment=environment)


def test_closure_reports_missing_mismatch_and_duplicate_versions():
    verifier = _load_verifier()
    constraints = {
        "exact": _requirement("exact==1.2.3"),
        "drifted": _requirement("drifted==2.0"),
        "local": _requirement("local==1.0"),
    }
    installed = {
        "exact": {"1.2.3"},
        "drifted": {"2.1"},
        "missing": {"4.0"},
        "duplicate": {"1.0", "1.1"},
        "local": {"1.0+private"},
        "maverick-agent": {"0.1.7"},
    }

    errors = verifier.closure_errors(
        installed,
        constraints,
        allowed_unconstrained={"maverick-agent"},
    )

    assert errors == [
        "drifted==2.1: expected ==2.0",
        "duplicate: multiple installed versions ['1.0', '1.1']",
        "local==1.0+private: expected ==1.0",
        "missing==4.0: no active constraint",
    ]


def test_repository_constraints_are_exact_and_cover_current_environment():
    verifier = _load_verifier()
    constraints = verifier.active_constraints(
        REPO_ROOT / "requirements" / "ci.txt"
    )
    first_party = verifier.release_cohort_names(
        REPO_ROOT / "release-cohort.toml"
    )

    assert canonicalize_name("maverick-agent") in first_party
    # The kernel declares a tzdata floor (packages/maverick-core/pyproject.toml);
    # the lock must pin a tzdata that satisfies it, whichever version that is.
    core = tomllib.loads(
        (REPO_ROOT / "packages" / "maverick-core" / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )
    tzdata_floor = next(
        Requirement(dependency)
        for dependency in core["project"]["dependencies"]
        if canonicalize_name(Requirement(dependency).name) == "tzdata"
    )
    pinned_tzdata = next(iter(constraints["tzdata"].specifier)).version
    assert tzdata_floor.specifier.contains(pinned_tzdata), (
        f"tzdata=={pinned_tzdata} does not satisfy the kernel floor {tzdata_floor}"
    )
    # Bumped with psycopg 3.3.6 in 4fd34f7c; the Postgres CI job installs the same pin.
    assert constraints["psycopg-pool"].specifier.contains("3.3.3")


def test_workflow_and_build_pins_agree_with_dependency_constraints():
    verifier = _load_verifier()
    constraints = verifier.active_constraints(REPO_ROOT / "requirements" / "ci.txt")
    sources = [*(REPO_ROOT / ".github" / "workflows").glob("*.yml"),
               *(REPO_ROOT / ".github" / "actions").glob("*/action.yml"),
               REPO_ROOT / "scripts" / "build-nuitka.sh"]
    mismatches = []
    for source in sources:
        for line_no, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            for name, version in re.findall(r"([\w.-]+)==([\d][\w.+-]*)", line):
                requirement = constraints.get(canonicalize_name(name))
                if requirement and not requirement.specifier.contains(version):
                    mismatches.append(f"{source.relative_to(REPO_ROOT)}:{line_no}: {name}=={version}, "
                                      f"constraint {requirement.specifier}")
    assert not mismatches, "\n".join(mismatches)


def test_parser_allows_explicit_additional_first_party_distributions():
    verifier = _load_verifier()

    args = verifier.build_parser().parse_args(
        [
            "--allow-unconstrained",
            "maverick-native",
            "--allow-unconstrained",
            "private-helper",
        ]
    )

    assert args.allow_unconstrained == [
        "maverick-native",
        "private-helper",
    ]
