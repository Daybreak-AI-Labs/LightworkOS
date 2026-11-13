"""Public claims in the docs must match what the repository ships.

Each test pins one wording fix so the claim cannot quietly drift back: a
supported-version line that was never released, a "tamper-evident" headline
without its key-custody qualifier, a CLI command that is not registered, a
backend listed as a deploy target while its code is a scaffold, a queue called
exactly-once while its reclaim path is at-least-once, and benchmark results
that look recorded when none are.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]


def _read(relpath: str) -> str:
    return (REPO_ROOT / relpath).read_text(encoding="utf-8")


def test_security_policy_does_not_claim_an_unreleased_supported_line():
    """SECURITY.md named v0.2.x as the supported line. No release is published
    (main is 0.1.7 in release-cohort.toml), so the supported-versions section
    must say so and name `main` as the line that receives fixes."""
    text = _read("SECURITY.md")
    assert "v0.2.x" not in text
    section = text.split("## Supported versions", 1)[1].split("\n## ", 1)[0]
    assert "No release is currently published" in section
    assert "`main`" in section
    cohort = re.search(r'^version = "([^"]+)"', _read("release-cohort.toml"), re.MULTILINE)
    assert cohort is not None
    assert cohort.group(1) in section


def test_readme_tamper_evidence_headline_names_its_key_custody():
    """The README headline said "Tamper-evident" with no qualifier. The audit
    signing key is held on the same host by default (audit/signing.py), so the
    headline must say so and name the off-host setting."""
    headline = next(
        line for line in _read("README.md").splitlines() if "Tamper-evident" in line
    )
    assert "same host" in headline
    assert "MAVERICK_AUDIT_SIGNING_KEY" in headline


def test_public_material_names_only_a_registered_proof_pack_command():
    """`maverick proof-pack` is not a registered CLI command; the click group has
    `proof` (the workforce value report) and no proof-pack. The signed evidence
    bundle is built by `python -m maverick.proof_pack`, which has a __main__ block."""
    module = _read("packages/maverick-core/maverick/proof_pack.py")
    assert 'if __name__ == "__main__"' in module
    paths = ["README.md"]
    for root in ("docs",):
        for path in sorted((REPO_ROOT / root).rglob("*")):
            if path.suffix in {".md", ".html"}:
                paths.append(path.relative_to(REPO_ROOT).as_posix())
    stale = [p for p in paths if "maverick proof-pack" in _read(p)]
    assert stale == [], f"unregistered 'maverick proof-pack' command in: {stale}"


def test_firecracker_is_described_as_a_scaffold_not_a_deploy_target():
    """The Firecracker backend labels itself a SCAFFOLD (sandbox/firecracker.py
    docstring) and deploy/aws/EXECUTOR.md and the deployment playbook call the
    local scaffold unsupported. Any doc line that names Firecracker as a deploy
    target or shipped backend must say it is an experimental scaffold."""
    checked = {
        "README.md": None,
        "SECURITY.md": None,
        "docs/architecture.md": None,
        "docs/handbook.md": None,
        "docs/configuration.md": None,
        "docs/env-vars.md": None,
    }
    enterprise = sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in (REPO_ROOT / "docs" / "enterprise").rglob("*.md")
    )
    for relpath in enterprise:
        checked.setdefault(relpath, None)
    # The backend option list and the MAVERICK_FIRECRACKER_STRICT row name
    # Firecracker as an accepted value, not as a shipped target.
    accepted_values = {
        "docs/configuration.md": "local | docker | ssh | podman | gvisor | devcontainer | firecracker | kubernetes | modal",
        "docs/env-vars.md": "`MAVERICK_FIRECRACKER_STRICT`",
    }
    for relpath, needle in checked.items():
        for line in _read(relpath).splitlines():
            if "firecracker" not in line.lower() or (needle and needle not in line):
                continue
            if relpath in accepted_values and accepted_values[relpath] in line:
                continue
            assert "scaffold" in line.lower(), f"{relpath}: {line[:120]}"


def test_queue_delivery_is_not_described_as_exactly_once():
    """JobQueue.claim is atomic (one worker per job at a time), but a job whose
    worker dies after its side effect and before complete() runs again after the
    lease expires (JobQueue.reclaim_stale; Worker._reclaim_stale). Delivery is
    at-least-once, so prose must not say exactly-once for the queue as a whole."""
    stale = {
        "packages/maverick-dashboard/maverick_dashboard/app.py":
            "durable, retrying, exactly-once",
        "packages/maverick-dashboard/maverick_dashboard/automation_queue.py":
            "JobQueue's exactly-once",
        "docs/FEATURES.md":
            "**exactly-once** — the contention",
        "docs/evidence/README.md":
            "**exactly-once** execution",
    }
    for relpath, phrase in stale.items():
        assert phrase not in _read(relpath), f"{relpath} still says {phrase!r}"


def test_benchmark_results_say_when_no_live_run_is_recorded():
    """benchmarks/RESULTS.md holds only a dry-run CI smoke row. While that is the
    case the file must say that no live-model result is recorded and give the
    harness command that records one, so the table is not read as measured."""
    text = _read("benchmarks/RESULTS.md")
    rows = [line for line in text.splitlines() if line.startswith("| benchmarks/")]
    if all("dry-run" in row for row in rows):
        assert "no live-model results are recorded yet" in text.lower()
    command = "python benchmarks/harness.py benchmarks/longhorizon/research-report.md"
    assert command in text
    harness = _read("benchmarks/harness.py")
    assert '"--max-dollars"' in harness and '"--tag"' in harness


def _features_toc():
    import importlib.util
    import sys

    path = REPO_ROOT / "scripts" / "features_toc.py"
    spec = importlib.util.spec_from_file_location("features_toc", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolve annotations via sys.modules
    spec.loader.exec_module(module)
    return module


def test_features_catalogue_has_a_current_table_of_contents():
    """docs/FEATURES.md is 6,000+ lines of `- **Name** -- ...` entries in `##`
    sections; its generated contents block (section, entry count, anchor) must
    match the sections it describes, every entry must sit under a section, and
    section headings must slug the same way on GitHub and MkDocs (no `&`)."""
    toc = _features_toc()
    text = _read("docs/FEATURES.md")
    assert toc.apply(text) == text, "run python scripts/features_toc.py --write"
    found = toc.sections(text)
    assert len(found) >= 19 and sum(s.entries for s in found) >= 454
    assert toc.entries_before_first_section(text) == 0
    for section in found:
        assert "&" not in section.title, section.title
        assert f"](#{toc.anchor(section.title)})" in text, section.title


#: The documents a reader needs today. Point-in-time material (audits, ledgers,
#: reviews, status boards, launch checklists) does not belong at the root.
ROOT_DOCUMENTS = {
    "README.md", "ARCHITECTURE.md", "CHANGELOG.md", "CLAUDE.md", "AGENTS.md",
    "CONTRIBUTING.md", "SECURITY.md", "CLA.md", "CODE_OF_CONDUCT.md", "MAINTAINERS.md",
    "GOVERNANCE.md", "SUPPORT.md", "RELEASING.md", "TRADEMARK.md", "THIRD-PARTY-NOTICES.md",
}


def test_the_root_holds_only_the_live_documents():
    """The repository root holds only the documents a reader needs today: the
    overview, architecture, changelog, agent instructions and the community and
    policy files. A new audit, ledger or launch checklist at the root fails here."""
    root_docs = {p.name for p in REPO_ROOT.glob("*.md")}
    assert root_docs <= ROOT_DOCUMENTS, sorted(root_docs - ROOT_DOCUMENTS)


def test_business_material_stays_out_of_the_product_repository():
    """Fundraising, strategy and patent material does not belong beside the
    product. A documentation or root file whose name looks like such material
    fails here."""
    # Documentation and root files only: product skill packs legitimately carry
    # names such as investor-update-author.md and due-diligence-data-room.md.
    tracked = subprocess.run(
        ["git", "ls-files", "--", "docs", "*.md", "*.pdf", "*.pptx"],
        capture_output=True, text=True, cwd=REPO_ROOT, check=True,
    ).stdout.split("\n")
    tracked = [path for path in tracked if path and (path.startswith("docs/") or "/" not in path)]
    telltale = re.compile(
        r"(investor|pitch[-_ ]?deck|fundrais|patent|seed[-_ ]deck|gtm[-_ ]outreach|"
        r"purchase[-_ ]blockers|invention[-_ ](register|disclosure|implementation))",
        re.IGNORECASE,
    )
    suspicious = sorted(path for path in tracked if telltale.search(path.rsplit("/", 1)[-1]))
    assert suspicious == [], f"file names that look like business material: {suspicious}"


def test_docs_provider_counts_match_the_registry():
    """docs/architecture.md, the handbook and the feature catalogue each quote a
    provider count; each must equal the length of ``providers.KNOWN_PROVIDERS``."""
    from maverick.providers import KNOWN_PROVIDERS

    expected = {len(KNOWN_PROVIDERS)}
    for relpath, pattern in (
        ("docs/architecture.md", r"(\d+) LLM provider backends"),
        ("docs/handbook.md", r"from (\d+) providers"),
        ("docs/FEATURES.md", r"(\d+) providers, routable per role"),
    ):
        found = re.findall(pattern, _read(relpath))
        assert found, (relpath, pattern)
        assert {int(v) for v in found} == expected, (relpath, found)


def test_channel_docs_name_every_server_wired_adapter():
    """Every adapter ``server._WIRES`` wires must appear, by its config table
    name, in the channels package README and docstring, and the counts the
    docstring, the handbook and the feature catalogue quote must match."""
    from maverick.server import _WIRES

    wired = sorted(_WIRES)
    channels_readme = _read("packages/maverick-channels/README.md")
    docstring = _read("packages/maverick-channels/maverick_channels/__init__.py")
    for name in wired:
        assert f"`{name}`" in channels_readme, name
        assert name in docstring, name
    assert f"Server-wired adapters ({len(wired)};" in docstring
    assert f"{len(wired)} wired adapters" in _read("docs/handbook.md")
    assert f"{len(wired)} wired channels" in _read("docs/FEATURES.md")


PACK_COUNT_DOCS = ("README.md", "docs/index.md", "docs/handbook.md", "docs/FEATURES.md")


def test_docs_pack_counts_match_the_shipped_domains():
    """Every "N packs" / "N specialists" / "N agents" count in the public claims
    must equal the number of domain TOML files that ship in ``maverick/domains``."""
    shipped = len(list((REPO_ROOT / "packages" / "maverick-core" / "maverick" / "domains").glob("*.toml")))
    pattern = re.compile(
        r"(\d),(\d{3})(?:-pack)?\s+(?:lint-clean\s+)?(?:built-in\s+)?(?:domain\s+)?(?:specialist\s+)?(?:prebuilt\s+)?(?:specialists|packs|agents)\b"
    )
    for relpath in PACK_COUNT_DOCS:
        found = [int(a + b) for a, b in pattern.findall(_read(relpath))]
        assert found, (relpath, "no pack count found")
        assert set(found) == {shipped}, (relpath, found, shipped)


def test_docs_connector_counts_match_the_specs():
    """2,877 write-capable REST/GraphQL connectors and 37 read-only public-data
    connectors are quoted across the docs; both must equal the spec tables."""
    from maverick.tools import _connector_specs, enterprise_connectors

    write_capable = len(_connector_specs._SPECS) + len(_connector_specs._GRAPHQL_SPECS)
    public_data = len(enterprise_connectors._PUBLIC_DATA_SPECS)
    for relpath in ("docs/technical-overview.md", "docs/architecture.md", "docs/handbook.md"):
        text = _read(relpath)
        found = [int(v.replace(",", "")) for v in re.findall(r"([\d,]+) write-capable", text)]
        assert found and set(found) == {write_capable}, (relpath, found, write_capable)
    for relpath in ("docs/architecture.md", "docs/handbook.md", "docs/enterprise/architecture.md"):
        found = [int(v) for v in re.findall(r"(\d+) read-only", _read(relpath))]
        assert found and set(found) == {public_data}, (relpath, found, public_data)


# The number of non-test functions carrying a complexity waiver. CLAUDE.md and
# pyproject.toml quote it, and the house rule is that new code stays under the
# cap, so this may only go down. Lower it when you remove a waiver; never raise
# it without an explicit review of why a new function needs one.
COMPLEXITY_WAIVER_CEILING = 165


def test_complexity_waivers_do_not_grow():
    """The ``# noqa: C901`` backlog is refactor debt (pyproject.toml). A new waiver
    in non-test code fails here; removing one should lower the ceiling above."""
    waivers = 0
    for root in ("packages", "apps"):
        for path in (REPO_ROOT / root).rglob("*.py"):
            if {"tests", ".venv", "build", "node_modules", "target"}.intersection(
                path.relative_to(REPO_ROOT / root).parts
            ):
                continue
            waivers += path.read_text(encoding="utf-8", errors="ignore").count("noqa: C901")
    assert waivers <= COMPLEXITY_WAIVER_CEILING, (
        f"{waivers} complexity waivers in non-test code, ceiling {COMPLEXITY_WAIVER_CEILING}: "
        "keep new functions under the cap instead of adding a waiver"
    )
    assert f"{COMPLEXITY_WAIVER_CEILING} grandfathered" in _read("CLAUDE.md")
    assert f"the {COMPLEXITY_WAIVER_CEILING} functions already over it" in _read("pyproject.toml")
