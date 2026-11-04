"""Checks that documented repository files exist and parse: the docs site
configuration and pages, the release and contribution workflows, the VS Code
extension scaffold and the cookbook.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

# ---------- CI workflows present ----------

def test_publish_workflow_exists():
    repo_root = Path(__file__).resolve().parents[3]
    assert (repo_root / ".github" / "workflows" / "publish.yml").is_file()


def test_conventional_commits_workflow_exists():
    repo_root = Path(__file__).resolve().parents[3]
    assert (repo_root / ".github" / "workflows" / "conventional-commits.yml").is_file()


def test_starter_goals_doc_exists():
    repo_root = Path(__file__).resolve().parents[3]
    # Moved out of docs/templates/ -> docs/ so MkDocs (which excludes the
    # templates/ dir) actually builds + serves the page. See fix/docs-accuracy.
    assert (repo_root / "docs" / "starter-goals.md").is_file()


# ---------- threat model + streaming docs exist ----------

def test_threat_model_doc_exists():
    repo_root = Path(__file__).resolve().parents[3]
    p = repo_root / "docs" / "security" / "threat-model.md"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    # Must cover all six STRIDE categories.
    for cat in ("Spoofing", "Tampering", "Repudiation",
                "Information disclosure", "Denial of service",
                "Elevation of privilege"):
        assert cat in body, f"threat model missing STRIDE category: {cat}"


def test_streaming_parity_doc_exists():
    repo_root = Path(__file__).resolve().parents[3]
    p = repo_root / "docs" / "performance" / "streaming-parity.md"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    # Doc must list every registered provider so it stays in sync with the
    # adapter registry.
    from maverick.providers import _PROVIDER_ALIASES

    assert len(_PROVIDER_ALIASES) >= 8
    for provider in _PROVIDER_ALIASES:
        assert f"`{provider}`" in body, f"streaming-parity doc missing: {provider}"


# ---------- VS Code extension scaffold ----------

def test_vscode_extension_package_json_valid():
    repo_root = Path(__file__).resolve().parents[3]
    p = repo_root / "apps" / "vscode-extension" / "package.json"
    assert p.is_file()
    data = json.loads(p.read_text())
    # Required VS Code extension fields.
    assert data["name"] == "maverick"
    assert "engines" in data and "vscode" in data["engines"]
    assert "main" in data
    # Commands declared.
    commands = {c["command"] for c in data["contributes"]["commands"]}
    for required in (
        "maverick.start",
        "maverick.status",
        "maverick.halt",
        "maverick.unhalt",
        "maverick.openExport",
        "maverick.refreshRuns",
    ):
        assert required in commands, f"missing command: {required}"


def test_vscode_extension_source_exists():
    repo_root = Path(__file__).resolve().parents[3]
    p = repo_root / "apps" / "vscode-extension" / "src" / "extension.ts"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    # Sanity: source mentions the CLI it shells out to.
    assert "maverick" in body
    assert "activate" in body
    assert "deactivate" in body


REPO_ROOT = Path(__file__).resolve().parents[3]


def test_mkdocs_yml_exists_and_parses():
    """Top-level mkdocs.yml configures the MkDocs Material site."""
    p = REPO_ROOT / "mkdocs.yml"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    # Sanity: required fields appear.
    for k in ("site_name:", "theme:", "nav:", "name: material"):
        assert k in body, f"mkdocs.yml missing {k!r}"


def test_mkdocs_yml_navigation_references_existing_files():
    """nav: entries must point to files that actually exist."""
    p = REPO_ROOT / "mkdocs.yml"
    body = p.read_text(encoding="utf-8")
    # Naive: extract any docs/ relative path the nav: block points to.
    # MkDocs paths are relative to docs/.
    import re

    nav_targets = re.findall(r":\s+([a-zA-Z0-9_/.-]+\.md)\s*$", body, flags=re.MULTILINE)
    assert nav_targets, "no nav targets parsed from mkdocs.yml"
    missing: list[str] = []
    for rel in nav_targets:
        target = REPO_ROOT / "docs" / rel
        # Allow paths that point to top-level files (CONTRIBUTING.md etc) -
        # the docs.yml workflow symlinks them into docs/ on build.
        top_level = REPO_ROOT / rel
        if not target.is_file() and not top_level.is_file():
            missing.append(rel)
    assert not missing, f"nav references missing files: {missing}"


def test_docs_index_landing_exists():
    p = REPO_ROOT / "docs" / "index.md"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    # The landing page must carry its core sections.
    for keyword in ("Lightwork", "Quick start", "Pricing"):
        assert keyword in body, f"index.md missing section: {keyword}"


def test_docs_workflow_exists():
    p = REPO_ROOT / ".github" / "workflows" / "docs.yml"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    # Must build with mkdocs and deploy to Pages.
    assert "mkdocs" in body
    assert "deploy-pages" in body or "github-pages" in body.lower()


def test_reusable_agent_on_pr_workflow_exists():
    p = REPO_ROOT / ".github" / "workflows" / "agent-on-pr.yml"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    # Must declare reusable workflow_call and required inputs.
    assert "workflow_call" in body
    assert "goal:" in body
    assert "max_dollars:" in body
    # Posts to PR via REST.
    assert "createComment" in body or "pull-requests: write" in body


def test_publish_workflow_still_present():
    """Earlier PyPI publish workflow shouldn't have been clobbered."""
    p = REPO_ROOT / ".github" / "workflows" / "publish.yml"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    assert "pypa/gh-action-pypi-publish" in body


def test_conventional_commits_workflow_still_present():
    p = REPO_ROOT / ".github" / "workflows" / "conventional-commits.yml"
    assert p.is_file()


# ---------- cookbook + failure-modes docs ----------

COOKBOOK_RECIPES = [
    "pr-review.md", "dep-migrate.md", "repo-onboarding.md",
    "issue-triage.md", "research.md",
    # Quick hits (under 60 seconds).
    "commit-message.md", "explain-error.md", "regex-builder.md",
    "changelog-entry.md", "docstring-pass.md", "test-naming.md",
    "env-audit.md",
]


@pytest.mark.parametrize("name", ["index.md", *COOKBOOK_RECIPES])
def test_cookbook_recipe_exists(name):
    p = REPO_ROOT / "docs" / "cookbook" / name
    assert p.is_file(), f"missing cookbook recipe: {name}"
    body = p.read_text(encoding="utf-8")
    # Each recipe must have a "Goal text" or be the index.
    if name == "index.md":
        return
    assert "## Goal text" in body or "Goal text" in body


def test_cookbook_has_at_least_12_recipes():
    assert len(COOKBOOK_RECIPES) >= 12
    # And each is linked from the index so users can find it.
    index = (REPO_ROOT / "docs" / "cookbook" / "index.md").read_text(encoding="utf-8")
    for name in COOKBOOK_RECIPES:
        assert f"({name})" in index or f"(./{name})" in index, (
            f"recipe not linked from index: {name}"
        )


def test_failure_modes_doc_exists():
    p = REPO_ROOT / "docs" / "performance" / "failure-modes.md"
    assert p.is_file()
    body = p.read_text(encoding="utf-8")
    # Must enumerate every ErrorClass.
    for cls in (
        "rate_limit", "transient_network", "server_5xx",
        "content_filter", "auth", "context_overflow",
        "malformed_response", "unknown",
    ):
        assert cls in body
