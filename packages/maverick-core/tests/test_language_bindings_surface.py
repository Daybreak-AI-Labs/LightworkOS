"""Validate the cross-language MCP surface we promise in the README.

The language-bindings decision in docs/clients/README.md commits us to:
  1. The `maverick mcp` CLI command exists + advertises the
     cross-language surface in its docstring.
  2. The TS / Go / Rust quickstart docs are present, runnable-shaped
     (i.e. have a real fenced code block), and cross-link to the
     language-bindings decision.
  3. The clients guide records that decision under "Language bindings"
     with the top-5 language list.
  4. The main README points consumers at all three quickstarts.

If anyone removes the cross-language surface, this test fails.
"""
from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[3]


def test_mcp_cli_advertises_cross_language():
    from click.testing import CliRunner
    from maverick.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["mcp", "--help"])
    assert result.exit_code == 0
    out = result.output.lower()
    assert "cross-language" in out
    # Reference each top-5 language by name so removals show up in CI.
    for lang in ("typescript", "go", "rust"):
        assert lang in out, f"`maverick mcp --help` no longer mentions {lang}"


def _quickstart(path: str) -> str:
    p = _REPO_ROOT / path
    assert p.exists(), f"missing {path}"
    text = p.read_text(encoding="utf-8")
    assert "```" in text, f"{path} has no fenced code block"
    return text


def test_typescript_quickstart_present():
    text = _quickstart("docs/clients/typescript-quickstart.md")
    assert "@modelcontextprotocol/sdk" in text
    assert "maverick mcp" in text or "[\"mcp\"]" in text
    assert "README.md#language-bindings" in text  # cross-link back


def test_go_quickstart_present():
    text = _quickstart("docs/clients/go-quickstart.md")
    assert "maverick mcp" in text or '"mcp"' in text
    assert "Go" in text or "go-sdk" in text.lower()


def test_rust_quickstart_present():
    text = _quickstart("docs/clients/rust-quickstart.md")
    assert "maverick mcp" in text or '"mcp"' in text
    assert "Rust" in text or "tokio" in text


def test_clients_guide_records_the_language_bindings_decision():
    text = (_REPO_ROOT / "docs/clients/README.md").read_text(encoding="utf-8")
    assert "## Language bindings" in text
    section = text.split("## Language bindings", 1)[1].split("\n#", 1)[0]
    # Each top-5 language is named in the decision.
    for lang in ("TypeScript", "Go", "Rust", "C#", "Java"):
        assert lang in section, f"top-5 language {lang!r} not in the decision"
    # A thin TypeScript client is the only port considered, and only on demand.
    assert "thin TypeScript client package" in section
    assert "MCP" in section


def test_readme_links_to_clients():
    text = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/clients/typescript-quickstart.md" in text
    assert "docs/clients/go-quickstart.md" in text
    assert "docs/clients/rust-quickstart.md" in text
