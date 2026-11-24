"""Tests for the file-system tools (maverick.tools.fs) in opaque benchmark mode."""
from __future__ import annotations

import os

import pytest

# ---- read_file refuses tests in benchmark opaque mode ----

class TestReadFileOpaqueGuard:
    def _make_sandbox(self, tmp_path):
        class _Sandbox:
            workdir = tmp_path
        return _Sandbox()

    def test_read_test_file_blocked_when_opaque(self, tmp_path, monkeypatch):
        from maverick.tools.fs import read_file
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_foo.py").write_text("assert x == 42")
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = read_file(self._make_sandbox(tmp_path))
        out = tool.fn({"path": "tests/test_foo.py"})
        assert "blocked" in out.lower()
        assert "x == 42" not in out

    def test_read_production_file_still_works(self, tmp_path, monkeypatch):
        from maverick.tools.fs import read_file
        (tmp_path / "src.py").write_text("def f(): return 42")
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = read_file(self._make_sandbox(tmp_path))
        out = tool.fn({"path": "src.py"})
        assert "return 42" in out

    def test_opaque_off_allows_test_reads(self, tmp_path, monkeypatch):
        from maverick.tools.fs import read_file
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "test_foo.py").write_text("assert x == 42")
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "0")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        tool = read_file(self._make_sandbox(tmp_path))
        out = tool.fn({"path": "tests/test_foo.py"})
        assert "x == 42" in out


@pytest.fixture(autouse=True)
def _shell_consented(fresh_human_decision):
    """These tests exercise git-internals BLOCKING through the shell tool;
    the shell's exact-approval permit needs a fresh human decision, which
    the shared fixture supplies so the blocking rules are what is tested."""
    del fresh_human_decision


@pytest.fixture
def opaque_mode(monkeypatch):
    monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "1")
    monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
    from maverick.coding_mode import reset_gold_patch_cache
    reset_gold_patch_cache()
    yield
    reset_gold_patch_cache()


class TestDotGitBlocked:
    def test_read_file_blocks_dotgit(self, tmp_path, opaque_mode):
        from maverick.tools.fs import read_file
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": ".git/HEAD"})
        assert "ERROR" in out
        assert "blocked" in out.lower()

    def test_read_file_blocks_nested_dotgit(self, tmp_path, opaque_mode):
        from maverick.tools.fs import read_file
        (tmp_path / "sub" / ".git").mkdir(parents=True)
        (tmp_path / "sub" / ".git" / "config").write_text("[core]\n")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": "sub/.git/config"})
        assert "ERROR" in out

    def test_read_file_allows_dotgit_in_non_opaque(self, tmp_path, monkeypatch):
        from maverick.tools.fs import read_file
        monkeypatch.setenv("MAVERICK_BENCHMARK_OPAQUE", "0")
        monkeypatch.setenv("MAVERICK_CODING_MODE", "1")
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": ".git/HEAD"})
        # No opaque-mode block; gets through to file read.
        assert "ref: refs/heads/main" in out


class TestSymlinkBypass:
    """Symlink to .git or tests/ must still be
    blocked by the resolved-path check."""

    @pytest.mark.skipif(
        os.name == "nt",
        reason="creating a symlink requires admin/Developer Mode on Windows (WinError 1314)",
    )
    def test_symlink_to_dotgit_blocked_in_read_file(self, tmp_path, opaque_mode):
        import os as _os

        from maverick.tools.fs import read_file
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        # Create symlink: safe_dir -> .git
        _os.symlink(".git", tmp_path / "safe_dir")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": "safe_dir/HEAD"})
        assert "ERROR" in out, (
            "symlink to .git/HEAD must be blocked on resolved path"
        )
        assert "ref:" not in out


class TestTestsDirAllFiles:
    """ANY file under tests/ is now blocked, not
    just files matching the test_*.py heuristic."""

    def test_conftest_under_tests_blocked(self, tmp_path, opaque_mode):
        from maverick.tools.fs import read_file
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "conftest.py").write_text("# expected_value = 42")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": "tests/conftest.py"})
        assert "ERROR" in out
        assert "expected_value" not in out

    def test_init_under_tests_blocked(self, tmp_path, opaque_mode):
        from maverick.tools.fs import read_file
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests" / "__init__.py").write_text("EXPECTED = 'gold'")

        class _Sandbox:
            workdir = tmp_path

        tool = read_file(_Sandbox())
        out = tool.fn({"path": "tests/__init__.py"})
        assert "ERROR" in out
        assert "gold" not in out


def test_java_test_names_are_test_paths():
    from maverick.tools.fs import _is_test_path
    assert _is_test_path("src/FooTest.java") and _is_test_path("src/FooTests.java")
    assert not _is_test_path("src/Contest.java")


def test_read_file_reads_only_up_to_the_cap(tmp_path, monkeypatch):
    from maverick.tools import fs
    (tmp_path / "big.txt").write_text("x" * 20000)
    seen: dict = {}
    real = fs.read_text_contained

    def _spy(sandbox, target, **kw):
        seen.update(kw)
        return real(sandbox, target, **kw)

    monkeypatch.setattr(fs, "read_text_contained", _spy)

    class _Sandbox:
        workdir = tmp_path

    out = fs.read_file(_Sandbox()).fn({"path": "big.txt"})
    assert seen["max_chars"] == fs.MAX_READ_BYTES + 1
    assert "truncated at 8000 characters, file is 20000 bytes" in out


@pytest.mark.parametrize("name,hint", [
    ("rent.xlsx", "`spreadsheet`"), ("report.doc", ".docx"), ("deck.ppt", ".pptx"),
    ("revenue_by_month.png", "SVG"), ("logo.JPG", "SVG"),
    ("bundle.zip", "text format"), ("Rent.XLSX", "`spreadsheet`"),
])
def test_write_file_refuses_text_in_a_binary_document(tmp_path, name, hint):
    # Live: asked for an Excel file, agents wrote "placeholder" into
    # rent_payments.xlsx with write_file, a file no app can open, then got
    # confused by it. The refusal names the tool that makes the format.
    from maverick.sandbox import LocalBackend
    from maverick.tools.fs import write_file

    tool = write_file(LocalBackend(workdir=tmp_path))
    out = tool.fn({"path": name, "content": "placeholder"})
    assert out.startswith("ERROR") and hint in out and "nothing was written" in out
    assert not (tmp_path / name).exists()
    assert tool.fn({"path": "rent.csv", "content": "a,b\n1,2\n"}).startswith("wrote")


def test_write_file_to_a_docx_path_makes_a_word_document_from_markdown(tmp_path):
    # Live: asked for a Word document, the agent wrote Markdown to
    # "job.docx.md" and delivered that, because write_file refused .docx and
    # the pandoc tool was not loaded. Markdown written to .docx is now a real
    # Word document, offered as a download like any other saved file.
    import io
    import zipfile

    from maverick.sandbox import LocalBackend
    from maverick.task_files import files_for
    from maverick.tools.fs import write_file
    from maverick.world_model import WorldModel

    world = WorldModel(path=tmp_path / "world.db")
    goal = world.create_goal("Job description", "")
    work = tmp_path / "work"
    work.mkdir()
    tool = write_file(LocalBackend(workdir=work), goal_id=goal, world=world)
    out = tool.fn({"path": "docs/job.docx", "content": "# Bookkeeper\n\n- Reconcile accounts\n- Run payroll\n"})
    assert out.startswith("wrote a Word document") and "job.docx" in out
    with zipfile.ZipFile(io.BytesIO((work / "docs" / "job.docx").read_bytes())) as document:
        body = document.read("word/document.xml").decode()
    assert "Bookkeeper" in body and "Run payroll" in body and "# Bookkeeper" not in body
    assert [item.path for item in files_for(world, goal)] == ["docs/job.docx"]
    assert tool.fn({"path": "../job.docx", "content": "x"}).startswith("ERROR")


def test_write_file_to_a_pptx_path_makes_a_deck_from_markdown(tmp_path):
    # Live: asked for a 5-slide PowerPoint, an agent's only route was a
    # python-pptx script waiting on a person's shell approval.
    import zipfile

    from maverick.sandbox import LocalBackend
    from maverick.tools.fs import write_file

    tool = write_file(LocalBackend(workdir=tmp_path))
    out = tool.fn({"path": "pitch.pptx", "content": "# Catering\n- Fresh daily\n# Pricing\n- $12 a head\n"})
    assert out.startswith("wrote a PowerPoint deck"), out
    with zipfile.ZipFile(tmp_path / "pitch.pptx") as deck:
        assert b"$12 a head" in deck.read("ppt/slides/slide2.xml")


def test_write_file_to_a_pdf_path_makes_a_printable_pdf(tmp_path):
    # Live: asked for "a printable PDF I can download", the agent was refused,
    # delivered a Word file instead and then stopped to ask the person.
    from maverick.sandbox import LocalBackend
    from maverick.tools.fs import write_file

    out = write_file(LocalBackend(workdir=tmp_path)).fn(
        {"path": "checklist.pdf", "content": "# Cleaning\n- [ ] Wipe counters\n"})
    assert out.startswith("wrote a PDF"), out
    assert (tmp_path / "checklist.pdf").read_bytes().startswith(b"%PDF-1.4")


def test_write_file_refuses_an_svg_that_is_not_svg(tmp_path):
    # Live: asked for a bar chart, the agent wrote Markdown with a Mermaid
    # block to monthly_revenue_chart.svg and delivered it; it opens as nothing.
    from maverick.sandbox import LocalBackend
    from maverick.tools.fs import write_file

    tool = write_file(LocalBackend(workdir=tmp_path))
    mermaid = "# Total Revenue by Month\n\n```mermaid\nxychart-beta\n    bar [1, 2]\n```\n"
    out = tool.fn({"path": "chart.svg", "content": mermaid})
    assert out.startswith("ERROR") and "<svg" in out and not (tmp_path / "chart.svg").exists()
    svg = ('<?xml version="1.0"?>\n<!-- revenue -->\n<svg xmlns="http://www.w3.org/2000/svg" width="10" '
           'height="10"><rect width="5" height="5"/></svg>\n')
    assert tool.fn({"path": "chart.svg", "content": svg}).startswith("wrote")
    assert (tmp_path / "chart.svg").read_text() == svg


@pytest.mark.parametrize("name", ["quote.pdf", "quote.docx", "quote.md"])
def test_write_file_says_when_a_documents_totals_do_not_add_up(tmp_path, name):
    # Live: a quote PDF's summary gave a grand total its lines did not add
    # to; only the chat answer and sheets were checked, never a document.
    from maverick.sandbox import LocalBackend
    from maverick.tools.fs import write_file

    tool = write_file(LocalBackend(workdir=tmp_path))
    quote = ("# Quote\n\n| Item | Amount |\n|---|---:|\n| Consulting | $1,740.00 |\n"
             "| Laptops | $3,269.97 |\n| Discount | -$327.00 |\n| Setup | $250.00 |\n"
             "| Sales tax | $220.72 |\n| Grand total | {total} |\n")
    out = tool.fn({"path": name, "content": quote.format(total="$5,253.69")})
    assert "do not add up" in out and "5,153.69" in out, out
    assert (tmp_path / name).exists()  # the file is written; the note asks for a fix
    out = tool.fn({"path": name, "content": quote.format(total="$5,153.69")})
    assert "do not add up" not in out, out
