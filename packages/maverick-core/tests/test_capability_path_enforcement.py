"""Capability layer: path resource-scope enforcement at the tool chokepoint.

A capability whose ``allow_paths`` is non-empty restricts which filesystem
paths the known file tools (read_file/write_file/list_dir/str_replace_editor/
ast_edit/spreadsheet/image_content_classifier/apply_patch) may touch. Default-open: an
empty ``allow_paths`` (the common case, and the only state reachable without
opting into capability enforcement) is a no-op, so normal behaviour is
unchanged.

Mirrors ``tests/test_capability.py``'s ``_agent(tmp_path)`` + ``_run_tool``
setup; hermetic (no real LLM, no network).
"""

import pytest
from maverick.capability import Capability
from maverick.tools import Tool


@pytest.mark.parametrize("name", ["repo_map", "dep_graph", "file_watcher", "semantic_code_search", "cross_repo_deps", "preview_diff", "test_impact", "lsp_bridge", "shell", "git_advanced", "notebook_exec", "container_build", "wasm_run", "model3d_inspect", "openapi_runner", "repl_exec", "audio_understanding", "office_convert", "a11y", "embedded_device", "workspace_snapshot", "html_to_app", "list_dir", "str_replace_editor", "obsidian", "ocr", "memory"])
def test_unscoped_workspace_enumerator_refused(tmp_path, name):
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_paths=frozenset({"allowed/*"}))
    assert "DENIED" in agent._capability_path_denial(name, {}, capability)


@pytest.mark.parametrize("name", ["read_pdf", "pandas_query", "view_video"])
def test_readers_obey_path_restrictions(tmp_path, name):
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_paths=frozenset({"allowed/*"}))
    assert "DENIED" in agent._capability_path_denial(name, {"source": "private/data"}, capability)


@pytest.mark.parametrize("name", ["read_pdf", "pandas_query", "view_image", "view_video", "transcribe_audio"])
def test_reader_scope_uses_the_trimmed_source(tmp_path, name):
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_paths=frozenset({" allowed/*"}))
    assert "DENIED" in agent._capability_path_denial(name, {"source": " allowed/data"}, capability)


@pytest.mark.parametrize("name", ["read_pdf", "view_image"])
def test_reader_scope_expands_home_before_checking(tmp_path, monkeypatch, name):
    monkeypatch.setenv("HOME", str(tmp_path))
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_paths=frozenset({"~/*"}))
    assert "DENIED" in agent._capability_path_denial(name, {"source": "~/private"}, capability)


@pytest.mark.parametrize(("name", "args"), [
    ("sql_query", {"database": " allowed/data.db"}),
    ("sql_query_read", {"database": " allowed/data.db"}),
    ("ocr", {"op": "extract", "path": " allowed/image.png"}),
    ("pandoc", {"op": "convert", "input_path": " allowed/file.md"}),
    ("imagemagick", {"op": "identify", "input_path": " allowed/image.png"}),
    ("ffmpeg", {"op": "info", "input_path": " allowed/video.mp4"}),
    ("image_edit", {"op": "crop", "input_path": " allowed/image.png"}),
])
def test_tool_path_scope_matches_whitespace_normalization(tmp_path, name, args):
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_paths=frozenset({" allowed/*"}))
    assert "DENIED" in agent._capability_path_denial(name, args, capability)


def _agent(tmp_path):
    from maverick.agent import Agent
    from maverick.blackboard import Blackboard
    from maverick.budget import Budget
    from maverick.sandbox import LocalBackend
    from maverick.swarm import SwarmContext
    from maverick.world_model import WorldModel

    world = WorldModel(tmp_path / "world.db")
    goal_id = world.create_goal("g", "")
    ctx = SwarmContext(
        llm=None, world=world, budget=Budget(max_dollars=1.0),
        blackboard=Blackboard(), sandbox=LocalBackend(workdir=tmp_path),
        goal_id=goal_id, use_skills=False,
    )
    return Agent(ctx=ctx, role="coder", brief="b")


def _spy_tool(name: str, calls: list, path_key: str = "path") -> Tool:
    """A fake file-shaped tool that records its calls instead of touching FS."""
    return Tool(
        name=name,
        description="spy",
        fn=lambda args: calls.append(args.get(path_key)) or "ran",
        input_schema={
            "type": "object",
            "properties": {path_key: {"type": "string"}},
        },
    )


@pytest.mark.asyncio
async def test_path_outside_scope_denied_and_tool_not_run(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_paths=frozenset({"repo/*"}))
    calls: list = []
    # Register a fake read_file so a permitted call would be observable; the
    # denied call must NOT reach it.
    agent.tools.register(_spy_tool("read_file", calls))

    out = await agent._run_tool("read_file", {"path": "etc/passwd"})
    assert "DENIED by capability" in out
    assert "agent:coder-1" in out
    assert "etc/passwd" in out
    assert calls == []  # the file tool did not run


@pytest.mark.asyncio
async def test_path_inside_scope_permitted(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_paths=frozenset({"repo/*"}))
    calls: list = []
    agent.tools.register(_spy_tool("read_file", calls))

    out = await agent._run_tool("read_file", {"path": "repo/ok.py"})
    assert "DENIED" not in out
    assert calls == ["repo/ok.py"]  # passed the gate and ran


@pytest.mark.asyncio
async def test_image_classifier_file_path_scope_denied(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_paths=frozenset({"repo/*"}))
    calls: list = []
    agent.tools.register(
        _spy_tool("image_content_classifier", calls, path_key="file")
    )

    out = await agent._run_tool("image_content_classifier", {"file": "secret.png"})

    assert "DENIED by capability" in out
    assert "secret.png" in out
    assert calls == []


@pytest.mark.asyncio
async def test_unclassified_tool_is_denied_for_restricted_paths(tmp_path):
    # An unclassified tool might touch files through hidden inputs.
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_paths=frozenset({"repo/*"}))
    calls: list = []
    agent.tools.register(_spy_tool("not_a_file_tool", calls))

    out = await agent._run_tool("not_a_file_tool", {"path": "etc/passwd"})
    assert "DENIED" in out
    assert not calls


@pytest.mark.asyncio
async def test_no_allow_paths_is_no_path_denial(tmp_path):
    # Default grant (empty allow_paths == all): no path denial.
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1")  # no allow_paths
    calls: list = []
    agent.tools.register(_spy_tool("read_file", calls))

    out = await agent._run_tool("read_file", {"path": "etc/passwd"})
    assert "DENIED" not in out
    assert calls == ["etc/passwd"]


@pytest.mark.asyncio
async def test_unrestricted_capability_none_is_no_path_denial(tmp_path):
    # capability is None == enforcement off entirely.
    agent = _agent(tmp_path)
    agent.capability = None
    calls: list = []
    agent.tools.register(_spy_tool("read_file", calls))

    out = await agent._run_tool("read_file", {"path": "etc/passwd"})
    assert "DENIED" not in out
    assert calls == ["etc/passwd"]


@pytest.mark.asyncio
async def test_missing_path_arg_fails_soft(tmp_path):
    # Fail-soft: a file tool called without its path arg must not crash on the
    # path check -- it falls through to the tool's own validation.
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_paths=frozenset({"repo/*"}))
    calls: list = []
    agent.tools.register(_spy_tool("read_file", calls))

    out = await agent._run_tool("read_file", {})  # no "path"
    assert "DENIED by capability" not in out
    assert calls == [None]  # reached the tool


@pytest.mark.asyncio
async def test_path_denial_is_audited(tmp_path, monkeypatch):
    import maverick.audit
    from maverick.audit import EventKind
    calls = []
    monkeypatch.setattr(maverick.audit, "record",
                        lambda kind, **kw: calls.append((kind, kw)) or True)
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_paths=frozenset({"repo/*"}))
    await agent._run_tool("write_file", {"path": "etc/evil", "content": "x"})
    denied = [kw for k, kw in calls if k == EventKind.CAPABILITY_DENIED]
    assert denied, "path denial was not written to the audit log"
    assert denied[0]["tool"] == "write_file"
    assert denied[0]["principal"] == "agent:coder-1"
    assert denied[0]["path"] == "etc/evil"


@pytest.mark.asyncio
async def test_dotdot_path_checked_after_workspace_canonicalization(tmp_path):
    agent = _agent(tmp_path)
    (tmp_path / "allowed").mkdir()
    (tmp_path / "secret.txt").write_text("SECRET_ROOT", encoding="utf-8")
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_paths=frozenset({"allowed/*"}))

    out = await agent._run_tool("read_file", {"path": "allowed/../secret.txt"})

    assert "DENIED by capability" in out
    assert "secret.txt" in out
    assert "SECRET_ROOT" not in out


@pytest.mark.asyncio
async def test_list_dir_missing_path_checks_default_root(tmp_path):
    agent = _agent(tmp_path)
    (tmp_path / "allowed").mkdir()
    (tmp_path / "secret.txt").write_text("SECRET_ROOT", encoding="utf-8")
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_paths=frozenset({"allowed/*"}))

    out = await agent._run_tool("list_dir", {})

    assert "DENIED by capability" in out
    assert "secret.txt" not in out


@pytest.mark.asyncio
async def test_apply_patch_is_refused_for_restricted_paths(tmp_path):
    import subprocess

    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    (tmp_path / "allowed").mkdir()
    (tmp_path / "secret.txt").write_text("old\n", encoding="utf-8")
    agent = _agent(tmp_path)
    agent.capability = Capability(principal="agent:coder-1",
                                  allow_paths=frozenset({"allowed/*"}))
    patch = """diff --git a/secret.txt b/secret.txt
--- a/secret.txt
+++ b/secret.txt
@@ -1 +1 @@
-old
+new
"""

    out = await agent._run_tool("apply_patch", {"patch": patch})

    assert "DENIED by capability" in out
    assert "cannot enforce" in out
    assert (tmp_path / "secret.txt").read_text(encoding="utf-8") == "old\n"


def test_mode_only_patch_is_refused_for_restricted_paths(tmp_path):
    agent = _agent(tmp_path)
    capability = Capability(principal="agent:coder-1", allow_paths=frozenset({"allowed/*"}))
    patch = "diff --git a/private/script b/private/script\nold mode 100644\nnew mode 100755\n"
    assert "DENIED" in agent._capability_path_denial("apply_patch", {"patch": patch}, capability)


@pytest.mark.asyncio
async def test_sandbox_read_only_path_blocks_in_process_write_tool(tmp_path):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    calls: list = []
    agent.tools.register(_spy_tool("write_file", calls))

    out = await agent._run_tool(
        "write_file",
        {"path": "evidence/PR_DIFF.patch", "content": "tampered"},
    )

    assert "DENIED by sandbox policy" in out
    assert "evidence/PR_DIFF.patch" in out
    assert calls == []


@pytest.mark.asyncio
async def test_sandbox_read_only_path_denial_is_audited(tmp_path, monkeypatch):
    import maverick.audit
    from maverick.audit import EventKind

    events: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        maverick.audit,
        "record",
        lambda kind, **payload: events.append((kind, payload)) or True,
    )
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)

    await agent._run_tool(
        "write_file",
        {"path": "evidence/PR_DIFF.patch", "content": "tampered"},
    )

    denied = [
        payload
        for kind, payload in events
        if kind == EventKind.SANDBOX_DENIED
    ]
    assert denied
    assert denied[0]["path"] == "evidence/PR_DIFF.patch"
    assert denied[0]["reason"] == "read_only_path"


@pytest.mark.asyncio
async def test_sandbox_read_only_path_still_allows_reads(tmp_path):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    calls: list = []
    agent.tools.register(_spy_tool("read_file", calls))

    out = await agent._run_tool("read_file", {"path": "evidence/PR_DIFF.patch"})

    assert "DENIED" not in out
    assert calls == ["evidence/PR_DIFF.patch"]


@pytest.mark.asyncio
async def test_sandbox_read_only_path_blocks_spreadsheet_write_and_preserves_file(
    tmp_path,
):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    evidence = tmp_path / "evidence" / "controls.csv"
    evidence.parent.mkdir()
    evidence.write_text("control,status\nAC-1,passed\n", encoding="utf-8")

    denied = await agent._run_tool(
        "spreadsheet",
        {
            "op": "write",
            "path": "evidence/controls.csv",
            "rows": [["control", "status"], ["AC-1", "failed"]],
        },
    )

    assert "DENIED by sandbox policy" in denied
    assert evidence.read_text(encoding="utf-8") == "control,status\nAC-1,passed\n"

    allowed = await agent._run_tool(
        "spreadsheet",
        {
            "op": "write",
            "path": "work/controls.csv",
            "rows": [["control", "status"], ["AC-1", "passed"]],
        },
    )
    assert "wrote 2 row(s)" in allowed
    assert (tmp_path / "work" / "controls.csv").read_text(
        encoding="utf-8",
    ) == "control,status\nAC-1,passed\n"


@pytest.mark.asyncio
@pytest.mark.parametrize("op", ["write", "set_cell"])
async def test_sandbox_read_only_path_classifies_spreadsheet_mutations(
    tmp_path,
    op,
):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    calls: list = []
    agent.tools.register(_spy_tool("spreadsheet", calls))

    out = await agent._run_tool(
        "spreadsheet",
        {"op": op, "path": "evidence/controls.xlsx"},
    )

    assert "DENIED by sandbox policy" in out
    assert calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("op", ["info", "read"])
async def test_sandbox_read_only_path_preserves_spreadsheet_reads(tmp_path, op):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    calls: list = []
    agent.tools.register(_spy_tool("spreadsheet", calls))

    out = await agent._run_tool(
        "spreadsheet",
        {"op": op, "path": "evidence/controls.xlsx"},
    )

    assert "ran" in out
    assert "DENIED" not in out
    assert calls == ["evidence/controls.xlsx"]


def test_every_known_in_process_workspace_writer_has_mutating_path_metadata():
    """A host-side writer cannot join the registry without dispatch metadata."""
    from maverick.agent import (
        _FILE_TOOL_POLICIES,
        _IN_PROCESS_WORKSPACE_WRITERS,
    )

    expected = {
        "write_file",
        "str_replace_editor",
        "ast_edit",
        "apply_patch",
        "spreadsheet",
        "sql_query",
        "ocr",
        "wasm_run",
        "diagram",
        "latex",
        "image_edit",
        "speak",
        "html_to_app",
        "workspace_snapshot",
        "android",
        "ios_sim",
        "obsidian",
        "memory",
        "browser",
        "oauth_helper",
    }
    assert expected == _IN_PROCESS_WORKSPACE_WRITERS
    declared = {
        "apply_patch",
        "obsidian",
        "memory",
        "browser",
        "oauth_helper",
    } | {
        name
        for name, policy in _FILE_TOOL_POLICIES.items()
        if any(rule.mutates for rule in policy.paths)
    }
    assert expected <= declared


@pytest.mark.asyncio
async def test_sandbox_read_only_path_blocks_real_image_edit_overwrite(tmp_path):
    image_module = pytest.importorskip("PIL.Image")
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    source = tmp_path / "source.png"
    protected = tmp_path / "evidence" / "proof.png"
    protected.parent.mkdir()
    image_module.new("RGB", (2, 2), color="blue").save(source)
    image_module.new("RGB", (5, 5), color="green").save(protected)

    out = await agent._run_tool(
        "image_edit",
        {
            "op": "resize",
            "input_path": "source.png",
            "output_path": "evidence/proof.png",
            "width": 1,
            "height": 1,
        },
    )

    assert "DENIED by sandbox policy" in out
    with image_module.open(protected) as image:
        assert image.size == (5, 5)


@pytest.mark.asyncio
async def test_sandbox_read_only_path_blocks_in_place_image_edit(tmp_path):
    image_module = pytest.importorskip("PIL.Image")
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    protected = tmp_path / "evidence" / "proof.png"
    protected.parent.mkdir()
    image_module.new("RGB", (5, 5), color="green").save(protected)

    out = await agent._run_tool(
        "image_edit",
        {
            "op": "resize",
            "input_path": "evidence/proof.png",
            "output_path": "evidence/proof.png",
            "width": 1,
            "height": 1,
        },
    )

    assert "DENIED by sandbox policy" in out
    with image_module.open(protected) as image:
        assert image.size == (5, 5)


@pytest.mark.asyncio
async def test_sandbox_read_only_path_blocks_real_snapshot_restore(
    tmp_path,
    monkeypatch,
):
    import maverick.workspace_snapshot as snapshot_module

    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    protected = tmp_path / "evidence" / "proof.txt"
    protected.parent.mkdir()
    protected.write_text("trusted", encoding="utf-8")
    source = tmp_path / "snapshot-source"
    source.mkdir()
    (source / "proof.txt").write_text("tampered", encoding="utf-8")
    store = tmp_path / "snapshot-store"
    manifest = snapshot_module.create_snapshot(source, store)
    monkeypatch.setattr(snapshot_module, "store_dir", lambda: store)

    out = await agent._run_tool(
        "workspace_snapshot",
        {"op": "restore", "id": manifest["id"], "dest": "evidence"},
    )

    assert "DENIED by sandbox policy" in out
    assert protected.read_text(encoding="utf-8") == "trusted"


@pytest.mark.asyncio
async def test_snapshot_restore_ancestor_cannot_overwrite_protected_descendant(
    tmp_path,
    monkeypatch,
):
    import maverick.workspace_snapshot as snapshot_module

    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    protected = tmp_path / "evidence" / "proof.txt"
    protected.parent.mkdir()
    protected.write_text("trusted", encoding="utf-8")
    source = tmp_path / "snapshot-source"
    (source / "evidence").mkdir(parents=True)
    (source / "evidence" / "proof.txt").write_text(
        "tampered",
        encoding="utf-8",
    )
    store = tmp_path / "snapshot-store"
    manifest = snapshot_module.create_snapshot(source, store)
    monkeypatch.setattr(snapshot_module, "store_dir", lambda: store)

    out = await agent._run_tool(
        "workspace_snapshot",
        {"op": "restore", "id": manifest["id"], "dest": "."},
    )

    assert "DENIED by sandbox policy" in out
    assert protected.read_text(encoding="utf-8") == "trusted"


@pytest.mark.asyncio
async def test_snapshot_archive_store_honors_protected_workspace(
    tmp_path,
    monkeypatch,
):
    import maverick.workspace_snapshot as snapshot_module

    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    source = tmp_path / "source"
    source.mkdir()
    (source / "input.txt").write_text("source", encoding="utf-8")
    store = tmp_path / "evidence" / "snapshots"
    monkeypatch.setattr(snapshot_module, "store_dir", lambda: store)

    out = await agent._run_tool(
        "workspace_snapshot",
        {"op": "snapshot", "path": "source", "label": "proof"},
    )

    assert "DENIED by sandbox policy" in out
    assert not store.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "args", "protected_path"),
    [
        ("diagram", {"engine": "dot", "source": "digraph {}", "format": "svg"}, "diagram.svg"),
        ("latex", {"op": "render", "latex": "x"}, "doc.pdf"),
        ("speak", {"text": "hello"}, "speech-1.mp3"),
        ("html_to_app", {"op": "scaffold", "html": "<p>x</p>", "dest": "evidence/app"}, "evidence"),
        (
            "wasm_run",
            {"op": "run", "module": "module.wasm", "dirs": ["evidence"]},
            "evidence",
        ),
        (
            "android",
            {"op": "screenshot", "out_path": "evidence/android.png"},
            "evidence",
        ),
        (
            "ios_sim",
            {"op": "screenshot", "out_path": "evidence/ios.png"},
            "evidence",
        ),
    ],
)
async def test_declared_host_writers_honor_read_only_paths(
    tmp_path,
    name,
    args,
    protected_path,
):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = (protected_path,)
    calls: list = []
    agent.tools.register(
        Tool(
            name=name,
            description="writer spy",
            fn=lambda payload: calls.append(payload) or "ran",
            input_schema={"type": "object", "properties": {}},
        )
    )

    out = await agent._run_tool(name, args)

    assert "DENIED by sandbox policy" in out
    assert calls == []


@pytest.mark.asyncio
async def test_obsidian_write_is_blocked_when_vault_overlaps_protected_workspace(
    tmp_path,
    monkeypatch,
):
    from maverick.tools import obsidian as obsidian_module

    vault = tmp_path / "evidence" / "vault"
    vault.mkdir(parents=True)
    monkeypatch.setattr(obsidian_module, "_vault", lambda: vault)
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    calls: list = []
    agent.tools.register(
        Tool(
            name="obsidian",
            description="writer spy",
            fn=lambda payload: calls.append(payload) or "ran",
            input_schema={"type": "object", "properties": {}},
        )
    )

    out = await agent._run_tool(
        "obsidian",
        {"op": "create", "note": "proof.md", "body": "tampered"},
    )

    assert "DENIED by sandbox policy" in out
    assert calls == []


@pytest.mark.asyncio
async def test_external_obsidian_vault_remains_usable_with_allow_all_paths(
    tmp_path,
    monkeypatch,
):
    from maverick.file_lock import prepare_private_directory
    from maverick.tools import obsidian as obsidian_module

    workdir = tmp_path / "work"
    prepare_private_directory(workdir)
    vault = tmp_path / "external-vault"
    vault.mkdir()
    monkeypatch.setattr(obsidian_module, "_vault", lambda: vault)
    agent = _agent(workdir)
    agent.capability = Capability(principal="agent:coder-1")

    out = await agent._run_tool(
        "obsidian",
        {"op": "create", "note": "proof.md", "body": "allowed"},
    )

    assert "DENIED" not in out
    assert (vault / "proof.md").read_text(encoding="utf-8") == "allowed"


@pytest.mark.asyncio
@pytest.mark.parametrize("read_only_value", [False, 0, "", [], {}])
async def test_sql_query_falsy_non_none_write_mode_cannot_mutate_protected_db(
    tmp_path,
    read_only_value,
):
    import sqlite3

    agent = _agent(tmp_path)
    protected_dir = tmp_path / "evidence"
    protected_dir.mkdir()
    database = protected_dir / "controls.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE controls(value TEXT)")
    agent.ctx.sandbox.read_only_paths = ("evidence",)

    out = await agent._run_tool(
        "sql_query",
        {
            "database": "evidence/controls.db",
            "query": "INSERT INTO controls VALUES ('tampered')",
            "read_only": read_only_value,
        },
    )

    assert "DENIED by sandbox policy" in out
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_sql_query_default_read_only_mode_can_read_protected_db(tmp_path):
    import sqlite3

    agent = _agent(tmp_path)
    protected_dir = tmp_path / "evidence"
    protected_dir.mkdir()
    database = protected_dir / "controls.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE controls(value TEXT)")
        conn.execute("INSERT INTO controls VALUES ('trusted')")
    agent.ctx.sandbox.read_only_paths = ("evidence",)

    out = await agent._run_tool(
        "sql_query",
        {
            "database": "evidence/controls.db",
            "query": "SELECT value FROM controls",
        },
    )

    assert "DENIED" not in out
    assert "trusted" in out


@pytest.mark.asyncio
async def test_sql_query_write_honors_protected_wal_sidecar(tmp_path):
    import sqlite3

    agent = _agent(tmp_path)
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    database = evidence / "controls.db"
    with sqlite3.connect(database) as conn:
        conn.execute("CREATE TABLE controls(value TEXT)")
    agent.ctx.sandbox.read_only_paths = ("evidence/controls.db-wal",)

    out = await agent._run_tool(
        "sql_query",
        {
            "database": "evidence/controls.db",
            "query": "INSERT INTO controls VALUES ('tampered')",
            "read_only": False,
        },
    )

    assert "DENIED by sandbox policy" in out
    with sqlite3.connect(database) as conn:
        assert conn.execute("SELECT COUNT(*) FROM controls").fetchone()[0] == 0


@pytest.mark.asyncio
async def test_configured_memory_root_honors_protected_workspace(
    tmp_path,
    monkeypatch,
):
    memory_root = tmp_path / "evidence" / "memory"
    monkeypatch.setenv("MAVERICK_MEMORY_DIR", str(memory_root))
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)

    out = await agent._run_tool(
        "memory",
        {"command": "create", "path": "proof.md", "file_text": "tampered"},
    )

    assert "DENIED by sandbox policy" in out
    assert not (memory_root / "proof.md").exists()


@pytest.mark.asyncio
async def test_memory_view_does_not_create_missing_configured_root(
    tmp_path,
    monkeypatch,
):
    memory_root = tmp_path / "evidence" / "memory"
    monkeypatch.setenv("MAVERICK_MEMORY_DIR", str(memory_root))
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)

    out = await agent._run_tool("memory", {"command": "view"})

    assert "DENIED" not in out
    assert "memory is empty" in out
    assert not memory_root.exists()


@pytest.mark.asyncio
async def test_configured_browser_state_honors_protected_workspace(
    tmp_path,
    monkeypatch,
):
    state = tmp_path / "evidence" / "browser-state.json"
    monkeypatch.setenv("MAVERICK_BROWSER_STATE", str(state))
    monkeypatch.delenv("MAVERICK_BROWSER_NO_PERSIST", raising=False)
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    calls: list[dict] = []
    agent.tools.register(
        Tool(
            name="browser",
            description="browser spy",
            fn=lambda payload: calls.append(payload) or "ran",
            input_schema={"type": "object", "properties": {}},
        )
    )

    out = await agent._run_tool(
        "browser",
        {"action": "navigate", "url": "https://example.test"},
    )

    assert "DENIED by sandbox policy" in out
    assert calls == []


@pytest.mark.asyncio
async def test_configured_oauth_sink_honors_protected_workspace(
    tmp_path,
    monkeypatch,
):
    from maverick import oauth_vault

    sink = tmp_path / "evidence" / "tokens.json"
    monkeypatch.setenv("MAVERICK_OAUTH_OUT", str(sink))
    monkeypatch.setattr(oauth_vault, "enabled", lambda: False)
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    calls: list[dict] = []
    agent.tools.register(
        Tool(
            name="oauth_helper",
            description="oauth spy",
            fn=lambda payload: calls.append(payload) or "ran",
            input_schema={"type": "object", "properties": {}},
        )
    )

    out = await agent._run_tool("oauth_helper", {"op": "exchange"})

    assert "DENIED by sandbox policy" in out
    assert calls == []


@pytest.mark.asyncio
async def test_ocr_url_temp_write_honors_read_only_workspace_root(tmp_path):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = (".",)
    calls: list[dict] = []
    agent.tools.register(
        Tool(
            name="ocr",
            description="ocr spy",
            fn=lambda payload: calls.append(payload) or "ran",
            input_schema={"type": "object", "properties": {}},
        )
    )

    out = await agent._run_tool(
        "ocr",
        {"op": "extract_url", "url": "https://example.test/proof.png"},
    )

    assert "DENIED by sandbox policy" in out
    assert calls == []


@pytest.mark.asyncio
async def test_speak_dynamic_default_is_frozen_before_hooks(
    tmp_path,
    monkeypatch,
):
    from maverick import hooks
    from maverick.hooks import HookEvent

    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("speech-2.mp3",)
    calls: list[dict] = []

    def run_speak(payload):
        output = payload.get("output")
        if not output:
            index = 1
            while (tmp_path / f"speech-{index}.mp3").exists():
                index += 1
            output = f"speech-{index}.mp3"
        calls.append(dict(payload))
        (tmp_path / output).write_text("audio", encoding="utf-8")
        return f"wrote {output}"

    agent.tools.register(
        Tool(
            name="speak",
            description="speak race spy",
            fn=run_speak,
            input_schema={"type": "object", "properties": {}},
        )
    )

    async def race_after_policy(ctx):
        if ctx.event == HookEvent.PRE_TOOL_USE:
            (tmp_path / "speech-1.mp3").write_text(
                "concurrent",
                encoding="utf-8",
            )
        return True

    monkeypatch.setattr(hooks, "dispatch", race_after_policy)

    out = await agent._run_tool("speak", {"text": "hello"})

    assert "DENIED" not in out
    assert calls[0]["output"] == "speech-1.mp3"
    assert not (tmp_path / "speech-2.mp3").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("latex", {"op": "mathml", "latex": "x"}),
        (
            "image_edit",
            {"op": "variation", "image": "https://example.test/image.png"},
        ),
        ("workspace_snapshot", {"op": "snapshot", "path": "evidence"}),
    ],
)
async def test_declared_read_operations_remain_available(
    tmp_path,
    name,
    args,
):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    calls: list = []
    agent.tools.register(
        Tool(
            name=name,
            description="reader spy",
            fn=lambda payload: calls.append(payload) or "ran",
            input_schema={"type": "object", "properties": {}},
        )
    )

    out = await agent._run_tool(name, args)

    assert "DENIED" not in out
    assert calls == [args]


@pytest.mark.asyncio
async def test_sandbox_read_only_path_blocks_patch_descendant(tmp_path):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    calls: list = []
    agent.tools.register(_spy_tool("apply_patch", calls, path_key="patch"))
    patch = """diff --git a/evidence/PR_DIFF.patch b/evidence/PR_DIFF.patch
--- a/evidence/PR_DIFF.patch
+++ b/evidence/PR_DIFF.patch
@@ -1 +1 @@
-trusted
+tampered
"""

    out = await agent._run_tool("apply_patch", {"patch": patch})

    assert "DENIED by sandbox policy" in out
    assert "evidence/PR_DIFF.patch" in out
    assert calls == []


@pytest.mark.asyncio
async def test_wasm_run_preopen_dirs_outside_scope_denied(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(
        principal="agent:coder-1",
        allow_tools=frozenset({"wasm_run"}),
        allow_paths=frozenset({"allowed/*"}),
    )
    calls: list = []
    agent.tools.register(Tool(
        name="wasm_run",
        description="spy",
        fn=lambda args: calls.append(args) or "ran",
        input_schema={"type": "object", "properties": {}},
    ))

    out = await agent._run_tool(
        "wasm_run",
        {"op": "run", "module": "allowed/module.wasm", "dirs": ["secret"]},
    )

    assert "DENIED by capability" in out
    assert "cannot enforce" in out
    assert calls == []


@pytest.mark.asyncio
async def test_wasm_run_module_outside_scope_denied(tmp_path):
    agent = _agent(tmp_path)
    agent.capability = Capability(
        principal="agent:coder-1",
        allow_tools=frozenset({"wasm_run"}),
        allow_paths=frozenset({"allowed/*"}),
    )
    calls: list = []
    agent.tools.register(Tool(
        name="wasm_run",
        description="spy",
        fn=lambda args: calls.append(args) or "ran",
        input_schema={"type": "object", "properties": {}},
    ))

    out = await agent._run_tool(
        "wasm_run",
        {"op": "run", "module": "secret/module.wasm", "dirs": ["allowed/data"]},
    )

    assert "DENIED by capability" in out
    assert "cannot enforce" in out
    assert calls == []


@pytest.mark.parametrize("header", [
    "--- x/evidence/f.txt\n+++ x/evidence/f.txt\n",          # any prefix, stripped by git -p1
    '--- "a/evid\\145nce/f.txt"\n+++ "b/evid\\145nce/f.txt"\n',  # C-quoted name
])
def test_sandbox_read_only_path_reads_patch_names_as_git_apply_does(tmp_path, header):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)
    patch = header + "@@ -1 +1 @@\n-old\n+new\n"

    assert "DENIED by sandbox policy" in agent._read_only_path_denial("apply_patch", {"patch": patch})


@pytest.mark.parametrize("patch", [
    # git diff --binary: no ---/+++ lines, only the diff --git header.
    "diff --git a/evidence/f.bin b/evidence/f.bin\nindex 1..2 100644\nGIT binary patch\n"
    "literal 3\nKcmZ?wbPWIi0RRF3\n\nliteral 0\nKcmV+b0RR6000031\n\n",
    # mode-only change
    "diff --git a/evidence/run.sh b/evidence/run.sh\nold mode 100644\nnew mode 100755\n",
])
def test_sandbox_read_only_path_covers_binary_and_mode_only_patches(tmp_path, patch):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)

    assert "DENIED by sandbox policy" in agent._read_only_path_denial("apply_patch", {"patch": patch})


def test_a_patch_whose_targets_cannot_be_read_is_denied(tmp_path):
    agent = _agent(tmp_path)
    agent.ctx.sandbox.read_only_paths = ("evidence",)

    out = agent._read_only_path_denial("apply_patch", {"patch": "diff --git a/x b/y z\nGIT binary patch\n"})
    assert "DENIED" in out and "unreadable" in out
