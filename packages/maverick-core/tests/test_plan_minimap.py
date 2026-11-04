"""Plan-tree minimap: glyphs, indentation, depth budget, collapsed counts."""
from __future__ import annotations

from maverick import plan_minimap as pm
from maverick.world_model import WorldModel


def _world(tmp_path) -> WorldModel:
    return WorldModel(tmp_path / "world.db")


def _tree(w):
    """root -> (a -> a1 -> a1x, b); statuses cover the glyph map."""
    root = w.create_goal("ship the release", "")
    a = w.create_goal("write the changelog", "", parent_id=root)
    b = w.create_goal("tag the build", "", parent_id=root)
    a1 = w.create_goal("collect merged PRs", "", parent_id=a)
    a1x = w.create_goal("dedupe entries", "", parent_id=a1)
    w.set_goal_status(root, "active")
    w.set_goal_status(a, "done")
    w.set_goal_status(b, "blocked")
    return root, a, b, a1, a1x


def test_one_line_per_node_with_glyphs_and_indent(tmp_path):
    w = _world(tmp_path)
    root, a, b, a1, a1x = _tree(w)
    out = pm.render_minimap(w, root, max_depth=5)
    lines = out.splitlines()
    assert lines[0] == f"◐ #{root} ship the release"          # active, depth 0
    assert lines[1] == f"  ● #{a} write the changelog"        # done, depth 1
    assert f"    ◌ #{a1} collect merged PRs" in lines         # pending, depth 2
    assert f"      ◌ #{a1x} dedupe entries" in lines          # depth 3
    assert f"  ⊘ #{b} tag the build" in lines                 # blocked, depth 1
    assert len(lines) == 5


def test_depth_budget_collapses_with_count(tmp_path):
    w = _world(tmp_path)
    root, a, b, a1, a1x = _tree(w)
    out = pm.render_minimap(w, root, max_depth=1)
    lines = out.splitlines()
    # a's subtree (a1 + a1x = 2 nodes) collapses under a, one level deeper.
    assert f"  ● #{a} write the changelog" in lines
    assert "    ▸ +2 collapsed" in lines
    assert "collect merged PRs" not in out
    # b is a leaf: no collapse marker under it.
    assert lines[-1] == f"  ⊘ #{b} tag the build"


def test_depth_zero_collapses_everything(tmp_path):
    w = _world(tmp_path)
    root, *_ = _tree(w)
    out = pm.render_minimap(w, root, max_depth=0)
    lines = out.splitlines()
    assert len(lines) == 2
    assert lines[1] == "  ▸ +4 collapsed"


def test_unknown_goal_renders_empty(tmp_path):
    assert pm.render_minimap(_world(tmp_path), 999) == ""


def test_unknown_status_gets_default_glyph(tmp_path):
    w = _world(tmp_path)
    gid = w.create_goal("odd one", "")
    w.set_goal_status(gid, "weird")
    assert pm.render_minimap(w, gid).startswith(f"· #{gid} ")


def test_long_titles_are_clipped(tmp_path):
    w = _world(tmp_path)
    gid = w.create_goal("x" * 200, "")
    line = pm.render_minimap(w, gid, max_title=20).splitlines()[0]
    assert line.endswith("…")
    assert len(line.split(" ", 2)[2]) == 20


def test_cancelled_glyph_and_subtree_only(tmp_path):
    """The minimap renders the requested goal's subtree, not the whole DB."""
    w = _world(tmp_path)
    root, a, b, a1, a1x = _tree(w)
    w.set_goal_status(a1x, "cancelled")
    out = pm.render_minimap(w, a, max_depth=5)
    assert out.splitlines()[0].startswith(f"● #{a}")
    assert f"⊗ #{a1x}" in out
    assert "tag the build" not in out  # sibling branch excluded
