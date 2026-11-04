"""Produce real native exports in an isolated home for offline browser tests."""
from __future__ import annotations

import argparse
import io
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from server import block_outbound, environment


def build(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="lightwork-archive-source-") as temporary:
        directory = Path(temporary)
        environment(directory)
        block_outbound()
        from maverick import config
        from maverick.deliverable_bundle_export import export_zip
        from maverick.deliverable_bundles import DeliverableBundles
        from maverick.goal_bundle import prepare_goal_archive
        from maverick.paths import tenant_scope
        from maverick.world_model import WorldModel

        config.reset_config_cache()
        with tenant_scope(tenant="browser-workspace"), WorldModel(directory / "world.db") as world:
            goal = world.create_goal("Portable evidence <script>unsafe()</script>",
                                     "Review this saved source on another device.", owner="user:archive-owner")
            world.set_goal_status(goal, "done", result="Captured result — café; no external action.")
            world.add_artifact(goal, kind="text", title="Unselected confidential file", content="Never include this artifact.")
            artifact = world.add_artifact(goal, kind="table", title="Selected evidence table",
                                          content="| Source | Value |\n| --- | --- |\n| =UNTRUSTED() | 12 |")
            world.append_event(goal, "fixture", "observation", "Original evidence <img src=https://blocked.invalid/x>")
            prepared = prepare_goal_archive(world, goal)
            archive = b"".join(prepared.chunks())
            (destination / "task.json").write_bytes(archive)
            service = DeliverableBundles(world, actor="user:archive-owner",
                                         eligible=lambda principal, *_: principal in {"user:archive-owner", "user:recipient"})
            choices = {"artifact_ids": [artifact], "attachment_ids": [], "include_result": False,
                       "name": "Recipient evidence bundle", "recipient": "user:recipient",
                       "note": "Review the exact selected table.", "unresolved": "Verify the source figures.", "lifetime": 86400}
            preview = service.prepare(goal, **choices)
            bundle = service.create(goal, expected_review=preview["review_version"],
                                    operation_id="browser-offline-export", **choices)
            payload = export_zip(bundle)
            (destination / "bundle.zip").write_bytes(payload)
            unpacked = destination / "bundle"
            unpacked.mkdir()
            with zipfile.ZipFile(io.BytesIO(payload)) as zipped:
                # Export-generated names are checked before writing this fixture.
                for name in zipped.namelist():
                    if Path(name).name != name:
                        raise AssertionError("Native export produced a non-flat entry")
                    (unpacked / name).write_bytes(zipped.read(name))
            (destination / "fixture.json").write_text(json.dumps({"goal": goal, "outbound_calls": "blocked",
                "archive_bytes": len(archive), "source_database_exists_after_export": True}), encoding="utf-8")
        viewer = Path(__file__).resolve().parents[2] / "maverick_dashboard/static/lightwork-archive-viewer.html"
        shutil.copyfile(viewer, destination / "viewer.html")
    # Only the exported files remain. The original home/database have gone, so
    # the receiving browser cannot accidentally consult live installation A.
    assert not directory.exists()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    build(parser.parse_args().output)
