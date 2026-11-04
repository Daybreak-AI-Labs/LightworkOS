"""Versioned asset identity follows file contents and cannot escape its root."""
from __future__ import annotations

import hashlib

from maverick_dashboard.static_asset_versioning import AssetVersions


def test_asset_versions_change_after_content_changes(tmp_path):
    asset = tmp_path / "view.js"
    asset.write_text("first", encoding="utf-8")
    versions = AssetVersions(tmp_path)
    assert versions.version("view.js") == hashlib.sha256(b"first").hexdigest()[:8]

    asset.write_text("second", encoding="utf-8")
    assert versions.version("view.js") == hashlib.sha256(b"second").hexdigest()[:8]
    asset.unlink()
    assert versions.version("view.js") == ""


def test_asset_version_rejects_paths_outside_the_asset_directory(tmp_path):
    versions = AssetVersions(tmp_path)
    for name in ("", "../secret", "folder/file.js", "folder\\file.js", ".hidden"):
        assert versions.version(name) == ""
