"""File + image attachment storage."""
from __future__ import annotations

import hashlib
import os

import pytest
from maverick import attachments, file_lock
from maverick import paths as maverick_paths
from maverick.attachments import (
    MAX_FILE_BYTES,
    MAX_GOAL_BYTES,
    AttachmentRejected,
    content_blocks_for_goal,
    store,
)
from maverick.world_model import WorldModel


def test_store_text_writes_to_disk(tmp_path):
    data = b"hello world\n"
    out = store(
        goal_id=42,
        filename="notes.txt",
        mime="text/plain",
        data=data,
        root=tmp_path,
    )
    assert out.filename == "notes.txt"
    assert out.mime == "text/plain"
    assert out.size_bytes == len(data)
    assert out.path.exists()
    assert attachments.read_bytes(out.path) == data  # sealed at rest in the secure posture
    # sha-prefixed dest avoids name collisions.
    assert out.path.name.startswith(out.sha256[:16] + "-")
    assert file_lock.private_path_is_restricted(out.path.parent, 0o700)
    assert file_lock.private_path_is_restricted(out.path)


def test_default_attachment_root_resolves_per_tenant_context(tmp_path, monkeypatch):
    import maverick.attachments as attachment_module

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setattr(attachment_module, "DEFAULT_ROOT", None)

    # Each workspace's copy is read back in that workspace: in the secure
    # posture it is sealed to that workspace's key.
    first_token = maverick_paths.set_tenant("tenant-a")
    try:
        first = store(1, "report.txt", "text/plain", b"tenant a")
        assert attachments.read_bytes(first.path) == b"tenant a"
    finally:
        maverick_paths.reset_tenant(first_token)

    second_token = maverick_paths.set_tenant("tenant-b")
    try:
        second = store(1, "report.txt", "text/plain", b"tenant b")
        assert attachments.read_bytes(second.path) == b"tenant b"
    finally:
        maverick_paths.reset_tenant(second_token)

    assert first.path != second.path
    assert tmp_path / "tenants" / "tenant-a" / "attachments" in first.path.parents
    assert tmp_path / "tenants" / "tenant-b" / "attachments" in second.path.parents


@pytest.mark.parametrize(
    "filename",
    [
        "report:secret.txt",  # NTFS alternate data stream
        "report?.txt",
        "report*.txt",
        "report|notes.txt",
        'report"notes.txt',
        "report<old>.txt",
        "CON",
        "con.txt",
        "CON .txt",
        "LPT9.csv",
        "COM¹.log",
        "trailing-dot.",
        "trailing-space ",
    ],
)
def test_store_rejects_portability_filename_attacks(tmp_path, filename):
    with pytest.raises(AttachmentRejected):
        store(
            goal_id=1,
            filename=filename,
            mime="text/plain",
            data=b"safe text",
            root=tmp_path,
        )


def test_store_rejects_filename_that_overflows_content_address_component(tmp_path):
    with pytest.raises(AttachmentRejected, match="too long"):
        store(
            goal_id=1,
            filename="a" * 239,
            mime="text/plain",
            data=b"safe text",
            root=tmp_path,
        )


def test_store_refuses_planted_content_address_without_overwriting(tmp_path):
    data = b"expected content"
    digest = hashlib.sha256(data).hexdigest()
    goal_dir = file_lock.ensure_private_directory(tmp_path / "7")
    planted = goal_dir / f"{digest[:16]}-report.txt"
    file_lock.atomic_create_bytes(planted, b"attacker content")

    with pytest.raises(AttachmentRejected, match="content-address mismatch"):
        store(
            goal_id=7,
            filename="report.txt",
            mime="text/plain",
            data=data,
            root=tmp_path,
        )

    assert planted.read_bytes() == b"attacker content"


def test_store_refuses_planted_symlink_without_touching_referent(tmp_path):
    data = b"expected content"
    digest = hashlib.sha256(data).hexdigest()
    goal_dir = file_lock.ensure_private_directory(tmp_path / "7")
    referent = tmp_path / "referent.txt"
    referent.write_bytes(b"do not overwrite")
    planted = goal_dir / f"{digest[:16]}-report.txt"
    try:
        os.symlink(referent, planted)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is unavailable on this host")

    with pytest.raises(AttachmentRejected, match="single-link regular file"):
        store(
            goal_id=7,
            filename="report.txt",
            mime="text/plain",
            data=data,
            root=tmp_path,
        )

    assert referent.read_bytes() == b"do not overwrite"


def test_store_rejects_unknown_mime(tmp_path):
    with pytest.raises(AttachmentRejected, match="mime type not allowed"):
        store(
            goal_id=1, filename="malware.exe",
            mime="application/x-msdownload", data=b"MZ\x00",
            root=tmp_path,
        )


def test_store_rejects_elf_under_benign_mime(tmp_path):
    # An ELF executable smuggled in under a client-supplied text/plain
    # Content-Type must be rejected by the magic-byte deny, regardless of
    # the (advisory, client-controlled) claimed mime.
    elf = b"\x7fELF" + b"\x02\x01\x01\x00" + b"\x00" * 64
    with pytest.raises(AttachmentRejected, match="executable or archive"):
        store(
            goal_id=1, filename="evil.txt",
            mime="text/plain", data=elf, root=tmp_path,
        )


def test_text_that_starts_with_executable_letters_is_accepted():
    # "MZ" and "BZh" are also ordinary letters: only content that reads as
    # plain text is let through, real executables and archives stay denied.
    import bz2

    from maverick.attachments import validate_attachment

    validate_attachment("notes.txt", "text/plain", b"MZ is my initials. hello\n")
    validate_attachment("notes.txt", "text/plain", "BZh\u00e9 and more\n".encode() * 2000)
    pe = b"MZ\x90\x00\x03" + b"A" * 55 + b"\x40\x00\x00\x00PE\x00\x00"
    for payload in (pe, b"MZ" + b"A" * 6000 + b"PE\x00\x00", b"MZ\x1b[0m text",
                    b"MZ caf\xe9", bz2.compress(b"hello"), bz2.compress(b"x" * 100000)):
        with pytest.raises(AttachmentRejected, match="executable or archive"):
            validate_attachment("notes.txt", "text/plain", payload)


def test_store_rejects_zip_under_benign_mime(tmp_path):
    # ZIP/PK bytes under a benign text/csv type must also be denied.
    zip_bytes = b"PK\x03\x04" + b"\x00" * 32
    with pytest.raises(AttachmentRejected, match="executable or archive"):
        store(
            goal_id=1, filename="data.csv",
            mime="text/csv", data=zip_bytes, root=tmp_path,
        )


def test_store_allows_legitimate_text(tmp_path):
    # The deny must not reject ordinary text content.
    out = store(
        goal_id=1, filename="ok.txt", mime="text/plain",
        data=b"a perfectly ordinary note\n", root=tmp_path,
    )
    assert out.path.exists()


def test_store_rejects_empty(tmp_path):
    with pytest.raises(AttachmentRejected, match="empty file"):
        store(
            goal_id=1, filename="empty.txt",
            mime="text/plain", data=b"", root=tmp_path,
        )


def test_store_rejects_oversized(tmp_path):
    with pytest.raises(AttachmentRejected, match="file too large"):
        store(
            goal_id=1, filename="big.txt",
            mime="text/plain",
            data=b"x" * (MAX_FILE_BYTES + 1),
            root=tmp_path,
        )


def test_store_rejects_path_traversal(tmp_path):
    with pytest.raises(AttachmentRejected, match="invalid filename"):
        store(
            goal_id=1, filename="../escape.txt",
            mime="text/plain", data=b"x", root=tmp_path,
        )


def test_store_enforces_per_goal_quota(tmp_path):
    # Filling 90% of quota then trying to add more than 10% must reject.
    near_full = MAX_GOAL_BYTES - 100
    with pytest.raises(AttachmentRejected, match="quota exceeded"):
        store(
            goal_id=1, filename="x.txt", mime="text/plain",
            data=b"x" * 1000,
            existing_total=near_full,
            root=tmp_path,
        )


def test_world_model_persists_attachment(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    gid = wm.create_goal("test", "")
    out = store(
        goal_id=gid, filename="hi.txt", mime="text/plain",
        data=b"hi", root=tmp_path / "attach",
    )
    aid = wm.add_attachment(
        goal_id=gid, filename=out.filename, mime=out.mime,
        size_bytes=out.size_bytes, sha256=out.sha256, path=str(out.path),
    )
    assert aid > 0

    attachments = wm.list_attachments(gid)
    assert len(attachments) == 1
    assert attachments[0].filename == "hi.txt"
    assert attachments[0].sha256 == out.sha256


def test_image_attachments_become_vision_blocks(tmp_path):
    # 1x1 PNG transparent pixel, minimal valid bytes
    png_bytes = bytes.fromhex(
        "89504E470D0A1A0A0000000D49484452000000010000000108060000001F15C4"
        "890000000A49444154789C6300010000000500010D0A2DB40000000049454E44"
        "AE426082"
    )
    wm = WorldModel(path=tmp_path / "w.db")
    gid = wm.create_goal("vision", "")
    out = store(
        goal_id=gid, filename="pixel.png", mime="image/png",
        data=png_bytes, root=tmp_path / "attach",
    )
    wm.add_attachment(
        goal_id=gid, filename=out.filename, mime=out.mime,
        size_bytes=out.size_bytes, sha256=out.sha256, path=str(out.path),
    )

    blocks = content_blocks_for_goal(wm, gid)
    assert len(blocks) == 1
    assert blocks[0]["type"] == "image"
    assert blocks[0]["source"]["type"] == "base64"
    assert blocks[0]["source"]["media_type"] == "image/png"
    assert blocks[0]["source"]["data"]


def test_text_attachment_is_not_vision_block(tmp_path):
    wm = WorldModel(path=tmp_path / "w.db")
    gid = wm.create_goal("textonly", "")
    out = store(
        goal_id=gid, filename="hi.txt", mime="text/plain",
        data=b"hi", root=tmp_path / "attach",
    )
    wm.add_attachment(
        goal_id=gid, filename=out.filename, mime=out.mime,
        size_bytes=out.size_bytes, sha256=out.sha256, path=str(out.path),
    )
    # Text attachments are reachable via list_attachments + read_file,
    # not auto-embedded.
    blocks = content_blocks_for_goal(wm, gid)
    assert blocks == []


def test_list_attachments_tool_returns_metadata(tmp_path):
    from maverick.tools.attachments import list_attachments_tool

    wm = WorldModel(path=tmp_path / "w.db")
    gid = wm.create_goal("attached", "")
    out = store(
        goal_id=gid, filename="a.txt", mime="text/plain",
        data=b"a", root=tmp_path / "attach",
    )
    wm.add_attachment(
        goal_id=gid, filename=out.filename, mime=out.mime,
        size_bytes=out.size_bytes, sha256=out.sha256, path=str(out.path),
    )
    tool = list_attachments_tool(wm, gid)
    result = tool.fn({})
    assert "a.txt" in result
    assert "text/plain" in result


def test_list_attachments_tool_no_goal(tmp_path):
    """The tool returns a friendly stub when there's no goal context."""
    from maverick.tools.attachments import list_attachments_tool
    wm = WorldModel(path=tmp_path / "w.db")
    tool = list_attachments_tool(wm, None)
    assert "no goal context" in tool.fn({})
