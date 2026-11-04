"""The skill-validator service endpoint lints a posted SKILL.md."""
from __future__ import annotations

import asyncio

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})

VALID = """---
name: refund-helper
triggers:
  - process a refund
tools_needed:
  - stripe
---

# What this skill does

Issue a refund and notify the customer, then verify the ledger entry.

# Steps

1. Look up the charge. 2. Refund. 3. Verify.
"""


def test_valid_skill_passes():
    r = client.post("/api/v1/skills/validate", content=VALID.encode())
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["ok"] is True and data["errors"] == []


def test_invalid_skill_reports_errors():
    r = client.post("/api/v1/skills/validate", content=b"no frontmatter at all")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False and data["errors"]


def test_empty_and_oversize_rejected():
    assert client.post("/api/v1/skills/validate", content=b"").status_code == 400
    big = b"x" * (256 * 1024 + 1)
    assert client.post("/api/v1/skills/validate", content=big).status_code == 413


def test_oversize_content_length_rejected_before_streaming():
    from maverick_dashboard import app as app_mod

    class OversizedRequest:
        headers = {
            "content-length": str(app_mod._MAX_SKILL_VALIDATE_BODY_BYTES + 1),
        }

        async def stream(self):
            raise AssertionError("oversized declared body should not be read")
            yield b""

    async def read():
        await app_mod._read_limited_skill_validator_body(OversizedRequest())

    with pytest.raises(HTTPException) as exc:
        asyncio.run(read())
    assert exc.value.status_code == 413


def test_lengthless_skill_validator_body_stream_is_bounded():
    from maverick_dashboard import app as app_mod

    class ChunkedRequest:
        headers = {}

        def __init__(self):
            self.chunks_read = 0

        async def stream(self):
            for chunk in (
                b"x" * app_mod._MAX_SKILL_VALIDATE_BODY_BYTES,
                b"x",
                b"unread after cap exceeded",
            ):
                self.chunks_read += 1
                yield chunk

    request = ChunkedRequest()

    async def read():
        await app_mod._read_limited_skill_validator_body(request)

    with pytest.raises(HTTPException) as exc:
        asyncio.run(read())
    assert exc.value.status_code == 413
    assert request.chunks_read == 2
