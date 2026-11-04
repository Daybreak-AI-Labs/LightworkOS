"""Standalone products must carry the same reviewed support implementation."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("demo", ["dsar-concierge"])
def test_standalone_context_contains_shared_support_and_captures_mail(demo, tmp_path):
    """A copied build context runs without access to the repository's shared dir."""
    source = ROOT / "demo" / demo
    context = tmp_path / demo
    context.mkdir()
    tls_dir = tmp_path / "tls"
    tls_dir.mkdir()
    for name in ("mailsink.py", "mailsink_transport.py"):
        shutil.copyfile(source / name, context / name)
    for name in ("mailsink_transport.py",):
        assert (source / name).read_bytes() == (ROOT / "demo" / "shared" / name).read_bytes()
        assert name in (source / "Dockerfile.standalone").read_text()
    script = '''
import asyncio
import sys
import tempfile
sys.path.insert(0, sys.argv[1])
import mailsink

tempfile.tempdir = sys.argv[2]
assert mailsink._selfsigned_context() is not None
mailsink._TLS_CTX = object()

class Reader:
    def __init__(self):
        self.lines = iter([b"EHLO localhost\\r\\n", b"STARTTLS\\r\\n", b"MAIL FROM:<a@example.test>\\r\\n",
                           b"RCPT TO:<b@example.test>\\r\\n", b"DATA\\r\\n",
                           b"From: a@example.test\\r\\n", b"To: b@example.test\\r\\n",
                           b"Subject: Hello\\r\\n", b"\\r\\n", b"hello\\r\\n",
                           b".\\r\\n", b"QUIT\\r\\n"])
    async def readline(self):
        return next(self.lines, b"")

class Writer:
    def __init__(self): self.output = bytearray()
    def write(self, data): self.output.extend(data)
    async def drain(self): pass
    async def start_tls(self, context): self.tls_context = context
    def close(self): pass

writer = Writer()
asyncio.run(mailsink._handle(Reader(), writer))
assert len(mailsink.INBOX) == 1
assert mailsink.INBOX[0].subject == "Hello"
assert mailsink.INBOX[0].body.strip() == "hello"
assert b"250 OK: queued" in writer.output
assert writer.tls_context is mailsink._TLS_CTX
'''
    subprocess.run([sys.executable, "-I", "-c", script, str(context), str(tls_dir)], check=True)
    assert not list(tls_dir.iterdir())


@pytest.mark.parametrize("demo", ["grc-concierge", "platform-threat-hunter",
                                  "environment-threat-hunter", "model-risk-ai-assurance-officer"])
def test_standalone_demo_carries_shared_request_and_lock_support(demo, tmp_path):
    """Each demo's copied support files run outside the repository and keep
    bounded request behavior."""
    source = ROOT / "demo" / demo
    context = tmp_path / demo
    context.mkdir()
    for name in ("request_limits.py", "request_boundary.py", "local_store_lock.py"):
        shutil.copyfile(source / name, context / name)
    for name in ("request_boundary.py", "local_store_lock.py"):
        assert (source / name).read_bytes() == (ROOT / "demo" / "shared" / name).read_bytes()
    script = '''
import asyncio
import sys
sys.path.insert(0, sys.argv[1])
import request_limits
from local_store_lock import cross_process_lock
from pathlib import Path

class Request:
    def __init__(self, payload):
        self.headers = {"content-type": "application/json"}
        self.payload = payload
    async def stream(self):
        yield self.payload

assert asyncio.run(request_limits.read_bounded_json(Request(b'{"name":"ok"}'))) == {"name": "ok"}
try:
    asyncio.run(request_limits.read_bounded_json(Request(b"x" * (request_limits.MAX_REQUEST_BYTES + 1))))
except request_limits.PayloadError as exc:
    assert exc.status_code == 413
else:
    raise AssertionError("oversized input was accepted")
with cross_process_lock(Path(sys.argv[1]) / "store.json"):
    assert (Path(sys.argv[1]) / "store.json.lock").is_file()
'''
    subprocess.run([sys.executable, "-I", "-c", script, str(context)], check=True)


@pytest.mark.parametrize("private", [False, True])
def test_standalone_store_lock_serializes_independent_processes(private, tmp_path):
    """A second process cannot enter until the first releases its store lock."""
    shutil.copyfile(ROOT / "demo" / "shared" / "local_store_lock.py", tmp_path / "local_store_lock.py")
    script = '''
import subprocess
import sys
import time
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from local_store_lock import cross_process_lock

directory = Path(sys.argv[1])
store = directory / "store.json"
marker = directory / "entered"
private = sys.argv[2] == "True"
child_code = """
import sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from local_store_lock import cross_process_lock
print('attempting', flush=True)
with cross_process_lock(Path(sys.argv[1]) / 'store.json', private=sys.argv[2] == 'True'):
    (Path(sys.argv[1]) / 'entered').write_text('entered')
"""
child = None
try:
    with cross_process_lock(store, private=private):
        child = subprocess.Popen(
            [sys.executable, "-I", "-c", child_code, str(directory), str(private)],
            stdout=subprocess.PIPE, text=True,
        )
        assert child.stdout.readline().strip() == "attempting"
        time.sleep(0.2)
        assert not marker.exists()
    assert child.wait(timeout=10) == 0
    assert marker.read_text() == "entered"
finally:
    if child is not None and child.poll() is None:
        child.kill()
        child.wait()
'''
    subprocess.run([sys.executable, "-I", "-c", script, str(tmp_path), str(private)], check=True, timeout=30)
