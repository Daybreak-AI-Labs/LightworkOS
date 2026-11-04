#!/usr/bin/env python3
"""Cross-language parity test: prove `maverick-verify-audit` (Rust) agrees with
`maverick.audit.signing.verify_chain` (the Python source of truth) on the SAME
signed audit file.

It drives the REAL Python writer (`AuditSigner`) to mint a key + sign a
hash-chained NDJSON log, then:

  1. runs the Rust binary on the intact file and asserts exit 0 ("OK"),
  2. confirms Python `verify_chain` also reports the file intact,
  3. flips one byte inside a row's payload and asserts BOTH the Rust binary
     (non-zero, break at the right row) AND Python `verify_chain` now report a
     break at the same line — the verdicts must match,
  4. checks the `--pubkey <hex>` override path,
  5. checks an entirely-unsigned log is reported UNVERIFIABLE (exit 1), matching
     the CLI semantics.

Run directly:  python3 rust/maverick-verify-audit/tests/parity.py
or via pytest:  python3 -m pytest rust/maverick-verify-audit/tests/parity.py

The binary path can be pinned with MVK_VERIFY_BIN; otherwise it is built with
`cargo build` (debug) on demand. If cargo is unavailable AND no prebuilt binary
is found, the test SKIPS with a clear message (CI must build it).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# --- locate repo + make maverick importable ---------------------------------
HERE = Path(__file__).resolve()
# rust/maverick-verify-audit/tests/parity.py -> repo root is 3 levels up.
REPO_ROOT = HERE.parents[3]
CRATE_DIR = HERE.parents[1]
RUST_DIR = HERE.parents[2]
sys.path.insert(0, str(REPO_ROOT / "packages" / "maverick-core"))


def _have_crypto() -> bool:
    try:
        import cryptography.hazmat.primitives.asymmetric.ed25519  # noqa: F401

        return True
    except Exception:
        return False


def _build_or_find_binary() -> str | None:
    """Return a path to the maverick-verify-audit binary, building if needed.

    Resolution order: MVK_VERIFY_BIN env -> existing target/debug artifact ->
    `cargo build`. Returns None if no binary is available (cargo absent and no
    prebuilt artifact), so the caller can SKIP rather than fail.
    """
    env_bin = os.environ.get("MVK_VERIFY_BIN")
    if env_bin and Path(env_bin).exists():
        return env_bin

    exe = "maverick-verify-audit" + (".exe" if os.name == "nt" else "")
    candidates = [
        RUST_DIR / "target" / "debug" / exe,
        RUST_DIR / "target" / "release" / exe,
    ]
    for c in candidates:
        if c.exists():
            return str(c)

    if shutil.which("cargo") is None:
        return None
    try:
        subprocess.run(
            ["cargo", "build", "-p", "maverick-verify-audit"],
            cwd=str(RUST_DIR),
            check=True,
            capture_output=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return None
    for c in candidates:
        if c.exists():
            return str(c)
    return None


def _run(binary: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [binary, *args], capture_output=True, text=True, timeout=60
    )


class ParityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _have_crypto():
            raise unittest.SkipTest("cryptography not installed; cannot sign")
        cls.binary = _build_or_find_binary()
        if cls.binary is None:
            raise unittest.SkipTest(
                "maverick-verify-audit binary unavailable (no cargo + no prebuilt "
                "artifact); CI must compile the crate"
            )

    def _make_signed_log(self, tmp: Path, n_rows: int = 5):
        """Sign `n_rows` events with the REAL AuditSigner into tmp, isolating the
        key dir there. Returns (day_file, keys_dir, pubkey_hex)."""
        from maverick.audit import signing

        keys_dir = tmp / "keys"
        keys_dir.mkdir()
        # Pin the key dir so AuditSigner writes its <keyid>.{key,pub} here and
        # the Rust binary can find the .pub via --keys-dir.
        signing.KEY_DIR = keys_dir
        day_file = tmp / "2026-06-18.ndjson"
        signer = signing.AuditSigner(day_file)
        for i in range(n_rows):
            ok = signer.write(
                {
                    "kind": "tool_call",
                    "seq": i,
                    "tool": "shell",
                    # Exercise the canonical-JSON edge cases: non-ASCII, floats,
                    # big ints, nested structures, control-ish strings.
                    "note": f"café №{i} — 中文 \U0001F600",
                    "cost": 1.5 if i % 2 == 0 else 2.0,
                    "big": 10 ** 25 + i,
                    "nested": {"z": [3, 2, 1], "a": None, "flag": True},
                    "ts": f"2026-06-18T00:00:0{i}+00:00",
                }
            )
            self.assertTrue(ok, "AuditSigner.write failed")
        return day_file, keys_dir, signer.public_key_hex

    def test_intact_chain_passes_both(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            day_file, keys_dir, pub_hex = self._make_signed_log(tmp)

            # Python verdict: intact.
            from maverick.audit.signing import verify_chain

            self.assertEqual(verify_chain(day_file, pubkey_hex=pub_hex), [])

            # Rust verdict via --keys-dir: exit 0, OK message.
            r = _run(self.binary, str(day_file), "--keys-dir", str(keys_dir))
            self.assertEqual(
                r.returncode, 0, f"expected OK, got rc={r.returncode}\n{r.stderr}"
            )
            self.assertIn("OK:", r.stdout)

            # Rust verdict via --pubkey override: also exit 0.
            r2 = _run(self.binary, str(day_file), "--pubkey", pub_hex)
            self.assertEqual(r2.returncode, 0, r2.stderr)

    def test_tamper_detected_at_right_row_both(self):
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            day_file, keys_dir, pub_hex = self._make_signed_log(tmp, n_rows=5)

            lines = day_file.read_text().splitlines()
            target_idx = 2  # 0-based -> tamper row 3 (1-based)
            row = json.loads(lines[target_idx])
            # Flip the payload WITHOUT touching hash/sig: the recomputed hash must
            # now disagree with the stored hash -> bad_hash at this row.
            row["seq"] = row["seq"] + 1000
            # Preserve key order roughly (irrelevant to verification) and rewrite.
            lines[target_idx] = json.dumps(row)
            day_file.write_text("\n".join(lines) + "\n")

            # Python verdict: a break somewhere from this row on.
            from maverick.audit.signing import verify_chain

            py_breaks = verify_chain(day_file, pubkey_hex=pub_hex)
            self.assertTrue(py_breaks, "Python should detect the tamper")
            py_first = py_breaks[0]
            self.assertEqual(py_first.line_no, target_idx + 1)
            self.assertIn(py_first.reason, ("bad_hash", "bad_signature"))

            # Rust verdict: non-zero, first break at the same row + reason.
            r = _run(self.binary, str(day_file), "--pubkey", pub_hex, "--all")
            self.assertNotEqual(r.returncode, 0, "Rust must reject the tamper")
            self.assertIn(f"line {target_idx + 1}:", r.stderr)
            self.assertIn(py_first.reason, r.stderr)

    def test_chain_mismatch_on_deleted_row(self):
        # Deleting an interior row breaks prev_hash linkage on the next row.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            day_file, keys_dir, pub_hex = self._make_signed_log(tmp, n_rows=5)
            lines = day_file.read_text().splitlines()
            del lines[2]  # remove 3rd row -> row 4's prev_hash no longer matches
            day_file.write_text("\n".join(lines) + "\n")

            from maverick.audit.signing import verify_chain

            py_breaks = verify_chain(day_file, pubkey_hex=pub_hex)
            self.assertTrue(any(b.reason == "chain_mismatch" for b in py_breaks))

            r = _run(self.binary, str(day_file), "--pubkey", pub_hex, "--all")
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("chain_mismatch", r.stderr)

    def test_unsigned_log_unverifiable_exit_1(self):
        # A log written with signing OFF (plain NDJSON) must be UNVERIFIABLE.
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            day_file = tmp / "2026-06-18.ndjson"
            day_file.write_text(
                json.dumps({"kind": "tool_call", "seq": 0}) + "\n"
                + json.dumps({"kind": "tool_call", "seq": 1}) + "\n"
            )
            keys_dir = tmp / "keys"
            keys_dir.mkdir()
            r = _run(self.binary, str(day_file), "--keys-dir", str(keys_dir))
            self.assertEqual(r.returncode, 1)
            self.assertIn("UNVERIFIABLE", r.stderr)

    def test_missing_file_exit_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            missing = Path(td) / "nope.ndjson"
            r = _run(self.binary, str(missing), "--keys-dir", td)
            self.assertNotEqual(r.returncode, 0)
            self.assertIn("missing_file", r.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
