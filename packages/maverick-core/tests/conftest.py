"""Shared test fixtures for maverick-core.

Provides:
  - ``fake_llm``: a scripted ``FakeLLM`` instance that replaces ``maverick.llm.LLM``
    in tests. Push ``LLMResponse`` objects to ``scripted`` and the agent loop
    pops them in order. Recorded calls available on ``.calls`` for assertions.
  - ``make_llm_response``: helper to build LLMResponse fixtures quickly.

Using this pattern is the only way to test the recursive agent loop and the
OpenAI translator without burning API credits in CI.
"""
from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass, field

import pytest
from maverick.llm import LLMResponse, ToolCall  # noqa: F401 - re-exported for tests


@pytest.fixture
def postgres_test_dsn(monkeypatch, request):
    """Own one disposable database, including for per-test encryption keys.

    Live PG suites require the dedicated test service's CREATEDB/admin role.
    Sharing its public tables across independent secure-posture key fixtures
    makes later scans attempt to decrypt a prior test's ciphertext.
    """
    dsn = os.environ.get("MAVERICK_PG_DSN", "")
    if not dsn:
        pytest.skip("MAVERICK_PG_DSN not set (no dedicated Postgres test service)")
    psycopg = pytest.importorskip("psycopg")
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    database = "mvk_test_" + uuid.uuid4().hex
    with psycopg.connect(dsn, autocommit=True) as admin:
        admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
    isolated = make_conninfo(dsn, dbname=database)
    monkeypatch.setenv("MAVERICK_PG_DSN", isolated)
    if hasattr(request.module, "_DSN"):
        monkeypatch.setattr(request.module, "_DSN", isolated)
    try:
        yield isolated
    finally:
        # Exactly the database created above; never a caller-supplied name.
        with psycopg.connect(dsn, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(database)))


@pytest.fixture(autouse=True)
def _isolate_maverick_home(tmp_path, monkeypatch, request):
    """Point user-home resolution at a per-test temp dir on every platform.

    maverick resolves ``~/.maverick`` via ``Path.home()`` in ~30 places. On
    Windows ``Path.home()`` reads ``USERPROFILE`` and ignores the ``$HOME``
    that tests monkeypatch, so the suite (a) read the developer's REAL home
    (PermissionError on pre-existing world-readable files) and (b) WROTE fake
    sessions/config into the real ``~/.maverick`` (cross-run pollution — a
    leftover ``____evil`` session proved it). Set both ``HOME`` and the Windows
    vars so ``Path.home()`` is isolated everywhere.

    POSIX: this just sets ``HOME`` to a temp dir (what tests already do), so it
    is effectively a no-op and cannot regress Linux CI; a test that sets its own
    ``HOME`` still overrides this.
    """
    # Use tmp_path itself (not a subdir) so a test that sets HOME=tmp_path and
    # then computes tmp_path/.maverick/... lines up with Path.home() on every
    # platform (on Windows Path.home() reads USERPROFILE, set here too).
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))  # Windows: what Path.home() reads
    # The shipped first-party skills library lives INSIDE the package, so unlike
    # the user skills dir it is not isolated by HOME. Disable it by default so
    # the suite sees only the (empty, isolated) user dir -- behaviour unchanged
    # from before the library shipped. Tests opt in with MAVERICK_BUILTIN_SKILLS=1.
    monkeypatch.setenv("MAVERICK_BUILTIN_SKILLS", "0")
    # Which security posture the suite runs under.
    #
    # The default here is the LEGACY posture, so the suite keeps asserting each
    # control's explicit on/off mechanics. That is a real thing to test, but on
    # its own it means ~19,000 passing tests describe a configuration no
    # customer runs: production ships secure-by-default, which turns on audit
    # signing, at-rest encryption, fail-closed consent for high-risk actions,
    # and the tool-risk ceiling.
    #
    # MAVERICK_TEST_SECURE_DEFAULT=1 runs the whole suite under the production
    # posture instead. Until that is green everywhere it is a separate CI job
    # rather than the default, because a red posture job that blocks every PR
    # gets switched off, and then nothing measures it at all.
    secure_default = os.environ.get("MAVERICK_TEST_SECURE_DEFAULT", "0")
    monkeypatch.setenv("MAVERICK_SECURE_DEFAULT", secure_default)
    if secure_default.strip().lower() in {"1", "true", "yes", "on"}:
        # The production posture requires off-host audit-key custody. Give each
        # test a stable, node-id-derived throwaway key so audit-dependent denial
        # paths exercise the customer posture without needing a CI secret. The
        # runtime consumes this environment variable on first use; the fixture
        # reinstalls a fresh test-scoped value for the next isolated test home.
        key_seed = f"maverick-posture-test:{request.node.nodeid}".encode()
        monkeypatch.setenv(
            "MAVERICK_AUDIT_SIGNING_KEY",
            hashlib.sha256(key_seed).hexdigest(),
        )
    # The reflexion / dreaming-insight / learned-skill stores expose their
    # no-tenant path as an IMPORT-TIME module constant (the ``legacy`` fallback in
    # ``reflexion``/``dreaming`` ``_tenant_path``), computed once via ``data_dir()``
    # at first import. Unlike the ~30 dynamic ``Path.home()`` callers, those
    # constants do NOT follow the HOME set above, so a learned skill/insight/
    # reflexion written by one test leaks into a later test's coverage/recall
    # (observed: worker_review saw a foreign finance lesson). Re-resolve them
    # under the per-test HOME; monkeypatch restores the originals at teardown.
    try:
        import maverick.dreaming as _dream
        import maverick.reflexion as _refl
        import maverick.skill.distillation_local as _distill
        from maverick.paths import data_dir as _dd
        monkeypatch.setattr(_refl, "DEFAULT_PATH", _dd("reflexions.ndjson"), raising=False)
        monkeypatch.setattr(_dream, "DEFAULT_DIR", _dd("dreams"), raising=False)
        monkeypatch.setattr(_dream, "DEFAULT_INSIGHTS", _dd("dreams") / "insights.ndjson",
                            raising=False)
        monkeypatch.setattr(_distill, "_STORE", _dd("learned-skills"), raising=False)
    except Exception:  # pragma: no cover -- isolation refresh never blocks a test
        pass
    return tmp_path


@pytest.fixture
def local_audit_key_custody(monkeypatch):
    """Select the on-disk audit-key path for tests that exercise it directly.

    The production-posture harness injects a test-scoped off-host signing key,
    and runtime correctly gives that key precedence over local key files. Tests
    for local rotation, custody, and corruption therefore need to opt into the
    local source explicitly; otherwise they pass or fail against the injected
    signer instead of the path named by the test.
    """
    from maverick.audit import signing

    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY", raising=False)
    monkeypatch.delenv("MAVERICK_AUDIT_SIGNING_KEY_WRAPPED", raising=False)
    monkeypatch.setenv("MAVERICK_AUDIT_REQUIRE_OFFHOST_KEY", "0")
    signing._reset_injected_keypair_cache()
    try:
        yield
    finally:
        signing._reset_injected_keypair_cache()


@pytest.fixture
def signed_audit(monkeypatch, request):
    """Sign this test's audit rows with a throwaway, test-scoped key.

    Learning cycles accept only a signed, confirmed activity row as their
    receipt (an unsigned row is not proof). The suite's legacy posture leaves
    signing off, so tests that run a real cycle opt into the production
    signing path here instead of stubbing the receipt away.
    """
    from maverick.audit import signing, writer

    seed = f"maverick-signed-audit-test:{request.node.nodeid}".encode()
    monkeypatch.setenv("MAVERICK_AUDIT_SIGN", "1")
    monkeypatch.setenv("MAVERICK_AUDIT_SIGNING_KEY", hashlib.sha256(seed).hexdigest())
    signing._reset_injected_keypair_cache()
    monkeypatch.setattr(writer, "_default", None)
    monkeypatch.setattr(writer, "_defaults", {})
    try:
        yield
    finally:
        signing._reset_injected_keypair_cache()


@pytest.fixture(autouse=True)
def _isolate_root_logging():
    """Snapshot + restore the root logger around every test.

    ``maverick.cli`` configures process-global logging on every command run
    (the group callback calls ``_configure_cli_logging`` -> ``configure_logging``,
    which is idempotent and *replaces* the root handlers, optionally attaching a
    warning filter). Any ``CliRunner(main)`` test therefore mutates the root
    logger for the rest of the session -- removing pytest's caplog handler and
    leaving a filter that drops non-allowlisted WARNINGs -- which silently
    breaks later ``caplog``-based warning assertions. Resetting per test keeps
    that mutation from leaking; within a test logging still behaves normally.
    """
    import logging

    import maverick.logging_config as lc
    root = logging.getLogger()
    saved_handlers = root.handlers[:]
    saved_level = root.level
    saved_filters = root.filters[:]
    saved_configured = getattr(lc, "_configured", False)
    try:
        yield
    finally:
        root.handlers[:] = saved_handlers
        root.setLevel(saved_level)
        root.filters[:] = saved_filters
        lc._configured = saved_configured


@pytest.fixture(autouse=True)
def _reset_client_binding_cache():
    """Reset the process-global client-id floor + per-tenant DEK cache per test.

    ``client._cached`` floors ``current_tenant_id()`` for the WHOLE process, so
    a test that sets ``MAVERICK_CLIENT_ID``/``[client] id`` and calls
    ``client_id()`` leaves the cache populated: ``monkeypatch.setenv`` undoes the
    env at teardown but NOT the cache, so the next test in the same worker would
    silently re-home every ``data_dir()`` under ``tenants/<that-client>/``. Reset
    before and after each test so binding never leaks across tests. The DEK cache
    is keyed on the same (floored) tenant id, so clear it in lockstep.
    """
    def _reset():
        try:
            from maverick import client
            client.reset_client_cache()
        except Exception:
            pass
        try:
            from maverick.tenant import kms as tenant_kms
            tenant_kms._clear_cache()
        except Exception:
            pass
        try:
            from maverick import config
            config.reset_config_cache()
        except Exception:
            pass
        try:
            # The injected audit-signing key is read once per process and cached
            # (the env var is popped for security), so a test that runs audit
            # signing without a key caches a miss that shadows a later test which
            # sets MAVERICK_AUDIT_SIGNING_KEY. Clear it in lockstep.
            from maverick.audit import signing as _audit_signing
            _audit_signing._reset_injected_keypair_cache()
        except Exception:
            pass

    _reset()
    yield
    _reset()


@dataclass
class FakeLLM:
    """Drop-in replacement for ``maverick.llm.LLM`` driven by a script."""

    scripted: list[LLMResponse] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list)
    model: str = "fake:test"

    def _record(self, **kwargs) -> None:
        self.calls.append(kwargs)

    def _next(self) -> LLMResponse:
        if not self.scripted:
            return LLMResponse(
                text="FINAL: (script exhausted)",
                thinking=None,
                tool_calls=[],
                stop_reason="end_turn",
            )
        return self.scripted.pop(0)

    async def complete_async(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        budget=None,
        max_tokens: int = 4096,
        thinking_budget: int | None = None,
        model: str | None = None,
    ) -> LLMResponse:
        self._record(
            system=system, messages=messages, tools=tools,
            max_tokens=max_tokens, model=model,
        )
        return self._next()

    def complete(
        self,
        system: str,
        messages: list[dict],
        tools: list[dict] | None = None,
        budget=None,
        max_tokens: int = 4096,
        thinking_budget: int | None = None,
        model: str | None = None,
        on_delta=None,
    ) -> LLMResponse:
        self._record(
            system=system, messages=messages, tools=tools,
            max_tokens=max_tokens, model=model,
        )
        return self._next()


def make_response(
    text: str = "",
    tool_calls: list[ToolCall] | None = None,
    thinking: str | None = None,
    stop_reason: str = "end_turn",
) -> LLMResponse:
    return LLMResponse(
        text=text,
        thinking=thinking,
        tool_calls=tool_calls or [],
        stop_reason=stop_reason,
    )


@pytest.fixture
def fake_llm() -> FakeLLM:
    return FakeLLM()


@pytest.fixture
def make_llm_response():
    return make_response
