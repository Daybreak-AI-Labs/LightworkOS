"""Smoke test: every kernel module imports cleanly."""
from __future__ import annotations


def test_top_level_imports():
    import maverick
    import maverick.agent  # noqa: F401
    import maverick.blackboard  # noqa: F401
    import maverick.budget  # noqa: F401
    import maverick.cli  # noqa: F401
    import maverick.config  # noqa: F401
    import maverick.llm  # noqa: F401
    import maverick.orchestrator  # noqa: F401
    import maverick.sandbox  # noqa: F401
    import maverick.sandbox.local  # noqa: F401
    import maverick.server  # noqa: F401
    import maverick.skills  # noqa: F401
    import maverick.swarm  # noqa: F401
    import maverick.tools  # noqa: F401
    import maverick.tools.ask_user  # noqa: F401
    import maverick.tools.fs  # noqa: F401
    import maverick.tools.shell  # noqa: F401
    import maverick.tools.spawn  # noqa: F401
    import maverick.world_model  # noqa: F401
    assert maverick.__version__


def test_provider_registry():
    from maverick.providers import KNOWN_PROVIDERS, get_provider_client  # noqa: F401
    assert "anthropic" in KNOWN_PROVIDERS
    assert "openai" in KNOWN_PROVIDERS
    assert "openrouter" in KNOWN_PROVIDERS
    assert "ollama" in KNOWN_PROVIDERS


def test_sandbox_module_loads():
    # Importing docker.py should not require Docker to be installed.
    from maverick.sandbox import DockerBackend, LocalBackend, build_sandbox  # noqa: F401
