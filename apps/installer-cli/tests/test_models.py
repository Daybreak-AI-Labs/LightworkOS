"""Wizard model-catalog invariants."""
from __future__ import annotations

import pytest
from maverick_installer import models


def test_every_provider_has_required_fields():
    for prov_id, info in models.PROVIDERS.items():
        assert "label" in info, f"{prov_id} missing label"
        assert "status" in info, f"{prov_id} missing status"
        assert info["status"] in ("ready", "planned")
        assert isinstance(info["models"], list)
        assert len(info["models"]) > 0
        for m in info["models"]:
            assert "id" in m
            assert "notes" in m


def test_default_for_every_role():
    for role, _ in models.ROLES:
        spec = models.default_for_role(role)
        assert ":" in spec, f"{role} default missing provider prefix: {spec}"
        provider, _model = spec.split(":", 1)
        assert provider in models.PROVIDERS, f"{role} -> unknown provider {provider}"


def test_all_providers_now_ready():
    # Sanity check: multi-provider dispatch landed; nothing should be 'planned'.
    for prov_id, info in models.PROVIDERS.items():
        assert info["status"] == "ready", (
            f"{prov_id} still marked planned; update models.py"
        )


def test_byok_providers_offered():
    """All 8 BYOK providers must show in the wizard.

    Adding a provider client without exposing it in the wizard is a
    silent regression -- non-technical users have no way to reach it.
    """
    expected = {
        "anthropic", "openai", "moonshot", "xai",
        "gemini", "deepseek", "openrouter", "ollama",
    }
    assert expected.issubset(set(models.PROVIDERS)), (
        f"missing from wizard catalog: {expected - set(models.PROVIDERS)}"
    )


def test_byok_env_vars_set():
    """Every provider that uses an API key must declare its env var.

    Without this, collect_api_keys() silently skips the provider and
    the user ends up with a config that references ${SOMETHING} that
    was never prompted for.
    """
    needs_key = {
        "anthropic":  "ANTHROPIC_API_KEY",
        "openai":     "OPENAI_API_KEY",
        "moonshot":   "MOONSHOT_API_KEY",
        "deepseek":   "DEEPSEEK_API_KEY",
        "xai":        "XAI_API_KEY",
        "gemini":     "GEMINI_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
    }
    for prov_id, expected_env in needs_key.items():
        info = models.PROVIDERS[prov_id]
        assert info.get("env") == expected_env, (
            f"{prov_id}: env={info.get('env')!r}, expected {expected_env!r}"
        )
    # Ollama is local-only -- no key.
    assert models.PROVIDERS["ollama"].get("env") is None


def test_openai_compatible_declares_base_url_env():
    info = models.PROVIDERS["openai_compatible"]
    assert info.get("env") == "OPENAI_COMPATIBLE_API_KEY"
    assert "OPENAI_COMPATIBLE_BASE_URL" in info.get("env_vars", [])


def test_wizard_catalog_matches_kernel_registry():
    """The wizard offerings must be dispatchable by the kernel.

    Every provider the wizard shows must be reachable via the BYOK registry
    (maverick.providers.KNOWN_PROVIDERS). If they drift, a user picks a
    provider in the wizard but the kernel refuses to instantiate it -- the
    worst possible UX bug.
    """
    try:
        from maverick.providers import KNOWN_PROVIDERS
    except ImportError:
        pytest.skip("maverick-core not installed in this environment")
    dispatchable = set(KNOWN_PROVIDERS)
    wizard_only = set(models.PROVIDERS) - dispatchable
    assert not wizard_only, (
        f"wizard offers providers the kernel can't dispatch: {wizard_only}"
    )


def test_wizard_model_ids_have_pricing():
    """Every BYOK model id in the wizard should be priced in the kernel.

    A user picks a model -> the agent dispatches it -> budget code looks
    up MODEL_PRICES -> falls back to 0 silently if missing. That hides
    cost from the user. Wizard-offered ids must be priced.

    Exemptions:
      - ollama / openrouter / tgi / openai_compatible / vllm: local,
        aggregated, or self-hosted catalogs whose model id is a placeholder
        for whatever the endpoint serves (dynamic, zero per-token cost known
        to the kernel).
      - azure / bedrock / vertex: paid hosted providers with dynamic placeholders;
        budget._lookup_price must fail closed for those placeholders rather
        than billing them at a fallback estimate.
      - codex_cli: ChatGPT/Codex subscription via the Codex CLI -- no
        per-token API invoice exists; budget._lookup_price prices the
        codex_cli: prefix at $0 deliberately (not a silent fallback).
    """
    try:
        from maverick.llm import MODEL_PRICES
    except ImportError:
        pytest.skip("maverick-core not installed in this environment")
    unpriced: list[str] = []
    fail_closed_dynamic = {"azure", "bedrock", "vertex"}
    for prov_id, info in models.PROVIDERS.items():
        if prov_id in ("ollama", "openrouter", "tgi", "openai_compatible",
                       "vllm", "codex_cli") or prov_id in fail_closed_dynamic:
            continue
        for m in info["models"]:
            if m["id"] not in MODEL_PRICES:
                unpriced.append(f"{prov_id}:{m['id']}")
    assert not unpriced, (
        f"wizard offers models not priced in llm.MODEL_PRICES: {unpriced}"
    )


def test_xai_wizard_prefers_current_exactly_priced_models():
    offered = models.PROVIDERS["xai"]["models"]

    assert [model["id"] for model in offered[:3]] == [
        "grok-4.5",
        "grok-build-0.1",
        "grok-4.3",
    ]
    legacy = next(model for model in offered if model["id"] == "grok-code-fast")
    assert "estimate-only" in legacy["notes"]


def test_paid_dynamic_hosted_placeholders_fail_closed():
    """Azure/Bedrock placeholders must not use fallback budget pricing."""
    try:
        from maverick.budget import UnpricedModelError, _lookup_price
    except ImportError:
        pytest.skip("maverick-core not installed in this environment")

    for model in ("azure", "azure:azure", "bedrock", "bedrock:bedrock", "vertex", "vertex:vertex"):
        with pytest.raises(UnpricedModelError):
            _lookup_price(model)


def test_a_typed_vertex_model_is_refused_with_the_google_billing_remedy():
    """Google bills Vertex AI, so a typed Vertex id never falls back to a Claude API price."""
    try:
        from maverick.budget import UnpricedModelError, _lookup_price
    except ImportError:
        pytest.skip("maverick-core not installed in this environment")

    with pytest.raises(UnpricedModelError, match="Google Cloud invoices"):
        _lookup_price("vertex:claude-haiku-4-5@20251001", estimate_only=False)


# ---------- Wizard catalog ----------

def test_wizard_catalog_includes_tgi():
    from maverick_installer import models
    assert "tgi" in models.PROVIDERS
    assert models.PROVIDERS["tgi"]["status"] == "ready"
