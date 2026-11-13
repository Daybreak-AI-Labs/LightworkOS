from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from maverick_dashboard import no_code_grc_studio_composition as composition
from starlette.requests import Request


def config(**updates: object) -> dict[str, object]:
    section = {
        "enable": True,
        "max_studios": 250,
        "retention_seconds": 86_400,
        "max_import_bytes": 65_536,
    }
    section.update(updates)
    return {"tech_risk_compliance": {"enable": True, "grc_studio": section}}


def request_for(app: FastAPI) -> Request:
    request = Request({"type": "http", "app": app, "state": {}})
    request.state.principal = SimpleNamespace(principal="user:operator")
    return request


def test_settings_are_closed_bounded_and_parent_gated() -> None:
    assert composition.grc_studio_settings(config()) == composition.GRCStudioSettings(
        max_studios=250,
        retention_seconds=86_400,
        max_import_bytes=65_536,
    )
    assert composition.grc_studio_settings({}) is None
    disabled = config()
    disabled["tech_risk_compliance"]["enable"] = False
    assert composition.grc_studio_settings(disabled) is None
    with pytest.raises(composition.GRCStudioCompositionError, match="unknown"):
        composition.grc_studio_settings(config(injected=True))
    with pytest.raises(composition.GRCStudioCompositionError, match="bound"):
        composition.grc_studio_settings(config(max_import_bytes=10))


def test_install_is_lazy_idempotent_and_does_not_claim_runtime_writes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    monkeypatch.setattr(composition, "grc_studio_enabled", lambda tenant: tenant == "tenant-a")
    monkeypatch.setattr(composition, "grc_studio_readiness", lambda tenant: tenant == "tenant-a")
    composition.install_no_code_grc_studio_composition(app)
    composition.install_no_code_grc_studio_composition(app)
    assert app.state.grc_studio_enabled_probe("tenant-a") is True
    assert app.state.grc_studio_readiness_probe("tenant-a") is True
    assert callable(app.state.grc_studio_store_factory)
    assert not hasattr(app.state, "grc_studio_target_authority_resolver_factory")
    assert not hasattr(app.state, "grc_studio_projection_applier_factory")


def test_store_factory_binds_request_principal_and_private_custody(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = FastAPI()
    request = request_for(app)
    monkeypatch.setattr(composition, "has_global_permission", lambda _request, _permission: True)
    monkeypatch.setattr(
        composition,
        "settings_for_tenant",
        lambda _tenant: composition.GRCStudioSettings(250, 86_400, 65_536),
    )

    def tenant_data_dir(*parts: str, tenant: str):
        return tmp_path / tenant / Path(*parts)

    monkeypatch.setattr(composition, "data_dir", tenant_data_dir)
    principal = composition.principal_ref(request, "tenant-a")
    store = composition.store_factory(
        app,
        tenant_id="tenant-a",
        principal_ref_value=principal,
        request=request,
    )
    assert store.tenant_id == "tenant-a"
    assert store.path.parent.parent.parent == tmp_path / "tenant-a"
    key = tmp_path / "tenant-a" / "tech_risk_compliance" / "grc-studio" / "integrity.key"
    assert key.exists() and len(key.read_bytes()) == 32
    with pytest.raises(Exception, match="principal"):
        composition.store_factory(
            app,
            tenant_id="tenant-a",
            principal_ref_value="attacker",
            request=request,
        )
