"""The one-line operator log for a saved-record failure answered with 503."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.testclient import TestClient
from maverick.paths import tenant_scope
from maverick_dashboard.store_failures import log_store_failure, remember_route

LOG = logging.getLogger("tests.store_failures")


def _app():
    router = APIRouter(prefix="/api/v1/example", dependencies=[Depends(remember_route)])

    @router.get("/records/{record_id}")
    def read(record_id: str):
        try:
            with tenant_scope(tenant="synthetic-demo-model-risk"):
                try:
                    raise ConnectionError("password authentication failed for postgresql://app:hunter2@db/lw")  # pragma: allowlist secret
                except ConnectionError as exc:
                    raise RuntimeError("governed-record backend unavailable\nretry later") from exc
        except RuntimeError as exc:
            with tenant_scope(tenant="synthetic-demo-model-risk"):
                log_store_failure(LOG, exc)
            raise HTTPException(503, "unavailable") from exc

    app = FastAPI()
    app.include_router(router)
    return app


def test_one_redacted_line_names_route_template_workspace_and_causes(caplog):
    with caplog.at_level(logging.WARNING, logger=LOG.name):
        response = TestClient(_app()).get("/api/v1/example/records/R-private-1")
    assert response.status_code == 503
    [record] = [row for row in caplog.records if row.name == LOG.name]
    line = record.getMessage()
    assert record.exc_info is None and "\n" not in line
    assert "route=GET /api/v1/example/records/{record_id}" in line and "R-private-1" not in line
    assert "workspace=synthetic-demo-model-risk" in line
    assert "error=RuntimeError: governed-record backend unavailable retry later" in line
    assert "caused by ConnectionError: password authentication failed" in line
    assert "hunter2" not in line


def test_outside_a_request_the_line_still_logs(caplog):
    with caplog.at_level(logging.WARNING, logger=LOG.name):
        log_store_failure(LOG, OSError("x" * 1000))
    line = caplog.records[-1].getMessage()
    assert "route=unknown" in line and "workspace=" in line and line.endswith("...")
