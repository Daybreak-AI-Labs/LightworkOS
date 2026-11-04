"""Govern a LIVE authenticated-REST system of record.

The enterprise REST connectors (:mod:`maverick.tools.enterprise_connectors`)
expose a service as a ``confirm=true``-gated :class:`~maverick.tools.Tool`. That
gating is per-call and leaves no durable, tamper-evident trail. This module
adapts the SAME REST shape into the governed-action surface
(:mod:`maverick.governed_connectors`): a ``<name>.read`` (GET, low risk) and a
``<name>.write`` (POST/PUT/PATCH/DELETE, high risk) that

  * previews its effect with NO network call (the ``simulate`` contract -- a
    real write would be a side effect), then
  * hits the approval floor (``[actions] require_approval_at``, default
    ``high``), then
  * records a tamper-evident lineage link on commit.

The actual request reuses the SSRF-safe + enterprise-egress request path from
:mod:`maverick.tools._rest_connector` -- the very boundary the Tool form
enforces -- so a governed write is held to identical egress rules (host
IP-pinning, no redirects, metadata-IP denial). This is the reference path for
wrapping real writes to a system of record; the framework's other built-in
connector is in-memory.

Opt-in/additive per kernel rule 1: importing this changes nothing; an operator
registers a connector explicitly (or via ``[governed_connectors] enable``).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .governed_actions import GovernedActions
from .governed_connectors import Connector, register_connector

# Mutating HTTP verbs -- the high-risk write surface.
WRITE_OPS = ("post", "put", "patch", "delete")


@dataclass
class RestConnector(Connector):
    """A live REST system of record adapted into governed read/write Actions.

    ``read`` performs a GET; ``preview_write`` *describes* the pending mutation
    WITHOUT calling the API (no side effect, honoring the simulate contract);
    ``write`` performs the POST/PUT/PATCH/DELETE through the shared SSRF-safe,
    egress-guarded request path.

    Auth mirrors :func:`maverick.tools._rest_connector.make_rest_tool`:
    ``{token_header}: {scheme} {token}`` by default, or HTTP basic when
    ``basic=True``; ``extra_headers_env`` carries APIM-style second credentials.
    Credentials come only from the named env vars (no ambient creds), exactly
    as the Tool form requires.
    """

    name: str = "rest"
    base_url_env: str = ""
    token_env: str = ""
    token_header: str = "Authorization"
    scheme: str = "Bearer"
    basic: bool = False
    extra_headers_env: dict[str, str] | None = None
    # Typed schemas for the governed-action layer. A write declares op + path +
    # body (an empty dict for verbs without a payload, e.g. DELETE).
    read_params: dict[str, type] = field(
        default_factory=lambda: {"path": str})
    write_params: dict[str, type] = field(
        default_factory=lambda: {"op": str, "path": str, "body": dict})

    # -- shared request plumbing (reused from the Tool factory) --------------
    def _norm(self, path: str) -> str:
        p = (path or "").strip()
        return p if p.startswith("/") else "/" + p

    def _config(self) -> tuple[str, str]:
        from .tools._rest_connector import _env_config
        return _env_config(self.name, self.base_url_env, self.token_env)

    def _headers(self, tok: str) -> dict[str, str]:
        from .tools._rest_connector import _build_auth_headers
        return _build_auth_headers(
            tok, basic=self.basic, token_header=self.token_header,
            scheme=self.scheme, extra_headers_env=self.extra_headers_env)

    @staticmethod
    def _op_of(params: dict) -> str:
        return str(params.get("op", "")).strip().lower()

    # -- governed surface ---------------------------------------------------
    def read(self, params: dict) -> str:
        from .tools._rest_connector import _rest_execute
        path = str(params.get("path", "")).strip()
        if not path:
            return "ERROR: path is required"
        args = {"params": params.get("params")}
        return _rest_execute(
            "get", path, args, name=self.name, config=self._config,
            headers=self._headers, norm=self._norm)

    def preview_write(self, params: dict) -> str:
        """Describe the pending mutation WITHOUT performing it (no network).

        A REST write cannot be truly dry-run server-side without risking a side
        effect, so the preview is a faithful textual effect -- verb, target
        path, and the field names of the payload -- which is exactly what the
        approver needs to authorize the change."""
        op = self._op_of(params)
        path = self._norm(str(params.get("path", "")))
        if op not in WRITE_OPS:
            return f"ERROR: op must be one of {list(WRITE_OPS)} (got {op!r})"
        if not str(params.get("path", "")).strip():
            return "ERROR: path is required"
        body = params.get("body")
        fields = sorted(body) if isinstance(body, dict) and body else []
        tail = f" with fields {fields}" if fields else ""
        return f"would {op.upper()} {self.name}{path}{tail}"

    def write(self, params: dict) -> str:
        from .tools._rest_connector import _rest_execute
        op = self._op_of(params)
        if op not in WRITE_OPS:
            return f"ERROR: op must be one of {list(WRITE_OPS)} (got {op!r})"
        path = str(params.get("path", "")).strip()
        if not path:
            return "ERROR: path is required"
        body = params.get("body")
        # ``_rest_execute`` is the SSRF-safe, egress-guarded path. ``confirm`` is
        # irrelevant here (the governed approval gate already authorized this);
        # we pass only op/path/body.
        args = {"body": body if isinstance(body, dict) else None}
        return _rest_execute(
            op, path, args, name=self.name, config=self._config,
            headers=self._headers, norm=self._norm)


# Reference connectors against real systems of record. Each names the same env
# vars the Tool form and the installer catalog already use, so an operator who
# configured the connector once gets the governed path for free.
def salesforce_connector() -> RestConnector:
    """Salesforce REST (sObjects). Reads/writes via ``/services/data/...``.
    Env: ``SALESFORCE_INSTANCE_URL`` + ``SALESFORCE_ACCESS_TOKEN``."""
    return RestConnector(
        name="salesforce",
        base_url_env="SALESFORCE_INSTANCE_URL",
        token_env="SALESFORCE_ACCESS_TOKEN")


def servicenow_connector() -> RestConnector:
    """ServiceNow Table API. Reads/writes via ``/api/now/table/...``.
    Env: ``SERVICENOW_INSTANCE_URL`` + ``SERVICENOW_TOKEN``."""
    return RestConnector(
        name="servicenow",
        base_url_env="SERVICENOW_INSTANCE_URL",
        token_env="SERVICENOW_TOKEN")


# Registry of reference governed-REST connectors, keyed by connector name. An
# operator selects which to register via ``[governed_connectors] connectors``.
GOVERNED_REST_FACTORIES = {
    "salesforce": salesforce_connector,
    "servicenow": servicenow_connector,
}


def available_rest_connectors() -> list[str]:
    """Names of the reference governed-REST connectors that can be registered."""
    return sorted(GOVERNED_REST_FACTORIES)


def register_rest_connectors(
    ga: GovernedActions, names: list[str] | tuple[str, ...],
) -> dict[str, tuple[str, str]]:
    """Register the named reference REST connectors onto ``ga``.

    Returns ``{name: (read_action, write_action)}`` for the ones registered;
    unknown names are skipped (fail-open, never raises on an unknown name)."""
    out: dict[str, tuple[str, str]] = {}
    for n in names:
        factory = GOVERNED_REST_FACTORIES.get(str(n).strip().lower())
        if factory is None:
            continue
        out[n] = register_connector(ga, factory())
    return out


def configured_governed_actions() -> tuple[GovernedActions, dict[str, tuple[str, str]]]:
    """Build a :class:`GovernedActions` with the operator-selected connectors.

    Reads ``[governed_connectors]`` (env override
    ``MAVERICK_GOVERNED_CONNECTORS``). When disabled, returns an empty registry
    -- nothing is registered, so the feature ships inert (kernel rule 1). When
    enabled, every name in ``connectors`` that matches a reference factory is
    registered as read+write governed Actions. Returns ``(ga, registered)``."""
    from .config import env_flag, get_governed_connectors
    from .governed_tools import _enterprise_mode

    cfg = get_governed_connectors()
    ga = GovernedActions()
    # The mutation boundary itself is always on (``governance_enabled``); the
    # reference REST connectors are still an operator opt-in so a standard
    # deployment ships inert. Enterprise mode is a mandatory floor.
    override = env_flag("MAVERICK_GOVERNED_CONNECTORS")
    enabled = _enterprise_mode() or (
        override if override is not None else bool(cfg.get("enable", False))
    )
    if not enabled:
        return ga, {}
    return ga, register_rest_connectors(ga, cfg["connectors"])


def placeholder_params(spec) -> dict:
    """A minimal typed-valid param dict for an action spec, so its approval
    requirement can be probed without real inputs (simulate has no side
    effects)."""
    sample = {str: "x", dict: {}, int: 0, float: 0.0, bool: False}
    return {k: sample.get(t, "x") for k, t in spec.params.items()}


def connector_rows(ga: GovernedActions, registered: dict[str, tuple[str, str]]) -> list[dict]:
    """One row per registered governed connector: its read and write actions,
    the write's risk tier, and whether committing a write needs an approver.
    Shared by ``maverick connectors list`` and the Connections page."""
    rows = []
    for name, (read_action, write_action) in sorted(registered.items()):
        write_spec = ga.get(write_action)
        rows.append({
            "connector": name,
            "read_action": read_action,
            "write_action": write_action,
            "write_risk": write_spec.risk,
            "write_requires_approval": ga.simulate(
                write_action, placeholder_params(write_spec)).requires_approval,
        })
    return rows


__all__ = [
    "RestConnector", "WRITE_OPS", "salesforce_connector", "servicenow_connector",
    "GOVERNED_REST_FACTORIES", "available_rest_connectors", "register_rest_connectors",
    "configured_governed_actions", "connector_rows", "placeholder_params",
]
