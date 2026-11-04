# Dashboard service boundaries

The dashboard serves pages and `/api/v1` routes from the same application.
Routes authenticate and authorize the current request before accessing a
service; moving a helper out of the API module must not turn a route's checks
into a one-time page-load decision. Mutations that require current authority
continue to recheck it at the point of the change.

`maverick_dashboard.api` remains the composition root and compatibility
facade. Route families and pages should depend on the service that owns a
policy rather than importing the facade back into themselves. Existing API
names are retained for integrations that already use them. The shared
boundaries include:

- `module_activation`: the module registry, dependency chains and effective
  configuration checks used by navigation, pages and API endpoints. Invalid or
  unreadable configuration fails closed for activation. Its process-local
  fingerprint key binds activation reviews to the configuration they reviewed.
- `request_identity` and `editor_policy`: verified caller attribution,
  connector-principal limits, administrator and API-key scope checks for
  editing. A local auth-off grant is handled by the same policy on every
  surface.
- `privacy_access`, `schedule_policy` and `deliverable_policy`: native privacy
  availability, permission to schedule work and the persisted release gate for
  task output. A missing or unreadable release policy does not grant release.
- `attachment_headers` and `voice_policy`: shared download-header formatting
  and the effective voice setting, including its environment override.
- `flow_dependencies`: explicit workflow services bound by the application.
  Request-local bindings isolate concurrent requests while retaining the API's
  compatibility overrides for existing callers.

The installer, settings catalog and runtime also share typed setting metadata
in `maverick.config_contracts`. A contract defines a setting's common default,
syntax or dashboard bounds; it does not replace context-specific validation or
change precedence. In particular, a runtime may deliberately fail closed for
an unreadable security setting or accept values beyond a dashboard's UI range.
When adding a shared setting, preserve those distinctions and cover the
installer output, catalog definition and runtime interpretation.

For changes to a shared boundary, add coverage for allowed and denied paths,
configuration failures and the surfaces that consume it. The repository's
normal and secure-default suites, browser journeys and release checks are
listed in [AGENTS.md](../../AGENTS.md) and [CONTRIBUTING.md](../../CONTRIBUTING.md).

The remaining owned OIDC, voice forwarding and local-runtime HTTP clients use
`governed_http.admit_client_request` before dispatch. Their response streaming,
timeouts, and client cleanup remain with the owning service. The process-wide
guard remains necessary for third-party SDK calls.

World-store domain records live in `maverick.world_records`; both SQL backends
consume them without importing the SQLite implementation merely to construct a
record. Existing `maverick.world_model` record imports and pickle identities are
preserved.
