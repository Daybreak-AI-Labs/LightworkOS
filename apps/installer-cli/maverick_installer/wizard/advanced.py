"""The advanced step: reasoning, learning and governance toggles.

``pick_advanced`` asks the questions; ``_cfg_advanced`` renders the answers
as ``config.toml`` sections.  The two are kept together so a toggle and the
table it writes are reviewed side by side.

Prompt primitives and the console are reached through :mod:`._seams`, so a
monkeypatch of ``maverick_installer.wizard._q_confirm`` (or ``console``,
``CONFIG_FILE``) applies here as well.
"""
from __future__ import annotations

import math
import re
import secrets
from typing import Any
from urllib.parse import urlsplit

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover -- Py 3.10 CI matrix
    import tomli as tomllib  # type: ignore[no-redef]

from .. import models as catalog
from ._common import _csv_list, _emit_kv, _safe_float, _safe_int, _toml_key, _toml_str
from ._seams import _q_checkbox, _q_confirm, _q_secret, _q_select, _q_text, config_file, console


def _prior_consent_salt() -> str:
    """The existing consent subject_salt, or a fresh one on first enable.

    Consent subject digests are sha256(salt:subject), so regenerating the
    salt on a wizard re-run would orphan every stored consent record.
    Mirror the MAVERICK_RED_TEAM_COMMITMENT_KEY preservation: read the
    current config.toml (which the wizard is about to rewrite) and keep
    the salt that the existing records were digested under.
    """

    try:
        prior = tomllib.loads(config_file().read_text(encoding="utf-8"))
        salt = str((prior.get("consent_registry") or {}).get("subject_salt") or "")
        if 16 <= len(salt.strip()) <= 256:
            return salt.strip()
    except (OSError, ValueError):
        pass
    return secrets.token_urlsafe(24)


def _spending_alert_at(raw) -> list[int] | None:
    """The wizard's spending-alert answer as ``alert_at``; None keeps the
    default (50, 75, 100). "none" means no alerts. An answer that cannot be
    read keeps the default rather than silently turning alerts off."""
    from maverick.spending_alerts import DEFAULT_ALERT_AT, validate_alert_at

    text = str(raw if raw is not None else "").strip()
    if not text:
        return None
    if text.lower() in ("none", "off", "no"):
        return []
    try:
        chosen = validate_alert_at([part for part in text.replace(";", ",").split(",") if part.strip()])
    except ValueError:
        print("  Spending alerts: keeping 50, 75 and 100 percent (that answer could not be read).")
        return None
    return None if chosen == list(DEFAULT_ALERT_AT) else chosen


def _typical_cost_min_runs(raw) -> int | None:
    """The wizard's answer for how many finished tasks a typical cost needs;
    None keeps the default (10). An answer that cannot be read keeps it too."""
    from maverick.typical_cost import DEFAULT_MIN_RUNS, validate_min_runs

    text = str(raw if raw is not None else "").strip()
    if not text:
        return None
    try:
        chosen = validate_min_runs(text)
    except ValueError:
        print(f"  Typical cost: keeping {DEFAULT_MIN_RUNS} finished tasks (that answer could not be read).")
        return None
    return None if chosen == DEFAULT_MIN_RUNS else chosen


def _employee_activation_job_choices() -> list[str]:
    from maverick.config import EMPLOYEE_ACTIVATION_JOBS
    chosen = _q_checkbox("Which first-job guides may employees use within their existing access?", list(EMPLOYEE_ACTIVATION_JOBS.values()), default=list(EMPLOYEE_ACTIVATION_JOBS.values()))
    return [key for key, label in EMPLOYEE_ACTIVATION_JOBS.items() if label in chosen]


_LOCAL_FIRST_PROVIDERS = frozenset({"ollama", "tgi"})


def _local_first_model(providers: list[str]) -> str | None:
    """Return the default local model spec for the selected providers."""
    for prov in providers:
        if prov not in _LOCAL_FIRST_PROVIDERS:
            continue
        info = catalog.PROVIDERS.get(prov)
        models = (info or {}).get("models") or []
        if models:
            return f"{prov}:{models[0]['id']}"
    return None


def _pick_agent_budget_reporting() -> dict[str, float]:
    """The same bounded startup choices offered in All settings."""
    console.print("[dim]Keep part of a task's dollar limit for its final answer. "
                  "Running-spending updates do not change how charges or limits are counted.[/dim]")
    choices = {}
    for field, question, default, maximum in (
        ("synthesis_reserve", "  Budget kept for the final answer, as a percentage (0–100; zero keeps no reserve)", "25", 100),
        ("spend_mirror_interval", "  Refresh recorded running spending every how many seconds (0–300; zero updates every step)", "5", 300),
    ):
        while True:
            try:
                value = float(_q_text(question, default=default).strip())
                if not math.isfinite(value) or not 0 <= value <= maximum:
                    raise ValueError
            except ValueError:
                console.print(f"[yellow]Enter a number from 0 to {maximum}.[/yellow]")
                continue
            choices[field] = value / 100 if field == "synthesis_reserve" else value
            break
    return choices


def _pick_action_recipe_lineage() -> dict[str, Any]:
    """Keep service-attested training evidence separate from execution approval."""
    enabled = _q_confirm(
        "Enable signed reviewed evidence for action recipes? "
        "Service signatures attest recorded reviews, not personal reviewer signatures. "
        "Copied business data needs explicit retention consent; current eligibility is checked before actions. "
        "Older unsigned learned flows may stop until rebuilt from permitted signed examples.",
        default=False,
    )
    out: dict[str, Any] = {"action_recipe_lineage": enabled}
    out["require_action_recipe_lineage"] = _q_confirm(
        "Require governed reviewed lineage for every learned action recipe? "
        "This blocks raw or stripped-lineage recipes at save, publication and execution. "
        "Example capture or signed evidence also blocks them even if this choice is off.",
        default=False,
    )
    if out["require_action_recipe_lineage"] and not enabled:
        console.print("[yellow]Lineage is required but disabled; learned recipes remain blocked until configured.[/yellow]")
    if enabled:
        while True:
            issuer = _q_text(
                "  Stable action-evidence issuer ID (letters/digits/._:-, max 128; blank keeps signing unavailable)",
                default="",
            ).strip()
            if not issuer or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", issuer):
                break
            console.print("[yellow]Use a bounded ASCII issuer identifier, not a URL.[/yellow]")
        out["action_evidence_issuer"] = issuer
        while True:
            raw_revoked = _q_text(
                "  Revoked action-evidence key IDs (comma-separated 16-character lowercase hex; blank = none)",
                default="",
            ).strip()
            revoked = [part.strip() for part in raw_revoked.split(",")] if raw_revoked else []
            if all(re.fullmatch(r"[0-9a-f]{16}", key) for key in revoked) and len(set(revoked)) == len(revoked):
                break
            console.print("[yellow]Use unique 16-character lowercase hex key IDs.[/yellow]")
        out["action_evidence_revoked_keys"] = revoked
    return out


def _secure_or_loopback_url(value: str) -> bool:
    """Allow HTTPS or exact loopback HTTP origins, never hostname prefixes."""
    if "\\" in value or any(character.isspace() or ord(character) < 32 for character in value):
        return False
    try:
        url = urlsplit(value)
        # Accessing port also rejects malformed/out-of-range ports.
        _ = url.port
        return bool(
            url.hostname and url.username is None and url.password is None
            and (url.scheme == "https" or (
                url.scheme == "http" and url.hostname in {"localhost", "127.0.0.1", "::1"}
            ))
        )
    except ValueError:
        return False


def _pick_approval_url(prompt: str) -> str:
    while True:
        value = _q_text(prompt, default="").strip()
        if not value or _secure_or_loopback_url(value):
            return value
        console.print("Use an HTTPS URL for approval links (loopback HTTP allowed).", style="yellow")


def _require_secure_url(value: str, label: str) -> None:
    if not _secure_or_loopback_url(value):
        raise ValueError(f"{label} requires an HTTPS URL (loopback HTTP allowed).")


def _pick_oidc_value(prompt: str, *, url: bool = False) -> str:
    while True:
        value = _q_text(prompt, default="").strip()
        if value and (not url or _secure_or_loopback_url(value)):
            return value
        console.print("[yellow]Enter an HTTPS URL (HTTP is allowed only on loopback).[/yellow]" if url
                      else "[yellow]This value is required when OIDC is enabled.[/yellow]")


def _pick_oidc_secret(prompt: str, *, minimum: int = 1) -> str:
    while True:
        value = _q_secret(prompt).strip()
        if len(value) >= minimum:
            return value
        console.print(f"[yellow]Enter a secret with at least {minimum} characters.[/yellow]")


def pick_oidc() -> dict[str, Any]:
    """Opt-in to OIDC ID-token verification for `maverick serve` (SSO).

    Off by default. When enabled, the server verifies an OpenID-Connect ID
    token (RS256/ES256 only — never HMAC/none) against the issuer + audience
    you configure, and maps the verified ``sub`` to a ``user:<sub>`` principal.
    Returns a dict written under ``[auth.oidc]``; ``{"enabled": False}`` when
    declined (so the writer emits nothing).
    """
    console.print(
        "[dim]OIDC SSO lets users authenticate to `maverick serve` with your "
        "identity provider (Okta, Auth0, Entra, Google, ...). Tokens are "
        "verified with the IdP's public keys; only RS256/ES256 are accepted "
        "(HMAC/none are rejected to prevent algorithm-confusion). OFF by "
        "default.[/dim]"
    )
    if not _q_confirm("Enable OIDC SSO token verification?", default=False):
        return {"enabled": False}
    issuer = _pick_oidc_value(
        "  Issuer URL (the IdP's 'iss', e.g. https://example.okta.com)", url=True,
    )
    audience = _pick_oidc_value("  Audience (your app's client_id / API audience)")
    jwks_uri = _pick_oidc_value(
        "  JWKS URI (the IdP's signing-key endpoint, e.g. https://example.okta.com/oauth2/v1/keys)", url=True,
    )
    result: dict[str, Any] = {
        "enabled": True,
        "issuer": issuer,
        "audience": audience,
        "jwks_uri": jwks_uri,
    }
    # Optional: the built-in browser-login (authorization-code) flow. The
    # default path is bearer-token verification only (API clients) or a reverse
    # proxy for browser SSO; this self-contained flow is for deployments that
    # can't run an auth proxy. OFF unless the operator opts in and supplies the
    # OAuth client + a session-signing secret.
    console.print(
        "[dim]Optional: built-in browser login. Lets the dashboard run the "
        "OAuth2 authorization-code flow itself (browser SSO without a separate "
        "auth proxy). Needs an OAuth client_id/secret registered with your IdP "
        "and a redirect URI of <dashboard-url>/auth/callback. OFF by "
        "default.[/dim]"
    )
    if _q_confirm("  Also enable the built-in browser login flow?", default=False):
        client_id = _pick_oidc_value("    OAuth client_id (this dashboard's registered client)")
        client_secret = _pick_oidc_secret("    OAuth client_secret")
        redirect_uri = _pick_oidc_value(
            "    Redirect URI (must be <dashboard-url>/auth/callback)", url=True,
        )
        session_secret = _pick_oidc_secret(
            "    Session-signing secret (a random string of at least 32 characters; keep it secret)",
            minimum=32,
        )
        result.update(
            {
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "session_secret": session_secret,
            }
        )
    return result


def pick_sign_in_security(sso_enabled: bool) -> dict[str, Any]:
    """The "Sign-in security" step: require a second factor, how recent it
    must be for sensitive actions, and the network addresses allowed in.

    Returns a dict the writer emits as ``[auth.mfa]`` and
    ``[auth.ip_allowlist]``; ``{}`` when nothing was chosen (so the writer
    emits nothing and the kernel defaults -- off, 15 minutes, everyone --
    apply). Off by default for compatibility.
    """
    console.print(
        "[dim]Sign-in security. With company sign-in, Lightwork can insist that "
        "the provider confirmed a second factor (authenticator app, security key "
        "or code) and ask for a recent one before sensitive actions such as "
        "changing roles or turning off the emergency stop. You can also limit "
        "which network addresses may reach Lightwork at all. All OFF by "
        "default.[/dim]"
    )
    result: dict[str, Any] = {}
    if _q_confirm("Set browser sign-in time limits? You can change them later in Settings.", default=False):
        result["idle_minutes"] = max(0, min(1440, _safe_int(
            _q_text("  Sign out inactive browsers after (minutes, zero turns the limit off)", default="30"),
            default=30,
        )))
        if sso_enabled:
            result["company_hours"] = max(0, min(168, _safe_int(
                _q_text("  Maximum company sign-in length (hours, zero keeps the existing limit)", default="8"),
                default=8,
            )))
    if sso_enabled and _q_confirm(
        "Require sign-in with a second factor?", default=False
    ):
        result["require"] = True
        minutes = _safe_int(
            _q_text(
                "  Sensitive actions need a second factor no older than (minutes)",
                default="15",
            ),
            default=15,
        )
        result["step_up_minutes"] = max(1, min(minutes, 1440))
    if not sso_enabled:
        # Local sign-in only: the owner's authenticator app (read by
        # maverick.config.get_auth_local_owner_totp). Optional is the default.
        console.print(
            "[dim]Owner's authenticator app. Optional lets the owner add a code from an "
            "authenticator app to their passphrase. Required makes them set one up at their "
            "next sign-in. Off hides the option.[/dim]"
        )
        totp = _q_select(
            "Owner's authenticator app at sign-in",
            ["optional", "required", "off"],
            default="optional",
        )
        if totp in {"required", "off"}:
            result["local_owner_totp"] = totp
    cidrs = _csv_list(
        _q_text(
            "Network addresses or ranges allowed to reach Lightwork "
            "(comma-separated, empty = everyone; include the address you use)",
            default="",
        )
    )
    if cidrs:
        import ipaddress

        bad = [c for c in cidrs if _bad_network(c, ipaddress)]
        while bad:
            console.print(
                f"[yellow]Not a network address or range: {', '.join(bad)}[/yellow]"
            )
            cidrs = _csv_list(_q_text("  Allowed addresses or ranges", default=""))
            bad = [c for c in cidrs if _bad_network(c, ipaddress)]
        if cidrs:
            result["cidrs"] = cidrs
    return result


def _bad_network(text: str, ipaddress) -> bool:
    try:
        ipaddress.ip_network(text, strict=False)
    except ValueError:
        return True
    return False


def _ask_external_agent_followups(advanced: dict[str, Any]) -> None:
    """The external-agent gateway's follow-up questions (gateway already on).

    Governed execution rides on the gateway: naming a connector is the
    operator's explicit decision to let foreign agents ACT through
    Lightwork's egress-guarded, receipted connector path. Blank keeps the
    gateway screen-only; the kernel intersects with its reference factories
    anyway, so the filter here just surfaces a typo at answer time instead
    of silently at runtime.
    """
    raw = _q_text(
        "  Governed connectors external agents may EXECUTE through "
        "(comma-separated: salesforce, servicenow; blank = screen-only)",
        default="",
    )
    connectors = []
    for name in dict.fromkeys(_csv_list(raw, lower=True)):
        if name in ("salesforce", "servicenow"):
            connectors.append(name)
        else:
            console.print(
                f"  [yellow]unknown connector '{name}' — skipped "
                "(valid: salesforce, servicenow)[/yellow]"
            )
    if connectors:
        advanced["external_connectors"] = connectors
    # Both hardening switches below are strict, tightening booleans in the
    # kernel (a malformed config value engages them, never disables).
    if _q_confirm(
        "  Require the strong credential? An agent whose trust entry pins "
        "an Ed25519 key or names a JWT issuer must present it -- its "
        "minted bearer alone stops authenticating (token-only agents are "
        "unaffected). Off by default.",
        default=False,
    ):
        advanced["external_require_signed"] = True
    if _q_confirm(
        "  Step-up approval on credential minting? Each mint/rotation "
        "parks a dashboard approval a decision-maker must approve before "
        "the token is issued (one approval mints exactly one credential). "
        "Off by default.",
        default=False,
    ):
        advanced["external_mint_approval"] = True


def _ask_governed_execution_followups(advanced: dict[str, Any]) -> None:
    """Follow-ups for the two default-off governed-execution planes.

    The session kernel's containment IS the sandbox backend, which was already
    chosen several steps back, so the note points back at that answer and
    names the backends that can host a session at all: the kernel writes its
    driver, statement and result file into the sandbox workdir, which ssh and
    kubernetes do not share with the host.

    Self-refinement's approval gate is asked separately because it is the
    whole reason an agent may write its own instructions at all; declining it
    is a real choice, so it is written explicitly rather than defaulted.
    """
    if advanced.get("repl"):
        console.print(
            "[dim]  The kernel runs model-written Python through "
            "sandbox.exec, so the sandbox backend you picked earlier is its "
            "containment boundary: it should be docker/gvisor/podman -- "
            "'local' runs that code on this machine. ssh and kubernetes "
            "cannot host a session (the kernel needs a workdir shared with "
            "the host); edit [sandbox] backend if you chose one of those."
            "[/dim]"
        )
    if advanced.get("harness_refine") and not _q_confirm(
        "  Require a human approval before a refinement is applied? Each "
        "proposal parks a dual-control approval bound to that one target and "
        "name, spent once. Declining lets an applied refinement rewrite the "
        "agent's own instructions with no human decision. ON by default.",
        default=True,
    ):
        advanced["harness_refine_require_approval"] = False


def _ask_self_harness_evaluation_boundary(advanced: dict[str, Any]) -> None:
    """Collect the durable ledger, container pin, and custody posture."""
    ledger = _q_text(
        "    Existing provisioned holdout query-ledger path "
        "(required for live confirmation; blank = keep failing closed)",
        default="",
    ).strip()
    if ledger:
        advanced["self_harness_holdout_ledger"] = ledger
    while True:
        image_id = _q_text(
            "    Reviewed local evaluator image ID (optional; sha256: plus "
            "64 lowercase hex; blank = resolve the local default image)",
            default="",
        ).strip()
        if not image_id or re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
            break
        console.print(
            "[yellow]Enter an immutable local sha256 image ID or leave it blank.[/yellow]"
        )
    if image_id:
        advanced["self_harness_holdout_container_image"] = image_id
    advanced["self_harness_require_independent_custody"] = _q_confirm(
        "    Require independent evaluator custody for confirmatory results? "
        "Local-only installs fail closed until a separate custodian exists.",
        default=False,
    )


def _pick_codebase(advanced: dict[str, Any]) -> None:
    """Software development: vault your repositories, let swarms build features."""
    if not _q_confirm(
        "  Enable the code vault? Your repositories are held sealed inside Lightwork, "
        "swarms build features on branches, and nothing merges or pushes without "
        "your approval (`maverick code`).",
        default=False,
    ):
        return
    advanced["codebase_enable"] = True
    protect = _q_select(
        "    While a swarm works on your code, a call that would send it outside should",
        choices=["block   - be refused (recommended)",
                 "approve - wait for a human",
                 "audit   - be recorded and allowed"],
        default="block   - be refused (recommended)",
    )
    advanced["codebase_protect"] = (str(protect or "").split() or ["block"])[0]


def _pick_ifc(advanced: dict[str, Any]) -> None:
    """Information-flow control: what an agent has read decides where it may send."""
    mode = _q_select(
        "  Information-flow control: when an agent that has read tenant data (or "
        "your code) calls a tool that sends outside, Lightwork should",
        choices=[
            "audit   - record it and allow (default)",
            "approve - ask a human each time a new kind of data would leave",
            "block   - refuse it",
            "off     - do not track",
        ],
        default="audit   - record it and allow (default)",
    )
    mode = (str(mode or "").split() or ["audit"])[0]
    if mode in ("approve", "block", "off"):
        advanced["ifc_mode"] = mode


def _pick_swarm_scale(advanced: dict[str, Any]) -> None:
    """Swarm scale: a goal may create up to 64 agents by default. Raising it is
    safe only with a model-call bound, so the swarm queues for the provider."""
    if not _q_confirm(
        "  Allow larger swarms (more than 64 agents per goal)? The budget still "
        "caps total spend.",
        default=False,
    ):
        return
    advanced["swarm_max_total_spawns"] = max(1, _safe_int(
        _q_text("    Maximum agents one goal may create", default="256"), default=256))
    advanced["swarm_max_concurrent_model_calls"] = max(0, _safe_int(
        _q_text("    Model calls in flight at once per goal (0 = unbounded)",
                default="16"), default=16))


def _pick_image_edit_models() -> dict[str, str]:
    """The same optional model choices offered after installation."""
    from maverick.image_edit_models import CHOICES, validate_model

    if not _q_confirm(
        "Choose models for hosted image edits now? You can change them later in "
        "All settings > AI models > Images. Replicate image edits may cost money; "
        "setup makes no images.", default=False,
    ):
        return {}
    choices = {}
    for field, _env, label in CHOICES:
        while True:
            value = _q_text(label + " (blank keeps the built-in choice)", default="").strip()
            try:
                choices[field] = validate_model(value)
                break
            except ValueError as exc:
                console.print(str(exc), style="yellow")
    return choices


def _drop_self_connect_without_connections(advanced: dict[str, Any]) -> None:
    """Employee-connected accounts are written only with named connections.

    Say so instead of silently dropping the answer.
    """
    if advanced.get("connections_self_connect") and not advanced.get("connections"):
        advanced["connections_self_connect"] = False
        console.print("[yellow]Employees can connect their own accounts only when named connections are on. "
                      "That answer was not saved. Turn on named connections to use it.[/yellow]")


def _drop_per_tenant_keys_without_at_rest(advanced: dict[str, Any]) -> None:
    """Per-tenant keys are written only with at-rest encryption; say so when dropped."""
    if advanced.get("encrypt_per_tenant") and not advanced.get("encrypt_at_rest"):
        advanced["encrypt_per_tenant"] = False
        console.print("[yellow]Per-tenant encryption keys require at-rest encryption. "
                      "That answer was not saved. Turn on at-rest encryption to use them.[/yellow]")


def pick_advanced() -> dict[str, Any]:
    """Configure advanced reasoning, learning, and governance features.

    Governed learning choices default on; higher-authority or infrastructure
    features retain explicit opt-ins. Many have reviewed in-product controls;
    deployment-only choices require a separate administrator change.

    The toggles are asked in groups, in this order; the follow-up questions
    that depend on them come after.
    """
    console.print()
    advanced: dict[str, Any] = {
        **_pick_working_toggles(),
        **_pick_learning_toggles(),
        **_pick_memory_and_product_toggles(),
        **_pick_governance_monitor_toggles(),
        **_pick_feature_allowances(),
        **_pick_learning_lifecycle_toggles(),
        **_pick_workflow_and_extension_toggles(),
        **_pick_enterprise_toggles(),
        **_pick_data_protection_toggles(),
        **_pick_runtime_toggles(),
    }
    _drop_self_connect_without_connections(advanced)
    _drop_per_tenant_keys_without_at_rest(advanced)
    # The governed sidecar is an extension of the external-agent boundary: its
    # clients authenticate through per-agent MCP credentials and then inherit
    # the same trust/revocation/control-plane posture. Keep the deployment
    # prompt behind that explicit higher-level opt-in so a normal wizard run is
    # unchanged and the operator sees the dependency before enabling egress.
    if advanced.get("external_agents"):
        sidecar = pick_governed_mcp_sidecar()
        if sidecar:
            advanced["mcp_sidecar"] = sidecar
    _ask_insight_exchange(advanced)
    _ask_flow_followups(advanced)
    if advanced.get("external_agents"):
        _ask_external_agent_followups(advanced)
    # Both governed-execution planes are off by default, so the helper guards
    # each of its own questions rather than gating the call.
    _ask_governed_execution_followups(advanced)
    _ask_self_harness_followups(advanced)
    _ask_chat_and_resource_followups(advanced)
    _ask_regulated_deployment(advanced)
    _ask_identity_followups(advanced)
    _ask_dashboard_followups(advanced)
    _ask_model_followups(advanced)
    return advanced


def _pick_working_toggles() -> dict[str, Any]:
    """Cost, planning, context, voice, attachments, documents and compaction."""
    return {
        "agent_budget_reporting": _pick_agent_budget_reporting(),
        "image_edit": _pick_image_edit_models(),
        "cost_aware": _q_confirm(
            "Cost-aware routing? Use the cheapest capable model per role to cut spend.",
            default=False,
        ),
        "tree_of_thought": _q_confirm(
            "Tree-of-thought planning? Draft a few plans and let a critic pick the "
            "best before working (more tokens up front, fewer dead ends).",
            default=False,
        ),
        "compact_history": _q_confirm(
            "Compact long conversations? Keep the most relevant older turns under a "
            "token budget instead of just the last few.",
            default=False,
        ),
        "model_scaled_context": _q_confirm(
            "Model-scaled context? Size history windows, compaction targets, and "
            "routing thresholds to the driving model's real context window (a "
            "1M-token model gets 1M-token bounds) instead of fixed constants. "
            "Recommended; ON by default.",
            default=True,
        ),
        "voice_commands": _q_confirm(
            "Dashboard voice commands? A mic button on the chat composer records "
            "a spoken goal and transcribes it (OpenAI/Groq Whisper key or the "
            "built-in local Whisper; falls back to browser speech recognition). "
            "ON by default.",
            default=True,
        ),
        "voice_local_stt": _q_confirm(
            "  Allow local speech model downloads? Fetch a checksum-verified "
            "Whisper model (~148 MB, at dashboard startup) so the mic works "
            "offline with no provider key — the engine ships with the "
            "dashboard. You can also set it up later in Settings > Models.",
            default=True,
        ),
        "attach_any_mime": _q_confirm(
            "Accept attachments of ANY declared type? Text, images, audio, video, "
            "and document formats are always accepted; this also admits anything "
            "else EXCEPT executables/archives (magic-byte deny stays). OFF by "
            "default.",
            default=False,
        ),
        "attachment_understanding": _q_confirm(
            "Attachment understanding? Auto-transcribe incoming audio/video and "
            "extract text from Office documents into the goal context (audio "
            "needs an STT key: OPENAI_API_KEY/GROQ_API_KEY or local "
            "faster-whisper). ON by default.",
            default=True,
        ),
        "macro_cell_edits": _q_confirm(
            "Allow cell edits in macro-enabled Excel workbooks? Preserve VBA and untouched workbook parts; "
            "never execute macros. Whole-workbook replacement and digitally signed documents are refused.",
            default=False,
        ),
        "native_recalculation": _q_confirm(
            "Recalculate existing spreadsheet formulas with offline LibreOffice Calc? Requires the "
            "document engine image and a Docker, Podman or Kubernetes sandbox. Original formulas and VBA are preserved.",
            default=False,
        ),
        "pdf_ocr": _q_confirm(
            "Read scanned PDFs with offline OCR? Requires the document engine image (Poppler/Tesseract) "
            "and a Docker, Podman or Kubernetes sandbox. Default limit: 20 pages per call.",
            default=False,
        ),
        "document_engine_image": _q_text(
            "Document engine image (build/publish deploy/docker/Dockerfile.documents before enabling native processing):",
            default="lightwork-documents:local",
        ),
        "compaction_strategy": _q_select(
            "  Compaction strategy? (default = simple shrink)",
            [
                "default     - keep recent + trim big tool outputs",
                "learned     - LLM summary, self-tuning prompt picker",
                "multimodal  - stub heavy image/audio blocks to text",
                "streaming   - incremental running summary (long chats)",
                "graph       - entity-relation digest",
            ],
            default="default     - keep recent + trim big tool outputs",
        ).split()[0],
    }


def _pick_learning_toggles() -> dict[str, Any]:
    """Reflexion, self-harness and the two recording opt-ins."""
    return {
        "reflexion": _q_confirm(
            "Reflexion learning? Remember lessons from failed runs and recall them "
            "on the next similar goal.",
            default=True,
        ),
        "self_harness": _q_confirm(
            "Self-harness? Learn a MODEL-SPECIFIC operating-guidance addendum from "
            "recurring failures -- mined, validated on held-out cases, and gated "
            "through the same promotion ladder as every other learned change -- "
            "then recalled into that model's system prompt. Inspect or roll it "
            "back any time with `maverick self-harness`. ON by default.",
            default=True,
        ),
        "approval_challenges": _q_confirm(
            "Allow fictional approval challenges and isolated local checks? Uses disposable local requests, "
            "no customer credentials and no AI calls. Each check and shared file needs separate review; "
            "no live approval rule is activated. OFF by default.", default=False,
        ),
        "instruction_capture": _q_confirm(
            "Allow private instruction recording on this local installation? Each person must separately authorize "
            "one task's next completed model call. It records instruction text, makes no extra AI call, "
            "and does not enable learning. OFF by default.", default=False,
        ),
    }


def _pick_memory_and_product_toggles() -> dict[str, Any]:
    """Fleet memory, immune canaries, product modules, external agents and memory options."""
    return {
        "fleet_memory": _q_confirm(
            "Fleet memory? Let EXTERNAL agents (Agentforce, Copilot, custom) "
            "deposit experience into and recall from Lightwork's governed "
            "memory -- Shield-scanned, provenance-tagged, audited reads. "
            "An explicit trust decision; OFF by default.",
            default=False,
        ),
        "immune_canaries": _q_confirm(
            "Oversight canaries? Let operators seed realistic, known-flawed "
            "approvals into the real approvals queue (`maverick immune canary`) "
            "to measure whether reviewers catch them -- per person and decision "
            "class, with earned approval authority. Nothing executes on a canary. "
            "An explicit decision to test your people; OFF by default.",
            default=False,
        ),
        "immune_twin_record": _q_confirm(
            "Production twin recording? Record every goal's tool results "
            "(sealed, per tenant) so a goal can be replayed later against exactly "
            "what production saw (`maverick immune twin replay`) -- to test a new "
            "model, prompt or policy on real work with nothing live touched. "
            "Retains tool output; OFF by default.",
            default=False,
        ),
        "cortex": _q_confirm(
            "Enable Cortex, the governed company memory over knowledge, skills, "
            "lessons, the Operating Record and fleet memory (recommended)? One "
            "recall/deposit surface, tenant-exact, one audit row per read and "
            "per write; each source's own toggle still applies. Inspect it with "
            "`maverick cortex status`. ON by default.",
            default=True,
        ),
        "commerce": _q_confirm(
            "Commerce suite tools? Give the com_ shopper and merchant packs "
            "their storefront/merchant tools: search, compare, cart-building "
            "under per-session spend and quantity caps, product Q&A with "
            "provenance, and STAGED store changes a human approves. The agent "
            "never sees payment details or the checkout page -- it hands off "
            "an opaque cart link. Ships with the in-memory demo backend; a "
            "real storefront is plugged in via maverick.commerce. OFF by "
            "default.",
            default=False,
        ),
        "shoring": _q_confirm(
            "Autonomous Shoring tooling (recommended)? The engagement surface for "
            "moving a whole business function onto the workforce: a tenant-scoped "
            "Book of Work, service levels measured from real completed work, and "
            "the exception desk over the approvals queue, at /shoring. Includes "
            "reviewed starter teams with offline samples and evidence-linked "
            "structured input checks. Samples do not qualify live connections "
            "or enable outside actions. ON by "
            "default; a deliberate no is written as an explicit opt-out.",
            default=True,
        ),
        "stripe_billing": _q_confirm(
            "Collect money via Stripe? Turn the metered usage invoices into REAL "
            "charges: one Stripe customer + platform-fee subscription per tenant, "
            "with a webhook that downgrades a tenant to the base plan on a failed "
            "payment and restores it when paid. The secret key stays in the env "
            "(MAVERICK_STRIPE_SECRET_KEY), never in this file; metered model-usage "
            "billing stays OFF until you set the markup. OFF by default.",
            default=False,
        ),
        "external_agents": _q_confirm(
            "External-agent gateway? Govern agents built on OTHER platforms "
            "(Salesforce Agentforce, AWS Bedrock, custom runtimes): enroll "
            "them, credential them, screen their actions, and account their "
            "runs on the Operating Record. An explicit trust decision; OFF "
            "by default.",
            default=False,
        ),
        "repl": _q_confirm(
            "Governed session kernel? Let an agent write PYTHON against a live "
            "namespace instead of composing fixed tool calls -- every "
            "statement is hashed, injection-screened, receipted on the "
            "tamper-evident chain and audited. It admits ARBITRARY CODE "
            "EXECUTION, so run it on a container sandbox backend "
            "(docker/gvisor/podman), never on 'local'. OFF by default.",
            default=False,
        ),
        "harness_refine": _q_confirm(
            "Governed self-refinement? Let an agent PROPOSE a change to its "
            "own operating instructions (prompt / skill / memory) from a "
            "failure it observed. Nothing self-applies: a proposal parks a "
            "human approval, applying is snapshotted and reversible, and both "
            "ends land in the signed learning audit. OFF by default.",
            default=False,
        ),
        "session_tree": _q_confirm(
            "Run forking? Branch a run at a decision point so Oversight can "
            "read what the agent chose beside the alternative, under one root "
            "on the Run Tree page. Lineage only -- forking re-executes "
            "nothing and spends no tokens. ON by default.",
            default=True,
        ),
        "memory_guard": _q_confirm(
            "Memory Guard (OWASP ASI06)? Screen every stored fact for prompt-"
            "injection/poisoning, stamp it with provenance + a trust tier, and "
            "keep low-trust memory out of the agent's standing brief (trust-aware "
            "retrieval). Every decision is audited. OFF by default.",
            default=False,
        ),
        "fact_tags": _q_confirm("Organize shared business facts with tags? Tags do not change access.", default=False),
        "temporal_memory": _q_confirm(
            "Temporal memory? Keep a bitemporal history of every fact (validity "
            "windows) instead of overwriting -- answer 'what did we believe on "
            "date X, and why' for the Operating Record. OFF by default.",
            default=False,
        ),
    }


def _pick_governance_monitor_toggles() -> dict[str, Any]:
    """Governance and compliance monitors."""
    return {
        "fairness_monitor": _q_confirm(
            "Continuous fairness monitoring (ISO 42001 A.6.2.6)? Watch decision "
            "outcomes over a rolling window and raise a signed FAIRNESS_ALERT when "
            "the four-fifths rule is breached or fairness drifts below baseline. A "
            "deployment opts in by feeding the monitor its outcomes. OFF by default.",
            default=False,
        ),
        "drift_monitoring": _q_confirm(
            "Continuous model drift monitoring? Keep governed aggregate baselines "
            "for feature/prediction distributions, embeddings, and delayed-ground-"
            "truth performance; emit bound assurance evidence and a signed alert "
            "when configured PSI, KL, cosine, or decay thresholds are crossed. Raw "
            "rows and vectors are not retained. OFF by default.",
            default=False,
        ),
        "ai_incident_reporting": _q_confirm(
            "EU AI Act Art. 73 serious-incident reporting? Classify an "
            "assurance incident under Art. 3(49), start the tiered 2/10/15-day "
            "clock from awareness, draft the report for the routed Member-State "
            "authority, and record human-gated submissions. Clocks and drafts "
            "only -- nothing is ever transmitted. OFF by default.",
            default=False,
        ),
        "ai_regulatory_feed": _q_confirm(
            "AI regulatory-change impact bridge? Run reviewed regulatory "
            "alerts through explicit operator rules to create policy-impact "
            "records, exact evidence-staleness flags, and idempotent customer "
            "notices. Requires finance operations and the AI evidence gateway. "
            "Decision support, never a legal applicability opinion. OFF by "
            "default.",
            default=False,
        ),
        "eu_conformity": _q_confirm(
            "EU AI Act conformity workflows? Human-gated registers for the "
            "Art. 27 fundamental-rights impact assessment, the Annex IV "
            "technical-documentation checklist, and the Art. 43 conformity-"
            "assessment route with forbidden combinations refused. Drafting "
            "and tracking assistance, never a conformity assessment or legal "
            "advice. OFF by default.",
            default=False,
        ),
        "explainability": _q_confirm(
            "Model-agnostic explainability? Seeded permutation importance, "
            "partial dependence, Spearman global sensitivity, and "
            "standardized-deviation reason codes, recordable as governed "
            "evidence. Attribution for your own review, never a fairness "
            "certification. OFF by default.",
            default=False,
        ),
        "content_provenance": _q_confirm(
            "Signed content provenance (EU AI Act Art. 50(2), applicable "
            "2 Dec 2026)? Machine-readable sidecar manifests binding "
            "generated content to the generating system, Ed25519-signed and "
            "verifiable against an external key registry. Marking assistance "
            "only, never a content-authenticity certification. OFF by "
            "default.",
            default=False,
        ),
        "llm_gateway": _q_confirm(
            "Governed LLM gateway? Agents built anywhere point their "
            "OpenAI- or Anthropic-compatible base URL at Lightwork; every "
            "call crosses a governed checkpoint (own bearer, model allowlist, "
            "prompt/completion redaction, injection screen, bounded bodies, "
            "team budget, and egress-guarded upstream) and unknown callers "
            "land in a shadow-AI ledger. Requires reviewed upstream URLs and "
            "tokens after setup. OFF by default.",
            default=False,
        ),
        "vendor_management": _q_confirm(
            "Third-party vendor register? Governed vendor records with "
            "criticality tiers, questionnaire campaigns served over the "
            "public form endpoint, monitoring notes, links to assessments "
            "and RoPA entries, and a OneTrust vendor-CSV importer. A "
            "register and audit trail, never a vendor risk rating service. "
            "OFF by default.",
            default=False,
        ),
        "consent_registry": _q_confirm(
            "Consent receipts and preferences registry? Per-subject consent "
            "receipts (purpose, policy version, channel) with salted "
            "subject digests, a current-preference projection, audit "
            "export, and a OneTrust consent-CSV importer. The governed "
            "record behind a consent front end, never a cookie banner or "
            "TCF-certified CMP. OFF by default.",
            default=False,
        ),
        "data_map": _q_confirm(
            "Data map and discovery? A governed register of data assets "
            "with a column-name classifier, a deterministic CONTENT "
            "classifier for pasted data samples (Luhn/mod-97/structural "
            "validation, never an ML guess), an information_schema CSV "
            "importer for warehouses, a SharePoint site census via "
            "Microsoft Graph, and a Snowflake masking-policy DDL export. "
            "Triage for a human data-mapping exercise, never a crawler. "
            "OFF by default.",
            default=False,
        ),
        "ediscovery": _q_confirm(
            "Legal holds and matter export? Hold the records of a legal matter for "
            "named custodians and date ranges, so bulk deletion pauses and their "
            "records cannot be erased, then export the matter as a signed archive "
            "for counsel. Only auditors and administrators see matter details. "
            "OFF by default.",
            default=False,
        ),
        "breach_notification": _q_confirm(
            "Breach-notification planner? Fourteen regimes' verified "
            "who/when/whether rules (GDPR, HIPAA, six US states, LGPD, "
            "PIPEDA, Australia, Singapore, Japan, Korea) turned into "
            "per-incident obligations with computed deadlines and "
            "citations. Decision support for your counsel, never legal "
            "advice, and nothing is ever transmitted. OFF by default.",
            default=False,
        ),
        "dsar_fulfillment": _q_confirm(
            "DSAR fulfillment pipeline? Execute subject requests as a "
            "governed pipeline: recorded identity verification, collection "
            "logging, deterministic third-party redaction, and a "
            "token-gated response link assembled at delivery time (no "
            "second copy of personal data stored). OFF by default.",
            default=False,
        ),
        "ai_literacy": _q_confirm(
            "EU AI Act Art. 4 AI-literacy register? Named humans set which "
            "trainings each role requires, record completions with evidence "
            "references, and export gap and evidence snapshots for auditors. "
            "Decision support, never a certification of competence. OFF by "
            "default.",
            default=False,
        ),
        "grc_sync": _q_confirm(
            "Outbound GRC synchronization? Idempotently mirror model-risk "
            "findings, accepted risks, and incidents into your ServiceNow, "
            "Archer, or other REST GRC system as governed pointer records "
            "with a round-trip link. Evidence never leaves Lightwork. Paths "
            "and connector are configured in [grc_sync]. OFF by default.",
            default=False,
        ),
        "agent_topology": _q_confirm(
            "Agent dependency and MCP blast-radius governance? Project each "
            "enabled agent's tools, MCP servers, hosts, paths, knowledge, and model "
            "routes with the trust boundary at every hop; promote configured MCP "
            "servers into the assurance inventory without retaining credentials. "
            "OFF by default.",
            default=False,
        ),
        "governance_inventory": _q_confirm(
            "Enable the shared governance inventory? Build a tenant-scoped, "
            "revisioned projection across the stock governance suites and entity "
            "graph with closed retention, record, relationship, export, and "
            "snapshot bounds. OFF by default.",
            default=False,
        ),
        "specialist_discipline": _q_confirm(
            "Specialist operating discipline? Append each business suite's "
            "professional guardrails (finance maker-checker, legal privilege, "
            "HR PII-minimization, ...) to every domain pack's persona at "
            "spawn. Recommended; prompts only, hard limits stay enforced by "
            "capabilities/governance.",
            default=True,
        ),
    }


def _pick_feature_allowances() -> dict[str, Any]:
    """The ``allow_*`` dashboard feature allowances."""
    return {
        "allow_pack_editing": _q_confirm(
            "Allow editing agents (domain packs) from the dashboard? Operators "
            "can fork/tweak a specialist's persona, tools, and workflow per "
            "client; an edit is validated before it saves, so it can never "
            "weaken the safety envelope. Turn off to lock the agent roster.",
            default=True,
        ),
        "allow_runtime_configuration_status": _q_confirm(
            "Show saved versus startup-acknowledged configuration for running services? Missing or stale service evidence remains unconfirmed.", default=True,
        ),
        "allow_employee_task_diagnostics": _q_confirm(
            "Show employees bounded diagnostics and support guidance for their own tasks? No additional record access is granted.", default=True,
        ),
        "employee_activation_jobs": _employee_activation_job_choices(),
        "allow_employee_activation": _q_confirm(
            "Guide signed-in employees through readiness checks and their first allowed task? Existing policy and budget limits still apply.", default=True,
        ),
        "allow_configuration_profiles": _q_confirm(
            "Allow reviewed, secret-free configuration profiles and outcome presets? "
            "Import previews every change and keeps current policy checks.", default=True,
        ),
        "allow_conversation_inbox": _q_confirm(
            "Let people add guidance, queue their next message or start separate work while a task runs? On by default. "
            "Guidance is reviewed and read at the task's next safe point; existing task ownership, permissions and spending limits remain enforced.",
            default=True,
        ),
        "allow_public_chat": _q_confirm(
            "Allow a chat box on your public website for anonymous visitors? Off by default. "
            "Each website is listed exactly and has a daily spending limit. Visitors can ask one "
            "published specialist's questions only; they cannot use tools or see your records.",
            default=False,
        ),
        "allow_human_conversation_handoffs": _q_confirm(
            "Allow reviewed human help inside Chat? People select an on-duty helper "
            "and review the brief they share. AI pauses before the helper takes over; "
            "returning to AI is a separate choice. Off by default.", default=False,
        ),
        "allow_chat_message_actions": _q_confirm(
            "Let people try another answer, edit and resend a message, or branch from an earlier answer? "
            "The original conversation is kept. Alternatives use current access and spending limits; "
            "connected actions require a separate review.", default=True,
        ),
        "allow_personal_preferences": _q_confirm(
            "Allow account-scoped writing style, display preferences, pinned pages, saved task filters and daily work layout? "
            "Personal choices never grant tools or change security or retention policy.",
            default=True,
        ),
        "allow_draft_recovery": _q_confirm(
            "Keep encrypted recovery copies of unfinished dashboard work? "
            "Copies are private to each account and workspace. Credentials and "
            "attachments are excluded; restoring never runs or publishes work.",
            default=True,
        ),
        "allow_support_center": _q_confirm(
            "Allow installation administrators to prepare, review and download "
            "redacted diagnostics from Help? Nothing is sent automatically.",
            default=True,
        ),
        "allow_record_search": _q_confirm(
            "Include business records in the app's page finder? Searches use "
            "only metadata accessible to the signed-in account and workspace, "
            "with visible coverage limits; document bodies are excluded.",
            default=True,
        ),
        "allow_workspace_recovery": _q_confirm(
            "Enable administrator recovery of local work and retained installation "
            "safety settings? Workspace snapshots need a separately kept recovery key. "
            "Settings restoration uses verified saved copies and never resets an "
            "unreadable policy. External stores and other shared administration "
            "are excluded.",
            default=False,
        ),
        "allow_action_center": _q_confirm(
            "Enable the personal Action Center for approvals, sign-offs, and "
            "assessment reviews, with private read and snooze preferences?",
            default=True,
        ),
        "allow_guided_onboarding": _q_confirm(
            "Offer a guided first workflow in the app, completed only when a "
            "current result has a recorded human review?", default=True,
        ),
        "allow_workflow_readiness": _q_confirm(
            "Show workflow readiness in the app, including implementation "
            "limits and outstanding live or platform validation?", default=True,
        ),
        "allow_project_reviews": _q_confirm(
            "Enable project team reviews of selected, fixed task results? "
            "Assigned workspace reviewers cannot execute or sign off the live task.",
            default=False,
        ),
        "allow_work_details": _q_confirm(
            "Enable named business fields and stages for tasks and security records? "
            "Your team sets them up in the app and reviews each save. Business labels do not execute or approve work.",
            default=True,
        ),
        "allow_task_handoffs": _q_confirm(
            "Enable named task handoffs with explicit recipient acceptance, selected evidence and a new-work ceiling? Requires selected deliverable bundles.",
            default=False,
        ),
        "allow_deliverable_bundles": _q_confirm(
            "Enable selected deliverable bundles with named recipient access, separate human acceptance and offline verification?",
            default=False,
        ),
        "allow_project_workspaces": _q_confirm(
            "Enable project workspaces with explicit outcomes, milestones and reviewed source context? "
            "Only explicitly chosen colleagues see planning metadata; private tasks and review packets keep separate access rules.",
            default=False,
        ),
        "allow_employee_companions": _q_confirm(
            "Enable personal companions for employees enrolled by a workspace "
            "administrator, with own-task status and optional AI drafts? An "
            "administrator must permit drafts for each employee. The configured "
            "AI service receives messages, eligible retained history and permitted "
            "own-task titles and status. Administrators manage policy and audit "
            "metadata, without access to private companion history. Companions "
            "cannot take task actions or use connected sources.",
            default=False,
        ),
        "allow_personal_data_controls": _q_confirm(
            "Enable My Data, owned-memory controls and verified channel linking? Sharing stays off until the employee chooses it.",
            default=False,
        ),
        "allow_employee_content_access_requests": _q_confirm(
            "Employee tasks and chats are private to their owner. Enable exceptional "
            "task/export reads and exact approval-card reads with a separate reviewer, a stated purpose, "
            "expiry within one hour and a recorded receipt for each read?", default=False,
        ),
        "allow_permission_access_requests": _q_confirm(
            "Enable named employees to request permission reviews from the responsible administrator? Requests never grant access automatically.", default=False,
        ),
        "allow_employee_departures": _q_confirm(
            "Enable reviewed employee-departure controls? Named installation administrators "
            "can deactivate accounts, remove reviewed local credentials, retire recurring schedules "
            "and record handoff owners. Closure retains data, holds and explicit named responsibility "
            "for running work and unverified external outcomes.", default=False,
        ),
        "allow_outcome_measurement": _q_confirm(
            "Enable measured workflow pilots with paired baseline observations "
            "and explicit accepted outcomes? No savings are assumed.", default=False,
        ),
        "allow_commitment_viability": _q_confirm(
            "Enable a local promise-planning pilot based on the orders, capacity and stock "
            "your team enters? It suggests decisions but does not reserve anything with suppliers.",
            default=False,
        ),
        "allow_signing_identity_transition": _q_confirm(
            "Permit installation administrators to review dual-signed publisher or "
            "update-key bridge releases in isolated recovery mode? This is a new "
            "trust decision for all local workspaces; ordinary updates do not need it.",
            default=False,
        ),
        "allow_work_restructuring": _q_confirm(
            "Enable share preparation safely? Check exact shared preparation across permitted original local cases, with separate complete results and deadlines.",
            default=False,
        ),
        "allow_portable_competence": _q_confirm(
            "Enable share and qualify local rule structures? Release only reviewed anonymous local rule structures. Qualify them against a target workflow and its own permitted cases before any local use.",
            default=False,
        ),
        "allow_private_task_computation": _q_confirm(
            "Enable private task calculations? Check a bounded rule using a permitted task attachment and release only a separately approved fixed answer. Original data stays private.",
            default=False,
        ),
        "allow_procedure_interactions": _q_confirm(
            "Enable check local rules together? Compare two owned local rules in both orders and check all supported starting values before any combined use.", default=False,
        ),
        "allow_operational_competence_acquisition": _q_confirm(
            "Enable teaching-question planning? Compare supported rule alternatives and use only currently permitted effort reports. Teaching and publication remain separate reviews.", default=False,
        ),
        "allow_request_program": _q_confirm(
            "Enable prepare an answer for this request? Check bounded arrangements of your existing taught rules against permitted original cases for one request. Nothing is published automatically.", default=False,
        ),
        "allow_commitment_economic_alternatives": _q_confirm(
            "Enable compare additional-work economics? Compare reported offer prices and full incremental costs with currently protected commitments. Results remain conditional on your stated facts.", default=False,
        ),
        "allow_workflow_step_checks": _q_confirm(
            "Enable try one workflow step? Check one owned taught step against ordinary entered values without running the whole workflow or any connected action.", default=False,
        ),
        "allow_applicability_regions": _q_confirm(
            "Enable checked answer regions? Check both local rule versions across every supported starting situation. Only current separately permitted expected answers can choose a version; unclear situations remain for review.", default=False,
        ),
        "allow_governed_rule_evolution": _q_confirm(
            "Enable rewriting and checking local rules? Build alternative local rules and a complete checking order from one owned published rule. Independently review every change before publication, and retain the exact previous release for restoration.", default=False,
        ),
        "allow_recovery_visibility": _q_confirm(
            "Enable missing-reply practice? Practice with fictional sign-offs to see when identical visible status hides different original outcomes. No live approval or connected service is used.", default=False,
        ),
        "allow_semantic_rule_reuse": _q_confirm(
            "Enable complete rule-behavior evidence reuse? Check every supported input for a local Yes/No or bounded whole-number rule before reusing prior evidence across a rewrite. All checks count toward the reviewed work allowance.", default=False,
        ),
        "allow_commitment_capability_learning": _q_confirm(
            "Enable local additional-work qualification from reported capacity, possible additions and scoped trial results? "
            "Accepted commitments stay protected. This does not verify supplier stock or reserve resources.",
            default=False,
        ),
        "allow_shared_decision_evidence": _q_confirm(
            "Enable shared decision reviews using the facts and possible situations your team enters? "
            "Each case needs explicit sharing permission. Reported facts are not independently verified and no business action runs.",
            default=False,
        ),
        "allow_role_editing": _q_confirm(
            "Allow editing the core roles (orchestrator, coder, ...) from the "
            "dashboard? Operators can add a per-client system-prompt addendum "
            "to a role. Turn off to lock role behavior. (Model/effort routing "
            "is configured separately.)",
            default=True,
        ),
    }


def _pick_learning_lifecycle_toggles() -> dict[str, Any]:
    """Dreaming, verification, autonomy, rewards and the governed learning loops."""
    return {
        "dreaming_llm_consolidation": _q_confirm(
            "  └ LLM-enriched consolidation? Have the cheap summarizer model "
            "rewrite each consolidated failure into a transferable lesson "
            "(instead of the deterministic template). Inputs+output are "
            "shield-scanned and the spend is budgeted; fails open to the "
            "deterministic text. Costs a few tokens per dream cycle.",
            default=False,
        ),
        "dreaming": _q_confirm(
            "Dreaming (offline consolidation)? `maverick dream` replays recent "
            "runs while idle, distills recurring wins into skills per department, "
            "turns repeated failures into recalled insights (promoting patterns "
            "shared across departments), retires skills whose track record "
            "decayed, and prunes stale lessons. Deterministic by default "
            "(opt-in LLM enrichment + rehearsal runs are separate and budgeted).",
            default=True,
        ),
        "verify_ensemble": _q_confirm(
            "Ensemble verification? Cross-check final answers with a panel of models "
            "(slower, stronger).",
            default=False,
        ),
        "risk_proportional_verify": _q_confirm(
            "Risk-proportional verification? Skip the verifier on trivial, low-risk "
            "answers (short, prose-only, no tools or code) to save tokens and latency.",
            default=False,
        ),
        "autonomy_gate": _q_confirm(
            "Autonomy gate? When sub-agents disagree, cross-check the answer with a "
            "model panel AND hold irreversible (high-risk) actions until the "
            "disagreement is resolved or a human approves.",
            default=False,
        ),
        "confirm_plan": _q_confirm(
            "Show the plan before acting? Before a task's first action that could reach "
            "outside Lightwork, show its plan in Approvals and wait for a person.",
            default=False,
        ),
        "headless_assume": _q_confirm(
            "Autonomous (headless) mode? When no human is available to answer, the "
            "agent states a reasonable assumption and continues instead of stalling "
            "on a clarifying question. Best for batch / unattended runs.",
            default=False,
        ),
        "governed_actions": _q_confirm(
            "Governed actions? Record a tamper-evident lineage of every consequential "
            "agent action (writes, shell) so a run's actions are auditable end-to-end.",
            default=False,
        ),
        "workforce_levels": _q_confirm(
            "Per-agent autonomy levels? Treat each agent like a hire with a level of "
            "authority you set -- observe / suggest / request-approval / autonomous, "
            "per action risk -- starting supervised (onboarding) and graduating on a "
            "clean record. Off by default, every agent stages actions for human "
            "execution. Per-agent overrides go under [workforce.agents].",
            default=False,
        ),
        "workforce_data_grounding": _q_confirm(
            "Primary-source data grounding? Give each analyst pack its suite's "
            "public/government data connectors (SEC EDGAR, FRED, openFDA, "
            "USAspending, weather, ...) so it grounds work in primary sources. "
            "GET-only, low-risk, deferred (no context cost), and inert without "
            "each source's API key. On by default; turn off to withhold them.",
            default=True,
        ),
        "calibration_enforce": _q_confirm(
            "Calibration interlock? Freeze self-improvement (trajectory donation) "
            "if the verifier stops telling correct answers from incorrect ones on "
            "your labeled set, so the system never learns from a drifted evaluator.",
            default=False,
        ),
        "donate_trajectories": _q_confirm(
            "Donate run trajectories for training? Write scrubbed records of your "
            "runs to ~/.maverick/outbox/ so you can train the self-learning loop "
            "(PRM + DPO) on your OWN data -- nothing is uploaded, the records stay "
            "on this machine until you choose to ingest/train. Metadata-only by "
            "default; raw text stays local unless you also set [telemetry] "
            "donate_text. Off by default. See docs/self-learning-runbook.md.",
            default=False,
        ),
        "adaptive_compute": _q_confirm(
            "Adaptive test-time compute? Concentrate effort on uncertain sub-tasks "
            "and spend less when the swarm agrees (cheaper, focused).",
            default=False,
        ),
        "best_of_n": _q_confirm(
            "Best-of-N answers? Sample a few candidate answers and keep the one the "
            "verifier scores highest (stronger, more tokens).",
            default=False,
        ),
        "structured_verifier_off": _q_confirm(
            "Turn OFF the structured rubric verifier? It's ON by default: the "
            "verifier scores each FINAL on a rubric (correctness/completeness/"
            "grounding/safety) and a failing safety facet vetoes even a high score, "
            "with the rubric recorded for the learning audit (maverick.reasoning_reward). "
            "Costs ~more tokens per verify; say yes to fall back to the scalar verifier.",
            default=False,
        ),
        "jit_rl_off": _q_confirm(
            "Turn OFF JitRL test-time adaptation? It's ON by default but a no-op until "
            "experience accumulates: it records verifier-guided best-of-N outcomes and "
            "steers candidate selection toward what has verified well (maverick.jit_rl, "
            "no weight updates). Say yes to disable it entirely.",
            default=False,
        ),
        "audit_rewards": _q_confirm(
            "Sign verification rewards into the audit chain? Provable learning: write a "
            "tamper-evident, signed row for every structured reward the system learns "
            "from -- the per-dimension rubric, the score, and where a facet vetoed "
            "(maverick.reasoning_reward). On by default (adds audit volume); recommended "
            "for regulated deployments.",
            default=False,
        ),
        "reward_laundering": _q_confirm(
            "Enforce reward-laundering resistance? Beyond freezing on verifier DRIFT, "
            "also freeze learning when the judge stays sharp on normal traffic but its "
            "edge on adversarial probes collapses -- i.e. it's being GAMED "
            "(maverick.calibration). Off by default; enables the calibration interlock "
            "and needs adversarial probes recorded to bite.",
            default=False,
        ),
        "signed_approval": _q_confirm(
            "Require cryptographic approval for code/weights self-changes? Replace the "
            "self-settable approval boolean with an Ed25519 signature over the exact "
            "change, verified against operator-held keys, so a self-modifying agent "
            "cannot approve itself (maverick.approval_signing). Off by default; you "
            "provide approver public keys (fails closed until you do).",
            default=False,
        ),
        "self_modify": _q_confirm(
            "Enable RESEARCH-ONLY code evolution? The workforce may propose diffs to a "
            "narrow editable allowlist, evaluate them in isolated no-egress containers, "
            "and archive development telemetry (maverick.self_modify). It NEVER adopts "
            "code: production adoption remains disabled until an external one-shot "
            "evaluator and PREPARE/CAS/COMMIT integration exist. Off by default and inert "
            "until editable_paths plus at least two discriminating eval_tests are set.",
            default=False,
        ),
        "adapter_rung": _q_confirm(
            "Enable GOVERNED in-tenant weights adaptation? Train LoRA adapters for a "
            "LOCAL open-weights base model on your own corrections and traces -- frontier-"
            "model output is refused by default (distillation guard) -- and promote them "
            "through the weights rung: held-out evidence, no new authority, Ed25519 human "
            "signature, one-step rollback (maverick.adapter_rung). Nothing leaves the "
            "tenant. Off by default AND inert until you set base_model; needs Ollama (or "
            "compatible) serving and the [training] extra for real tuning.",
            default=False,
        ),
        "skill_synthesis": _q_confirm(
            "Test-time skill synthesis? Write a short task-specific cheat-sheet for "
            "each goal before working on it.",
            default=True,
        ),
        "experience_guidance": _q_confirm(
            "Experience-guided orchestration? Steer planning with how similar past "
            "goals turned out (what worked, what failed).",
            default=True,
        ),
        "credit_assignment": _q_confirm(
            "Counterfactual credit assignment? After a swarm answers, work out which "
            "sub-agent actually helped (ablate + re-verify) to improve learning and "
            "routing. Costs extra verifier calls per swarm.",
            default=True,
        ),
        "causal_promotion": _q_confirm(
            "Counterfactual promotion? When governed self-improvement is on, promote a "
            "learned change (tool/prompt/policy) only if its confounder-adjusted CAUSAL "
            "effect on outcomes clears the bar -- not just a correlation that co-occurred "
            "with success. Each promotion records the effect, its confidence interval, and "
            "what it adjusted for. Requires self-improvement enabled.",
            default=True,
        ),
        "factory_learning": _q_confirm(
            "Self-improving agent factory? Mine recurring pack-generation gaps (a tool a "
            "draft kept omitting, a skill its workflow kept needing) into proposer "
            "corrections and promote them through the self-improvement gate, so future "
            "packs are drafted better. Guidance text only -- never widens an envelope. "
            "Requires self-improvement enabled.",
            default=True,
        ),
        "evaluator_evolution": _q_confirm(
            "Evaluator co-evolution? When the learned judge stops discriminating, don't "
            "just FREEZE learning -- promote a better judge: a challenger evaluator "
            "replaces the incumbent only when its agreement with a fixed, checksum-locked "
            "ground-truth ANCHOR beats it (on the dedicated 'evaluator' rung). The anchor "
            "is immutable so a weak judge can't launder drift. Requires self-improvement "
            "enabled; an evaluator swap needs human approval until you raise max_auto_rung "
            "to 'evaluator'.",
            default=True,
        ),
        "rehearsal": _q_confirm(
            "Pre-execution rehearsal? Before a risky plan runs, simulate it against the "
            "learned world-model of your environment and gate on the prediction: proceed "
            "when the model is confident it's safe, BLOCK a confidently-poor outcome, and "
            "ESCALATE to a human when the model is unsure or has never seen the move. "
            "Governance that lets agents be bolder where it's earned; on by default.",
            default=True,
        ),
        "speculative": _q_confirm(
            "Speculative execution? On turns where the world-model is highly confident "
            "what comes next (a well-trodden, near-deterministic step), draft with a cheap "
            "model instead of the frontier one -- reserving the expensive model for novel "
            "or uncertain turns. Cuts cost/latency on repetitive workflows; off by default "
            "and a no-op until you set a draft model.",
            default=False,
        ),
        "data_engine": _q_confirm(
            "Cognitive Data Engine? The Tesla-style improvement flywheel: production "
            "failures are triaged by CAUSAL impact on real outcomes (fix what moves "
            "reality most, not what's merely frequent), then mined, validated in the "
            "world-model, and promoted through the safety ladder. The workforce compounds "
            "from its own experience; on by default.",
            default=True,
        ),
        "operations_scientist": _q_confirm(
            "Operations Scientist? An agent that DISCOVERS a better process and proves it: "
            "it pairs a harmful action with the beneficial habit that should replace it, "
            "validates the swap in the world-model, then runs a real causal experiment and "
            "ships the proven win. Discovery, not just labour; on by default.",
            default=True,
        ),
        "consequence": _q_confirm(
            "Consequence Engine? Ground the workforce's learning in REAL outcomes instead "
            "of a model's self-graded proxy: when a downstream result lands (an invoice "
            "paid, a ticket reopened), it overrides the proxy reward so the data engine "
            "learns from reality. Reality is the reward signal; on by default.",
            default=True,
        ),
        "earned_autonomy": _q_confirm(
            "Earned autonomy? Agents earn the right to act, action type by action type, "
            "by proving they predict consequences correctly: each rehearsed high-stakes "
            "action pins a consequence card, reality grades it, and a proven streak "
            "graduates the action from 'a human approves' to 'policy auto-approves' -- "
            "with instant demotion on one miss and a guaranteed undo until it's earned. "
            "Enabling only records evidence; graduation stays off until you also arm "
            "auto_graduate. Off by default.",
            default=False,
        ),
    }


def _pick_workflow_and_extension_toggles() -> dict[str, Any]:
    """Flows, connections, the plugin workbench and the emergent protocol/codec."""
    return {
        "flows": _q_confirm(
            "Flow engine? A deterministic skeleton -- branch, switch, loop, parallel, "
            "approval, delay, wait-for-event, try/catch -- over steps that are either a "
            "fixed tool call or a full agentic goal. Migrated workflows keep their "
            "structure and auditability, while any node can still be an agent; each "
            "node's outcome trains which steps should be deterministic vs. agentic. "
            "Off by default.",
            default=False,
        ),
        "connections": _q_confirm(
            "Named connections? Store a connector's base URL + API token under a name, "
            "sealed at rest, so a connector can be wired from the dashboard without "
            "setting <NAME>_TOKEN env vars (an existing env var still wins). Off by "
            "default.",
            default=False,
        ),
        "plugin_workbench": _q_confirm(
            "Enable the governed plugin qualification workbench? Sandbox checks require a reviewed local Linux image configured later in Settings; no image is downloaded. Ongoing tasks retain pins to plugin bytes already used.", default=False),
        "workflow_versioning": _q_confirm(
            "Keep workflow version history, safe input fixtures and administrator-reviewed publication before new schedules?", default=True),
        "workflow_typed_inputs": _q_confirm(
            "Allow workflow authors to add dates, choices, optional inputs, defaults and own connected-account selections? Account selections are checked again before execution.", default=True),
        "connections_self_connect": _q_confirm(
            "Allow employees to connect their own read-only Google Drive account after an administrator registers the workspace provider app? Other profiles require explicit approval in Settings.", default=False),
        "extension_form_values": _q_confirm(
            "Allow people to review and share browser form values with the configured AI service? Values remain off by default for every page.", default=False),
        "extension_page_structure": _q_confirm(
            "Allow people to review and share browser page headings and controls with the configured AI service?", default=True),
        "emergent_protocol": _q_confirm(
            "Emergent coordination shorthand? Swarms evolve short codes for the boilerplate "
            "they repeat (cheaper coordination), while every code decodes EXACTLY back to "
            "English -- the auditable translation layer, so nothing is ever hidden from the "
            "Shield or a human. Off by default; a no-op until a codebook is learned.",
            default=False,
        ),
        "emergent_codec": _q_confirm(
            "Measure the token-aware codec on live coordination? The codec that saves "
            "actual frontier TOKENS (not just bytes), via byte-stuffed cheap codes. When "
            "on, the blackboard measures -- never changes -- what it would compress real "
            "traffic to, so you can confirm the savings before agents ever read codes. "
            "Off by default; pure telemetry, the audit/Shield path is untouched.",
            default=False,
        ),
    }


def _monthly_limit(raw: Any, *, label: str = "") -> float:
    prefix = f"{label}: " if label else ""
    text = str(raw).strip().removeprefix("$").strip()
    if not re.fullmatch(r"(?:[0-9]+|[0-9]{1,3}(?:,[0-9]{3})+)(?:\.[0-9]{1,2})?", text):
        raise ValueError(prefix + "Enter a nonnegative dollar amount, such as $500 or 1,000.00.")
    value = float(text.replace(",", ""))
    if not math.isfinite(value) or value > 1_000_000_000:
        raise ValueError(prefix + "Enter a dollar amount no greater than 1,000,000,000.")
    return value


def _pick_monthly_limit(prompt: str, *, default: str = "0") -> float:
    while True:
        try:
            return _monthly_limit(_q_text(prompt, default=default))
        except ValueError as exc:
            console.print(str(exc), style="yellow")


def _pick_client_id() -> str:
    while True:
        value = _q_text(
            "Client/tenant id for THIS deployment (one Lightwork per enterprise client). "
            "All data is isolated under this id; leave blank only for a personal/single-user install. "
            "Use 1–64 lowercase letters/digits/._-, starting with a letter or digit (e.g. acme-corp).",
            default="",
        ).strip()
        if not value or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", value):
            return value
        console.print("[yellow]Enter a valid lowercase client/tenant id.[/yellow]")


def _pick_enterprise_toggles() -> dict[str, Any]:
    """Capabilities, quotas, spending, tenancy, enterprise, agent trust and the control plane."""
    return {
        "enforce_capabilities": _q_confirm(
            "Enforce agent capabilities? Each agent runs under a scoped grant and "
            "spawned sub-agents can only narrow it, never exceed it (least privilege).",
            default=False,
        ),
        "per_call_token_exchange": _q_confirm(
            "Per-call token exchange? Each tool call trades the run-long grant for "
            "a freshly minted, single-tool, short-lived signed token (zero-trust; "
            "shrinks the blast radius of a mid-run compromise). Needs capability "
            "enforcement.",
            default=False,
        ),
        "enforce_quotas": _q_confirm(
            "Enforce per-principal usage quotas? Track spend (dollars + tokens) per "
            "user per day and refuse to start a new goal once the daily cap is hit "
            "(chargeback / cost governance across runs, beyond the per-run budget).",
            default=False,
        ),
        "spending_workspace_monthly": _pick_monthly_limit(
            "Monthly spending limit for the whole workspace, in dollars "
            "(0 = no limit; you can change it any time in Admin > Spending limits)",
            default="0",
        ),
        "spending_person_monthly": _pick_monthly_limit(
            "Monthly spending limit for each person, in dollars "
            "(0 = no limit; you can set different limits per person in the dashboard)",
            default="0",
        ),
        "spending_alert_at": _q_text(
            "Alert administrators (and each person, for their own limit) when spending "
            "reaches these percentages of a spending limit; comma-separated, or none "
            "for no alerts. The limits still stop paid work at 100%.",
            default="50, 75, 100",
        ),
        "typical_cost_min_runs": _q_text(
            "Show what an agent's or specialist's past tasks usually cost beside the task "
            "form once it has finished this many tasks (2 to 1000). It is recorded history, "
            "never a prediction.",
            default="10",
        ),
        "tenant_by_user": _q_confirm(
            "Isolate each user into their own tenant? Per-user cross-session memory "
            "is kept separate — recommended for multi-user servers.",
            default=False,
        ),
        "client_id": _pick_client_id(),
        "enterprise": _q_confirm(
            "Enterprise mode (private/sensitive data)? Pin every LLM call to a "
            "local/self-hosted model so data never leaves your boundary, gate "
            "destructive actions, and enforce per-agent capabilities. Recommended "
            "when the agent handles PHI/PII/financial data.",
            default=False,
        ),
        "agent_trust": _q_confirm(
            "Govern which OUTSIDE agents your agents may talk to? Engages the Agent "
            "Trust Plane: external agents (federation peers, A2A callers, fleet "
            "agents) are default-DENIED unless listed in [agent_trust] agents with a "
            "pinned key, direction, and tool/budget/data ceiling. Auto-on under "
            "enterprise mode; recommended at the company boundary.",
            default=False,
        ),
        "control_plane": _q_confirm(
            "Turn on the Agent Control Plane? One console (dashboard page + "
            "`maverick control-plane`) over the running/revoked native principals "
            "and enrolled external agents this deployment can resolve: suspend / "
            "resume / contain / attenuate a principal, or operate HALT. Principal "
            "verbs land in enforcement the runtime already consults and attempt a "
            "control-plane audit row. Ordinary audit outages are marked in the "
            "result; a configured audit refusal propagates after any already-landed "
            "change. CLI HALT covers this local deployment; dashboard HALT reaches "
            "other replicas only with a configured shared authority. Reads remain "
            "available while the verbs are off and fail closed when a required "
            "authority is unreadable. Recommended wherever more than one person "
            "operates agents.",
            default=False,
        ),
    }


def _pick_data_protection_toggles() -> dict[str, Any]:
    """Logs, at-rest encryption, RLS, Copilot operations, audit sinks, SAML and approvals."""
    return {
        "anonymous_logs": _q_confirm(
            "Anonymous mode? Scrub user-identifying content (goal text, user/channel "
            "ids, home paths, emails/phones) from logs and audit events — hashes or "
            "sentinels instead of raw values. Good for shared/regulated environments.",
            default=False,
        ),
        "encrypt_at_rest": _q_confirm(
            "Encrypt sensitive local stores at rest? Seals the cross-session "
            "memory store with AES-256-GCM (key in ~/.maverick/keys, chmod 600). "
            "Implied by enterprise mode; recommended for PHI/PII/financial data.",
            default=False,
        ),
        "encrypt_per_tenant": _q_confirm(
            "Per-tenant encryption keys? Each tenant gets its own data key "
            "(wrapped by a KMS KEK) so one tenant's key never opens another's "
            "data — the posture a hosted multi-tenant store needs. Requires "
            "at-rest encryption; reads of existing data stay transparent. "
            "Off by default (single-tenant boxes don't need it).",
            default=False,
        ),
        "pg_rls": _q_confirm(
            "Database-enforced tenant isolation (Postgres Row-Level Security)? "
            "Only for the shared Postgres backend with MULTIPLE tenants: the DB "
            "itself rejects cross-tenant rows as defense-in-depth over the "
            "app-layer scoping. REQUIRES one-time prep first — assign legacy rows "
            "with `maverick tenant backfill --tenant <id>` and verify with "
            "`maverick tenant rls-preflight`, or pre-tenancy rows become invisible. "
            "Off by default; leave off for SQLite or single-tenant installs.",
            default=False,
        ),
        "copilot_operation_families": [
            "commitments" if value == "Promise reviews" else value
            for value in _q_checkbox(
                "Which action families may Copilot open when enabled? Native permissions still apply.",
                ["learning", "preferences", "tasks", "clarifications", "reviews", "schedules",
                 "connections", "artifacts", "notifications", "models", "budget", "plugins",
                 "Promise reviews"], default=["learning"],
            )
        ],
        "allow_copilot_operations": _q_confirm(
            "Let Copilot open controls that change things in your selected action families? "
            "Each change requires a fresh review and explicit confirmation. When this is off, "
            "Copilot still opens pages, focuses controls and shows status, but changes nothing.",
            default=False,
        ),
        "governed_pg_pool": _q_confirm(
            "Reuse one bounded Postgres connection for governed records? "
            "Only affects a configured Postgres governed-record backend. "
            "Each operation still validates tenant, schema and key authority; "
            "waiting is capped at five seconds. Start with one connection and "
            "measure your workload before increasing pool_size. Off by default.",
            default=False,
        ),
        "audit_sign": _q_confirm(
            "Sign the audit log for tamper-evidence? Ed25519 hash-chains every "
            "audit row (plus a signed cross-file ledger) so `maverick audit verify` "
            "can prove the log was not altered — the basis for SOC 2 evidence. "
            "Needs the [audit-signing] extra; falls back to unsigned if absent.",
            default=False,
        ),
        "audit_worm": _q_confirm(
            "Export closed audit day-files to a write-once (WORM) store? Beyond "
            "tamper-EVIDENCE, this makes the historical log un-alterable: each "
            "closed day-file is shipped with a retention lock so it can't be "
            "rewritten or deleted (S3 Object-Lock for regulator-grade WORM, or a "
            "local read-only mirror). Run `maverick audit worm push` (e.g. nightly "
            "cron). Defaults to a local mirror; edit [audit.worm] for S3.",
            default=False,
        ),
        "unified_audit": _q_confirm(
            "Project all six governance suites into one tenant-bound signed audit "
            "view? Each source stays authoritative while a bounded, digest-only "
            "projection exposes explicit coverage, lag, retry, revocation and "
            "integrity status. The managed runtime also stages independently "
            "verifiable checkpoints; WORM remains separately opt-in. This enables "
            "audit signing. OFF by default.",
            default=False,
        ),
        "saml": _q_confirm(
            "Prepare company single sign-on (SAML)? For enterprises "
            "whose IdP (Okta, Entra/Azure AD, ADFS) mandates SAML over OIDC. "
            "Keeps it inactive so current access stays available. After installation, "
            "use Settings > All settings > Single sign-on to upload provider files, "
            "try a real sign-in and review activation. Included in the standard "
            "release runtime; off by default.",
            default=False,
        ),
        "security_autofix": _q_confirm(
            "Let the security assessor auto-fix low-risk gaps? With enterprise mode "
            "on, `maverick remediate --apply` may auto-apply reversible, in-boundary "
            "config fixes (enable audit signing, set retention); anything "
            "behaviour-changing stays gated for a human. Off by default; every fix "
            "is audited and reversible.",
            default=False,
        ),
        "dual_approval": _q_confirm(
            "Require two-person approval for risky actions (N-of-M dual control)? "
            "A high/critical-risk action then needs 2 DISTINCT approvers in the "
            "dashboard queue, and the requester can't approve their own request — "
            "the segregation-of-duties control SOX / SOC 2 / HIPAA auditors test. "
            "Writes [security] approvals_required = 2. Off by default.",
            default=False,
        ),
    }


def _pick_runtime_toggles() -> dict[str, Any]:
    """Tool exposure, shield updates, eBPF, local runtime, caches, effort and hedging."""
    return {
        "shield_updates": _q_confirm(
            "Pull signed shield-rule updates? Fetches a publisher-signed rules "
            "bundle ([shield] update_url + update_pubkey; Ed25519-verified, "
            "downgrades refused) and stages it for the shield. Off by default.",
            default=False,
        ),
        "ebpf_monitor": _q_confirm(
            "Enable the eBPF syscall monitor? An operator-run bpftrace "
            "supervisor tracing execve/connect/openat for the agent's PID tree "
            "(needs root + bpftrace at runtime). Off by default.",
            default=False,
        ),
        "local_runtime": _q_confirm(
            "Manage a local model server (vLLM / TGI / llama.cpp)? Writes "
            "[local_runtime] so `maverick local-runtime plan` composes the "
            "right batching / KV-cache / precision flags for your engine; "
            "an administrator must prepare the engine and model separately. "
            "Off by default.",
            default=False,
        ),
        "output_cache": _q_confirm(
            "Cache tool outputs? Memoize side-effect-free (read-only) tool calls "
            "within a run so a repeated read isn't re-done. Off by default.",
            default=False,
        ),
        "hardware_sensors": _q_confirm(
            "Enable host hardware sensors? Lets agents read this machine's "
            "temperatures, fans, and battery via the [sensors] extra. Off by "
            "default because it exposes host telemetry to tool calls.",
            default=False,
        ),
        "local_first": _q_confirm(
            "Local-first models? When a configured local model's server is "
            "reachable, prefer it over a remote provider (privacy + cost). Only "
            "applies when you haven't pinned a model. Off by default.",
            default=False,
        ),
        "energy_aware": _q_confirm(
            "Energy-aware routing? On a laptop, downgrade to a cheaper/faster "
            "model when the battery is low. Off by default.",
            default=False,
        ),
        "effort": _q_confirm(
            "Per-role reasoning effort? Keep the orchestrator/coder at high effort "
            "but run bulk roles (researcher/verifier/writer) at lower effort — the "
            "biggest cost/latency lever on Opus 4.7/4.8. Off by default.",
            default=False,
        ),
        "cache_prewarm": _q_confirm(
            "Pre-warm the prompt cache at start? A max_tokens=0 prefill writes the "
            "system+tools cache so the first turn doesn't pay the cold-write "
            "latency (best for interactive use). Off by default.",
            default=False,
        ),
        "hedge_requests": _q_confirm(
            "Hedge slow LLM requests? If a call hasn't returned within ~1.5s, fire "
            "a backup request and take whichever finishes first (tightens p99 on a "
            "provider with variable latency). Costs extra on slow calls. Off by "
            "default.",
            default=False,
        ),
    }


def _ask_insight_exchange(advanced: dict[str, Any]) -> None:
    """Trusted peer keys for federated insight exchange (needs dreaming)."""
    # Federated insight exchange rides on dreaming: trusted peer keys are
    # only worth asking for when the loop that produces/consumes insights is
    # on. Imports are fail-closed without them.
    if advanced.get("dreaming") and _q_confirm(
        "  Exchange consolidated insights with trusted peer instances? "
        "(signed bundles via `maverick insights-export/-import`)",
        default=False,
    ):
        raw = _q_text(
            "  Trusted peer insight pubkeys (comma-separated hex Ed25519)",
            default="",
        )
        advanced["insight_pubkeys"] = [k.strip() for k in raw.split(",") if k.strip()]


def _ask_flow_followups(advanced: dict[str, Any]) -> None:
    """Self-correction, learned operators, action recipes and the approval-link URL (needs flows)."""
    # Autonomous self-correction only makes sense once flows are on. Human apply
    # + surfaced proposals work without it; this governs whether the loop may
    # UNDO a change on its own.
    if advanced.get("flows") and _q_confirm(
        "  Let flows self-correct? A scheduled pass reverts a node rewrite whose "
        "grounded outcomes measurably regressed -- the loop undoes its own bad "
        "changes. Off by default.",
        default=False,
    ):
        advanced["flows_auto_evolve"] = True
    # Signed channel Approve/Reject links need the dashboard's externally-
    # reachable base URL; blank keeps approvals on the dashboard itself.
    if advanced.get("flows"):
        advanced["flows_learned_operators"] = _q_confirm(
            "  Enable bounded learned pure operators from reviewed examples? "
            "Agreement within declared bounds only; otherwise use the original agent.",
            default=False,
        )
        advanced["flows_learned_operator_questions"] = _q_confirm(
            "  Enable stored learned-operator review questions? "
            "Reviewed answers create drafts without automatic publication.",
            default=False,
        )
        advanced["flows_composed_operators"] = _q_confirm(
            "  Enable bounded composed pure operators? "
            "Also requires learned operators; otherwise use the original agent.",
            default=False,
        )
        advanced["flows_action_recipes"] = _q_confirm(
            "  Enable learning action sequences from reviewed examples? "
            "Generated flows retain approval gates and stop on ambiguous data bindings.",
            default=False,
        )
        advanced["flows_action_recipe_transforms"] = _q_confirm(
            "  Enable learned transformations in action arguments? "
            "Also requires action recipes and explicit data bounds; every retained expression must agree. "
            "Approvals remain required and uncertainty stops further actions.",
            default=False,
        )
        advanced["flows_action_recipe_choices"] = _q_confirm(
            "  Enable learned binary action choices after one shared action? "
            "Also requires action recipes and transformed arguments. Every retained guard must agree; "
            "the chosen terminal action needs approval, and uncertainty never repeats the shared action.",
            default=False,
        )
        advanced["flows_action_recipe_teaching"] = _q_confirm(
            "  Enable human teaching at a real completed action prefix? "
            "Requires action recipes, transformed arguments, choices and governed lineage. "
            "Both continuation arguments must agree; human choice and a separate action approval remain required. "
            "Teaching never repeats the shared action.",
            default=False,
        )
        advanced["flows_action_episode_capture"] = _q_confirm(
            "  Enable retaining workflow examples for learning? "
            "Each run needs enrollment, encrypted storage, an expiry and a separate human review. "
            "Older unsigned learned flows may stop until rebuilt from permitted signed examples.",
            default=False,
        )
        advanced["flows_action_workflow_learning"] = _q_confirm(
            "  Enable bounded workflow learning from signed reviewed executions? "
            "Requires action recipes, transformed arguments and governed lineage. "
            "Learns next actions and completion from observed history, up to eight actions; "
            "approvals remain required and ambiguity stops further work. "
            "Signed execution receipts are mandatory; execution refuses if signing or persistence is unavailable. "
            "This choice does not enable audit signing or other dependencies.",
            default=False,
        )
        advanced["flows_action_workflow_memory_learning"] = _q_confirm(
            "  Enable bounded integer history accumulator learning? "
            "Requires workflow learning, action recipes, transformed arguments and governed lineage. "
            "One fixed update program runs across each history; all consistent models must agree. "
            "Native approvals remain in force and ambiguity or resource exhaustion stops further work. "
            "Signed execution receipts are mandatory; execution refuses if signing or persistence is unavailable. "
            "This choice does not enable audit signing or other dependencies.",
            default=False,
        )
        advanced.update({"flows_" + key: value for key, value in _pick_action_recipe_lineage().items()})
        flows_url = _pick_approval_url(
            "  Public base URL for flow approval links (e.g. https://ops.acme.com; "
            "blank = approve from the dashboard)",
        )
        if flows_url:
            advanced["flows_public_url"] = flows_url


def _ask_self_harness_followups(advanced: dict[str, Any]) -> None:
    """The optional self-harness paths (needs self-harness)."""
    # Self-harness has a handful of optional paths beyond the validation floors
    # written by default. Only worth asking once the loop itself is on; each
    # stays at its historical default unless the operator opts in here.
    if advanced.get("self_harness") and _q_confirm(
        "  Tune self-harness advanced paths? (eval corpus, per-department "
        "scoping, semantic mining, best-of-N, efficacy review, auto-retire)",
        default=False,
    ):
        corpus = _q_text(
            "  Eval-corpus path for the live A/B (lets a scheduled pass actually "
            "promote; blank = dry pass)",
            default="",
        ).strip()
        if corpus:
            advanced["self_harness_eval_corpus"] = corpus
            # A live A/B spends real provider dollars unattended, so cap it by
            # default; 0 retains the risk-limited $5 ceiling.
            advanced["self_harness_eval_budget"] = max(
                0.0,
                _safe_float(
                    _q_text(
                        "    Spend cap per auto-evaluated cycle, in dollars (0 = the risk-limited $5 ceiling)",
                        default="5",
                    ),
                    default=5.0,
                ),
            )
            _ask_self_harness_evaluation_boundary(advanced)
        if _q_confirm("    Mine and scope guidance per department (domain)?", default=False):
            advanced["self_harness_bucket_domain"] = True
        advanced["self_harness_semantic_mining"] = _q_confirm(
            "    Semantic mining? Cluster failures by embedding similarity when "
            "embeddings are available (else deterministic Jaccard).",
            default=False,
        )
        advanced["self_harness_efficacy_review"] = _q_confirm(
            "    Efficacy review? Re-measure each line's live A/B lift every cycle "
            "and demote dead weight (needs the eval corpus above).",
            default=False,
        )
        advanced["self_harness_canary"] = _q_confirm(
            "    Canary rollout? Stage each newly learned line on probation and "
            "graduate or pull it from real run outcomes.",
            default=False,
        )
        advanced["self_harness_auto_run"] = _q_confirm(
            "    Auto-run? Run the governed learning cycle for every role model "
            "as part of `maverick dream` (no second cron entry).",
            default=True,
        )
        advanced["self_harness_metamorphic"] = _q_confirm(
            "    Metamorphic validation? Paraphrase held-out cases and require a "
            "candidate's lift to survive the rewording (needs the live A/B).",
            default=False,
        )
        advanced["self_harness_relapse"] = _q_confirm(
            "    Relapse watch? Put a learned line back on probation when half "
            "or more of its recent run outcomes are failures.",
            default=False,
        )
        advanced["self_harness_calibrate_judge"] = _q_confirm(
            "    Judge calibration? Feed the evaluation judge's verdicts into "
            "the verifier-drift freeze so a drifting judge pauses learning.",
            default=False,
        )
        advanced["self_harness_transfer_auto"] = _q_confirm(
            "    Nightly cross-model transfer? Try each model's proven guidance "
            "on the rest of the fleet (gated, on probation, one-shot per pair).",
            default=False,
        )
        harvest_mode = _q_select(
            "    Corpus bootstrapping from run history?",
            [
                "off     - don't harvest",
                "propose - stage mined cases for your review",
                "auto    - merge mined cases straight into the corpus",
            ],
            default="off     - don't harvest",
        ).split()[0]
        if harvest_mode in ("propose", "auto"):
            advanced["self_harness_corpus_harvest"] = harvest_mode
        # Both nightly paths ride the dream beat: without auto_run (or, for
        # harvesting, a corpus) they are configured but never executed --
        # say so NOW, not silently at 3am.
        if not advanced.get("self_harness_auto_run") and (
            advanced.get("self_harness_transfer_auto") or harvest_mode in ("propose", "auto")
        ):
            console.print(
                "    [yellow]Note: nightly transfer/harvesting only run when "
                "auto-run is on -- enable it above (or run them manually via "
                "`maverick self-harness transfer` / `corpus harvest`).[/yellow]"
            )
        if harvest_mode in ("propose", "auto") and not corpus:
            console.print(
                "    [yellow]Note: corpus bootstrapping needs the eval-corpus "
                "path above; without one the harvest is a no-op.[/yellow]"
            )
        store_pick = _q_select(
            "    Learning-store backend?",
            [
                "files - per-host JSON under ~/.maverick (default)",
                "world - shared world database (a multi-host fleet learns as one)",
            ],
            default="files - per-host JSON under ~/.maverick (default)",
        ).split()[0]
        if store_pick == "world":
            advanced["self_harness_store"] = "world"
        advanced["self_harness_candidates"] = max(
            1,
            _safe_int(
                _q_text("    Candidate lines per weakness (best-of-N; 1 = single)", default="1"),
                default=1,
            ),
        )
        advanced["self_harness_retire_days"] = max(
            0,
            _safe_int(
                _q_text("    Auto-retire lines unused this many days (0 = never)", default="0"),
                default=0,
            ),
        )


def _ask_chat_and_resource_followups(advanced: dict[str, Any]) -> None:
    """Chat answer streaming/verification, SQL and REST ceilings, IFC, codebase and swarm scale."""
    # Chat answers (maverick.agent): a live, redacted, Shield-scanned preview,
    # and whether plain prose replies also wait on the self-verifier.
    advanced["stream_answers"] = _q_confirm(
        "  Stream chat answers as they are written (redacted and Shield-scanned)?",
        default=True,
    )
    advanced["verify_chat_answers"] = _q_confirm(
        "  Also self-verify plain chat replies (one extra model call each)?",
        default=False,
    )
    # Resource ceilings for the SQL tools and read-only REST connector retries.
    advanced["query_timeout_seconds"] = min(300, max(1, _safe_int(
        _q_text("  SQL tool query timeout in seconds (1-300)", default="30"), default=30)))
    advanced["connector_max_attempts"] = min(5, max(1, _safe_int(
        _q_text("  REST connector read attempts (1-5)", default="3"), default=3)))
    _pick_ifc(advanced)
    _pick_codebase(advanced)
    _pick_swarm_scale(advanced)


def _ask_regulated_deployment(advanced: dict[str, Any]) -> None:
    """Signed tax-constants channel, data residency, disclosure and regulatory profiles."""
    # Tax-constants content channel: law changes ship as SIGNED bundles
    # (fail-closed against the publisher keys), auto-applied by
    # `maverick tax prepare` / `maverick tax update`.
    if _q_confirm(
        "  Auto-update tax computation constants from a signed publisher "
        "channel? (new tax law as a content release, not a code release)",
        default=False,
    ):
        advanced["tax_update_url"] = _q_text("  Constants update URL", default="").strip()
        raw = _q_text(
            "  Trusted publisher pubkeys (comma-separated hex Ed25519)",
            default="",
        )
        advanced["tax_pubkeys"] = [k.strip() for k in raw.split(",") if k.strip()]
    # Regulated-deployment posture: data-residency region + a compliance
    # disclosure line. These map to the independent [residency]/[compliance]
    # scalar tables a regulated deployment needs.
    # (Action-level [governance] guards stay config-only: they share the
    # [governance] table the finance step already owns.)
    if _q_confirm(
        "  Set regulated-deployment knobs (data residency, compliance disclosure)?",
        default=False,
    ):
        region = _q_text(
            "  Data-residency region (e.g. us / eu / us-east-1; blank = none)", default=""
        ).strip()
        if region:
            advanced["residency_region"] = region
        disclosure = _q_text(
            "  Compliance disclosure line shown to users (blank = none)", default=""
        ).strip()
        if disclosure:
            advanced["compliance_disclosure_text"] = disclosure
    # Regulatory enforcement is independent of the optional residency and
    # disclosure fields above. Always expose it so answering "no" to that
    # unrelated bundle cannot make the controls undiscoverable.
    profiles = _q_checkbox(
        "  Regulatory obligations to compile into the action gate "
        "(strictest-wins)",
        _regulatory_profile_choices(),
        default=[],
    )
    if profiles:
        advanced["compliance_profiles"] = [str(p) for p in profiles]


def _ask_identity_followups(advanced: dict[str, Any]) -> None:
    """OIDC SSO, sign-in security, first-owner setup and department access."""
    # OIDC SSO is a string-bearing toggle (issuer/audience/jwks_uri), so it has
    # its own prompt; the result is nested under the "oidc" key and the writer
    # emits a single [auth.oidc] table for it.
    advanced["oidc"] = pick_oidc()
    advanced["sign_in_security"] = pick_sign_in_security(
        bool(advanced["oidc"].get("enabled")))
    advanced["local_owner_setup"] = _q_confirm(
        "Allow first-owner setup in the app on this computer? "
        "A named owner creates a local passphrase and can invite colleagues. "
        "Unavailable when managed sign-in or existing identity assignments are present.",
        default=not bool(advanced["oidc"].get("enabled")),
    )
    # Department (job-function) scoping only bites once sign-in is on, so it is
    # offered right after — writes under [dashboard]. Returns {} when declined.
    advanced["department_access"] = pick_department_access(bool(advanced["oidc"].get("enabled")))


def _ask_dashboard_followups(advanced: dict[str, Any]) -> None:
    """Compression, glass effects, the sidebar, mobile offline copies and device pairing."""
    # Response compression is on by default ([dashboard] compress); the only
    # reason to turn it off is a reverse proxy that already compresses.
    advanced["dashboard_compress"] = _q_confirm(
        "Compress dashboard responses (gzip)? Say no only if a proxy in front "
        "of Lightwork already compresses.",
        default=True,
    )
    # Glass effects ([dashboard] glass) are off by default: solid panels keep
    # pages fast to respond. People can still turn them on for themselves in
    # Display preferences; this only changes the starting look for everyone.
    advanced["dashboard_glass"] = _q_confirm(
        "Turn on glass effects (see-through, blurred panels) for everyone? "
        "Pages respond more slowly with them, especially on older computers. "
        "People can still choose for themselves in Display preferences.",
        default=False,
    )
    # The sidebar ([dashboard] navigation) stays "classic" by default. "areas"
    # groups every page into nine job-named areas; run the tree test in
    # docs/tree-test before switching it on for everyone.
    # navigation_personal lets each person try it in Your preferences.
    advanced["dashboard_navigation"] = "areas" if _q_confirm(
        "Use the job-named sidebar (areas such as Work, Privacy and Settings) for everyone? "
        "Keep the classic sidebar until a tree test shows people find pages faster.",
        default=False,
    ) else "classic"
    advanced["dashboard_navigation_personal"] = _q_confirm(
        "Let each person switch to the job-named sidebar for themselves in Your preferences?",
        default=False,
    )
    # Settings > Models lists the models each saved key can reach by asking the
    # provider's own model-list endpoint ([models] discovery, default on).
    advanced["mobile_offline"] = {"enabled": _q_confirm(
        "Allow mobile companions to save task copies for up to 24 hours and 2 MB? Shorter limits are available in All settings.", default=True,
    ), "max_age_seconds": 86400, "max_bytes": 2097152}
    advanced["device_pairing"] = _pick_device_pairing()


def _ask_model_followups(advanced: dict[str, Any]) -> None:
    """Model guidance, capability tests and provider model discovery in Settings."""
    advanced["model_guidance"] = _q_confirm(
        "Show dated model pricing evidence and provider-reported capabilities in Settings?",
        default=True,
    )
    advanced["model_capability_tests"] = _q_confirm(
        "Allow administrators to explicitly confirm bounded, potentially paid synthetic model tests (at most USD 0.05 and 64 output tokens, no retry)?", default=False,
    )
    advanced["model_discovery"] = _q_confirm(
        "Let Settings discover the models each provider key can reach (one "
        "bounded model-list request per provider, cached)? Say no to offer "
        "only the shipped catalog.",
        default=True,
    )


def _pick_device_pairing() -> dict[str, Any]:
    """Keep pairing and optional task-control consent in one ordered group."""
    pairing = {"enabled": _q_confirm(
        "Let named members pair personal companions with an expiring code and explicit browser approval? Devices can read only their own work in the chosen workspace.", default=False,
    ), "credential_hours": 24, "allow_actions": False}
    if pairing["enabled"]:
        pairing["allow_actions"] = _q_confirm(
            "Also allow separately opted-in companions to review and submit answers or Stop on their own tasks? Approvals remain on the dashboard.", default=False,
        )
    return pairing


def _regulatory_profile_choices() -> list[str]:
    """The installed compiler's released profile registry, not a local copy."""
    from maverick.regulatory_compiler import shipped_profile_keys

    return list(shipped_profile_keys())


def pick_governed_mcp_sidecar() -> dict[str, Any]:
    """Collect a reviewed, no-secret sidecar manifest for external MCP clients.

    The prompt deliberately asks for environment-variable *names*, never an
    upstream bearer value.  Tool schemas remain conservative ``object`` roots;
    operators can add a more restrictive reviewed JSON Schema later instead of
    the wizard inventing one from a tool name.
    """
    console.print(
        "[dim]A governed MCP sidecar fronts reviewed tools from one upstream "
        "MCP server for external clients. It needs per-agent MCP credentials, "
        "the Agent Trust Plane, and a Shield installation; it does not discover "
        "or proxy arbitrary upstream tools.[/dim]"
    )
    if not _q_confirm(
        "  Configure a governed MCP sidecar for external clients now?",
        default=False,
    ):
        return {}
    upstream = _q_text(
        "  Upstream Streamable HTTP MCP URL (https; loopback http allowed for development)",
        default="",
    ).strip()
    if not _secure_or_loopback_url(upstream):
        console.print(
            "[yellow]No valid sidecar URL supplied; leaving the sidecar disabled."
            "[/yellow]"
        )
        return {}
    raw_tools = _q_text(
        "  Reviewed upstream tools (comma-separated name[:low|medium|high])",
        default="",
    )
    tools: dict[str, dict[str, Any]] = {}
    for entry in _split_csv(raw_tools):
        name, separator, risk = entry.partition(":")
        name = name.strip()
        risk = risk.strip().lower() if separator else "high"
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name) or "__" in name:
            console.print(f"[yellow]Skipping invalid MCP tool name: {name!r}[/yellow]")
            continue
        if risk not in {"low", "medium", "high"}:
            console.print(
                f"[yellow]Skipping {name!r}: risk must be low, medium, or high.[/yellow]"
            )
            continue
        tools.setdefault(
            name,
            {
                "risk": risk,
                "description": "Reviewed governed MCP tool",
                "input_schema": {"type": "object", "properties": {}},
            },
        )
    if not tools:
        console.print(
            "[yellow]No reviewed tool bindings supplied; leaving the sidecar disabled."
            "[/yellow]"
        )
        return {}
    token_env = _q_text(
        "  Upstream bearer environment variable (blank = no static bearer)",
        default="MAVERICK_MCP_SIDECAR_UPSTREAM_TOKEN",
    ).strip()
    if token_env and not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", token_env):
        console.print("[yellow]Invalid environment variable name; no bearer will be configured.[/yellow]")
        token_env = ""
    max_calls = max(
        0,
        _safe_int(
            _q_text("  Per-principal call budget per hour (0 = no count ceiling)", default="1000"),
            default=1000,
        ),
    )
    port = min(
        65_535,
        max(
            1,
            _safe_int(_q_text("  Sidecar listen port", default="8787"), default=8787),
        ),
    )
    out: dict[str, Any] = {
        "enable": True,
        "upstream_url": upstream,
        "require_shield": True,
        "max_calls_per_window": min(max_calls, 1_000_000),
        "budget_window_seconds": 3_600,
        "listen_host": "127.0.0.1",
        "listen_port": port,
        "tools": tools,
    }
    if token_env:
        out["upstream_token_env"] = token_env
    return out


def _split_csv(text: str) -> list[str]:
    return [t.strip() for t in (text or "").split(",") if t.strip()]


def _collect_group_pairs(prompt: str, *, csv_value: bool) -> dict[str, Any]:
    """Collect ``Group Name = value`` lines until a blank entry. ``csv_value``
    parses the right side as a comma-separated list (departments) instead of a
    single token (role)."""
    out: dict[str, Any] = {}
    while True:
        line = _q_text(prompt, default="").strip()
        if not line:
            break
        if "=" not in line:
            console.print("Enter Group Name = value, or leave blank to finish.", style="yellow")
            continue
        name, _, rhs = line.partition("=")
        name, rhs = name.strip(), rhs.strip()
        if not name or not rhs:
            console.print("Enter both a group name and a value separated by =.", style="yellow")
            continue
        if not csv_value:
            try:
                from maverick_dashboard.rbac import is_known_role
            except ImportError:
                console.print("Roles cannot be checked. Install the dashboard before adding a group role.", style="yellow")
                continue
            rhs = rhs.lower()
            if not is_known_role(rhs):
                console.print("That role is not available. Enter a known role, such as viewer.", style="yellow")
                continue
        out[name] = _split_csv(rhs) if csv_value else rhs
    return out


def pick_department_access(sso_enabled: bool) -> dict[str, Any]:
    """Opt-in department (job-function) scoping for authenticated users.

    Only meaningful once sign-in is on (it keys on the authenticated
    principal), so it is skipped entirely when SSO is off. Collects the
    deny-by-default department set and optional SCIM-group -> role / department
    mappings, written under ``[dashboard]``. Returns ``{}`` when declined, so a
    default install is unchanged.
    """
    if not sso_enabled:
        return {}
    console.print(
        "[dim]Department scoping limits which specialist teams each signed-in "
        "user can see and run — a finance analyst gets the Finance department, "
        "not Legal. The recommended first-login baseline is viewer with no departments; you can "
        "always assign per-user access later on the dashboard Users page.[/dim]"
    )
    if not _q_confirm("Start new signed-in users as viewers with no departments until granted access?", default=True):
        console.print("[yellow]New users will be operators with access to every department. Existing deployments keep their chosen settings until you save this choice.[/yellow]")
        return {"default_role": "operator"}
    result: dict[str, Any] = {
        "default_role": "viewer",
        "default_suites": _split_csv(
            _q_text(
                "  Departments a new user may use until granted more (comma-separated "
                "suite keys, e.g. finance,tax; blank = none)",
                default="",
            )
        ),
    }
    console.print(
        "[dim]Optional: if your IdP pushes groups via SCIM, map a group to a "
        "role and/or departments so access follows team membership. Enter one "
        "'Group Name = value' per line; blank line to finish.[/dim]"
    )
    if _q_confirm("  Map IdP (SCIM) groups to roles/departments now?", default=False):
        roles = _collect_group_pairs(
            "    Group -> role (e.g. Finance Team=operator)", csv_value=False
        )
        suites = _collect_group_pairs(
            "    Group -> departments (e.g. Finance Team=finance,tax)", csv_value=True
        )
        if roles:
            result["group_roles"] = roles
        if suites:
            result["group_suites"] = suites
    return result


def _cfg_advanced(
    advanced: dict[str, Any] | None,
    providers: list[str],
    *,
    siem_dest: str = "",
) -> list[str]:
    """Render the advanced step's choices as ``config.toml`` sections.

    Each helper renders one family of toggles and returns its lines; the
    order here is the order the sections appear in the written file.
    """
    if not advanced and not siem_dest:
        return []
    lines: list[str] = []
    lines += _cfg_advanced_running_tasks_and_images(advanced)
    lines += _cfg_advanced_learning_opt_outs(advanced)
    lines += _cfg_advanced_routing_and_answers(advanced, providers)
    lines += _cfg_advanced_autonomy_and_workforce(advanced)
    lines += _cfg_advanced_verification_and_rewards(advanced)
    lines += _cfg_advanced_learning_governance(advanced)
    lines += _cfg_advanced_flows_and_extensions(advanced)
    lines += _cfg_advanced_quotas_and_tenancy(advanced)
    lines += _cfg_advanced_trust_and_audit(advanced, siem_dest)
    lines += _cfg_advanced_feature_locks(advanced)
    lines += _cfg_advanced_context_and_attachments(advanced)
    lines += _cfg_advanced_reflexion(advanced)
    lines += _cfg_advanced_self_harness(advanced)
    lines += _cfg_advanced_memory_and_immune(advanced)
    lines += _cfg_advanced_products(advanced)
    lines += _cfg_advanced_external_agents_and_memory(advanced)
    lines += _cfg_advanced_governance_monitors(advanced)
    lines += _cfg_advanced_dreaming_and_tax(advanced)
    lines += _cfg_advanced_runtime_and_tools(advanced, providers)
    lines += _cfg_advanced_oidc(advanced)
    lines += _cfg_advanced_dashboard(advanced)
    lines += _cfg_advanced_saml_and_sign_in(advanced)
    return lines


def _cfg_advanced_running_tasks_and_images(advanced: dict[str, Any]) -> list[str]:
    """``[agent]`` running-task reporting and ``[image_edit]`` model choices."""
    lines: list[str] = []
    budget_reporting = advanced.get("agent_budget_reporting")
    if budget_reporting is not None:
        if not isinstance(budget_reporting, dict) or set(budget_reporting) != {"synthesis_reserve", "spend_mirror_interval"}:
            raise ValueError("Running-task choices are not in the supported form.")
        values = []
        for key, maximum in (("synthesis_reserve", 1), ("spend_mirror_interval", 300)):
            value = budget_reporting[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= maximum:
                raise ValueError("Running-task choices must be within their displayed limits.")
            values.append(f"{key} = {float(value)}")
        lines.extend(["", "[agent]", *values])
    image_edit = advanced.get("image_edit")
    if image_edit:
        from maverick.image_edit_models import CHOICES, validate_model

        if not isinstance(image_edit, dict) or set(image_edit) - {row[0] for row in CHOICES}:
            raise ValueError("Image model choices are not in the supported form.")
        image_lines = []
        for field, _env, _label in CHOICES:
            value = validate_model(image_edit.get(field, ""))
            if value:
                image_lines.append(field + " = " + _toml_str(value))
        if image_lines:
            lines.extend(["", "[image_edit]", *image_lines])
    return lines


def _cfg_advanced_learning_opt_outs(advanced: dict[str, Any]) -> list[str]:
    """A deliberate no to a default-on learning section is written as ``enable = false``."""
    lines: list[str] = []
    # These governed-learning sections are default-on in the kernel. Preserve a
    # deliberate "no" from the advanced wizard instead of silently omitting the
    # table (which would now mean on). True choices are emitted with their richer
    # comments/settings in the existing blocks below.
    _learning_sections = {
        "reflexion": "reflexion",
        "self_harness": "self_harness",
        "dreaming": "dreaming",
        "skill_synthesis": "skill_synthesis",
        "experience_guidance": "experience",
        "credit_assignment": "credit",
        "rehearsal": "rehearsal",
        "data_engine": "data_engine",
        "operations_scientist": "operations_scientist",
        "consequence": "consequence",
        "cortex": "cortex",
        "shoring": "shoring",
    }
    for choice, section in _learning_sections.items():
        if choice in advanced and advanced[choice] is False:
            lines.extend(["", f"[{section}]", "enable = false"])
    return lines


def _cfg_advanced_routing_and_answers(advanced: dict[str, Any], providers: list[str]) -> list[str]:
    """``[routing]``, chat-answer verification/streaming and the SQL/REST ceilings."""
    lines: list[str] = []
    # Advanced reasoning toggles -> the kernel's config sections. Each is
    # off unless the wizard wrote it, matching the modules' own defaults.
    if (
        advanced.get("cost_aware")
        or advanced.get("verify_ensemble")
        or advanced.get("energy_aware")
        or advanced.get("autonomy_gate")
    ):
        lines.append("")
        lines.append("[routing]")
        # Constrain routing features enabled by the wizard to the providers
        # the user selected in this run. Some router/verifier fallbacks also
        # know about API keys from the shell environment; the allowlist keeps
        # advanced opt-ins from sending prompts to those unselected providers.
        _emit_kv(lines, "allowed_providers", providers)
        if advanced.get("cost_aware"):
            lines.append("cost_aware = true")
        if advanced.get("verify_ensemble"):
            lines.append("verify_ensemble = true")
        if advanced.get("energy_aware"):
            lines.append("energy_aware = true")
    if advanced.get("risk_proportional_verify") or advanced.get("verify_chat_answers"):
        lines.append("")
        lines.append("[verification]")
        if advanced.get("risk_proportional_verify"):
            lines.append("risk_proportional = true")
        if advanced.get("verify_chat_answers"):
            lines.append("verify_chat_answers = true")
    # Chat previews are on by default in the kernel: write only a deliberate "no".
    if advanced.get("stream_answers") is False:
        lines.append("")
        lines.append("[chat]")
        lines.append("stream_answers = false")
    if advanced.get("query_timeout_seconds", 30) != 30:
        lines.append("")
        lines.append("[query_limits]")
        lines.append(f"timeout_seconds = {int(advanced['query_timeout_seconds'])}")
    if advanced.get("connector_max_attempts", 3) != 3:
        lines.append("")
        lines.append("[connector_limits]")
        lines.append(f"max_attempts = {int(advanced['connector_max_attempts'])}")
    return lines


def _cfg_advanced_autonomy_and_workforce(advanced: dict[str, Any]) -> list[str]:
    """Autonomy gate, governed actions, workforce levels and calibration enforcement."""
    lines: list[str] = []
    if advanced.get("autonomy_gate") or advanced.get("headless_assume") or advanced.get("confirm_plan"):
        lines.append("")
        lines.append("[autonomy]")
        if advanced.get("autonomy_gate"):
            lines.append("enable = true")
        # A person confirms the plan before the first outside action.
        if advanced.get("confirm_plan"):
            lines.append("confirm_plan = true")
        # Independent axis: assume-and-proceed instead of blocking on ask_user.
        if advanced.get("headless_assume"):
            lines.append("headless_assume = true")
    if advanced.get("governed_actions"):
        lines.append("")
        lines.append("[actions]")
        lines.append("enable = true")
    # data_grounding defaults ON, so emit the knob only to DISABLE it. Both keys
    # share one [workforce] section.
    _wf_disable_grounding = advanced.get("workforce_data_grounding") is False
    if advanced.get("workforce_levels") or _wf_disable_grounding:
        lines.append("")
        lines.append("[workforce]")
        if advanced.get("workforce_levels"):
            lines.append("levels = true")
        if _wf_disable_grounding:
            lines.append("data_grounding = false")
    if advanced.get("calibration_enforce") or advanced.get("reward_laundering"):
        lines.append("")
        lines.append("[calibration]")
        lines.append("enforce = true")
        if advanced.get("reward_laundering"):
            lines.append("# Reward-laundering interlock: also freeze learning when the")
            lines.append("# verifier's edge on adversarial probes falls below this fraction")
            lines.append("# of its edge on natural traffic (the judge is being gamed). Needs")
            lines.append("# adversarial probes recorded (calibration.record_probe) to bite.")
            lines.append("min_resistance = 0.5")
    return lines


def _cfg_advanced_verification_and_rewards(advanced: dict[str, Any]) -> list[str]:
    """Trajectory donation, adaptive compute, verifier, reward and learning-signal toggles."""
    lines: list[str] = []
    if advanced.get("donate_trajectories"):
        lines.append("")
        lines.append("[telemetry]")
        lines.append("donate_trajectories = true")
        # Metadata-only by default. For DPO, add donate_text + the
        # donate_min_entropy/donate_min_confidence knobs by hand;
        # see docs/self-learning-runbook.md.
    if advanced.get("adaptive_compute"):
        lines.append("")
        lines.append("[adaptive_compute]")
        lines.append("enable = true")
    if advanced.get("best_of_n"):
        lines.append("")
        lines.append("[search]")
        lines.append("enable = true")
    if advanced.get("structured_verifier_off") or "audit_rewards" in advanced:
        lines.append("")
        lines.append("[reasoning_reward]")
        if advanced.get("structured_verifier_off"):
            lines.append("# The structured rubric verifier is ON by default (per-dimension")
            lines.append("# scoring + safety veto); disable it to fall back to the scalar")
            lines.append("# verifier verdict (maverick.reasoning_reward).")
            lines.append("enable = false")
        if "audit_rewards" in advanced:
            lines.append("# Sign each structured reward into the tamper-evident audit")
            lines.append("# chain (provable learning) -- the evidence the system learns")
            lines.append("# from, not just a mutable verdict. Enabled by default.")
            _emit_kv(lines, "audit_rewards", bool(advanced["audit_rewards"]))
    if advanced.get("jit_rl_off"):
        lines.append("")
        lines.append("[jit_rl]")
        lines.append("# JitRL test-time adaptation is ON by default (a no-op until it has")
        lines.append("# learned something); disable it entirely here (maverick.jit_rl).")
        lines.append("enable = false")
    if advanced.get("skill_synthesis"):
        lines.append("")
        lines.append("[skill_synthesis]")
        lines.append("enable = true")
    if advanced.get("experience_guidance"):
        lines.append("")
        lines.append("[experience]")
        lines.append("enable = true")
    if advanced.get("credit_assignment"):
        lines.append("")
        lines.append("[credit]")
        lines.append("enable = true")
    return lines


def _cfg_advanced_learning_governance(advanced: dict[str, Any]) -> list[str]:
    """The learning-policy ladder, self-modify, adapters and the governed learning loops."""
    lines: list[str] = []
    # The [self_improvement] block carries several default-on sub-toggles; emit
    # explicit values when the wizard records a choice, and write
    # factory_learning=false when the user opts out.
    declined_factory = "factory_learning" in advanced and not advanced.get("factory_learning")
    has_learning_policy = any(
        key in advanced for key in ("causal_promotion", "factory_learning", "evaluator_evolution")
    )
    if has_learning_policy or advanced.get("signed_approval"):
        lines.append("")
        lines.append("[self_improvement]")
        lines.append("enable = true")
        lines.append("capture = true")
        lines.append("prm_guidance = true")
        if "causal_promotion" in advanced:
            lines.append("# Promote learned changes on their confounder-adjusted causal")
            lines.append("# effect (maverick.promotion_effect), not a correlation. Applies")
            lines.append("# when self-improvement is enabled.")
            lines.append(
                f"causal_promotion = {str(bool(advanced.get('causal_promotion'))).lower()}"
            )
        if declined_factory:
            lines.append("# Keep the agent factory's generator static (do not mine")
            lines.append("# pack-generation gaps into proposer corrections).")
            lines.append("factory_learning = false")
        if "evaluator_evolution" in advanced:
            lines.append("# Promote a better judge instead of only freezing when the")
            lines.append("# evaluator drifts: a challenger replaces the incumbent only when")
            lines.append("# its agreement with a checksum-locked ground-truth anchor beats")
            lines.append("# it (maverick.evaluator_evolution, 'evaluator' rung).")
            lines.append(
                f"evaluator_evolution = {str(bool(advanced.get('evaluator_evolution'))).lower()}"
            )
        if advanced.get("signed_approval"):
            lines.append("# Require a cryptographic (Ed25519) human approval for the")
            lines.append("# code/weights rungs instead of a self-settable boolean, bound to")
            lines.append("# the exact change (maverick.approval_signing). Fails closed until")
            lines.append("# you provide approver PUBLIC keys (hex) or a dir of *.pub.")
            lines.append("require_signed_approval = true")
            lines.append('# approver_keys = ["<ed25519-pubkey-hex>"]')
            lines.append('# approver_keys_dir = "/etc/maverick/approvers"')
    if advanced.get("self_modify"):
        lines.append("")
        lines.append("[self_modify]")
        lines.append("# Research-only DGM cycles (maverick.self_modify): propose a diff,")
        lines.append("# enforce the reference monitor, evaluate baseline/candidate in distinct")
        lines.append("# no-egress non-root containers, and archive development telemetry.")
        lines.append("# This runner NEVER applies or promotes code. Production adoption remains")
        lines.append("# disabled until a one-shot external evaluator, evidence/base/tenant-bound")
        lines.append("# approval manifest, and durable PREPARE/CAS/COMMIT integration exist.")
        lines.append("# Inert until both gates are on, editable_paths is narrow, and at least")
        lines.append("# two discriminating eval_tests are configured. The tests are visible to")
        lines.append("# the candidate and are a development challenge corpus, not sealed proof.")
        lines.append("# Also select a container sandbox with require_container=true,")
        lines.append("# allow_network=false, allow_root=false, and finite process/memory limits.")
        lines.append("enable = true")
        lines.append('# editable_paths = ["packages/maverick-core/maverick/domains/*.toml"]')
        lines.append('# eval_tests = ["path/test_feature.py::case_a",')
        lines.append('#               "path/test_feature.py::case_b"]')
        lines.append('# eval_command = "python3 -m pytest -q"')
    if advanced.get("adapter_rung"):
        lines.append("")
        lines.append("[adapter_rung]")
        lines.append("# Governed in-tenant weights adaptation (maverick.adapter_rung):")
        lines.append("# LoRA adapters trained on YOUR corrections/traces, promoted through")
        lines.append("# the weights rung (held-out evidence + non-escalation + Ed25519")
        lines.append("# approval + one-step rollback). Frontier-model output is refused as")
        lines.append("# training data unless allow_model_output = true (distillation guard).")
        lines.append("# Inert until base_model is set to YOUR local serving spec; prefer an")
        lines.append("# Apache-2.0/MIT base so no vendor can restrict the tenant's model.")
        lines.append("enable = true")
        lines.append('# base_model = "ollama:<model-id>"   # e.g. an Apache-2.0 Qwen3 size')
        lines.append('# trainer = "dpo-lora"               # needs the [training] extra')
        lines.append("# allow_synthetic = false")
        lines.append("# allow_model_output = false")
    if advanced.get("rehearsal"):
        lines.append("")
        lines.append("[rehearsal]")
        lines.append("# Simulate a risky plan against the learned world-model before it")
        lines.append("# runs; proceed when confidently safe, block a poor outcome, escalate")
        lines.append("# the unknown (maverick.rehearsal). Fail-open while disabled.")
        lines.append("enable = true")
    if advanced.get("speculative"):
        lines.append("")
        lines.append("[speculative]")
        lines.append("# Draft a confidently-predictable turn with a cheap model, keeping the")
        lines.append("# frontier model for novel/uncertain turns (maverick.speculative_exec).")
        lines.append("# Set draft_model to a cheap spec to activate; a no-op until you do.")
        lines.append("enable = true")
        lines.append('# draft_model = "anthropic:claude-haiku-4-5-20251001"')
    if advanced.get("data_engine"):
        lines.append("")
        lines.append("[data_engine]")
        lines.append("# Triage production failures by causal impact on real outcomes, then")
        lines.append("# mine + validate + promote fixes (maverick.data_engine). The Tesla")
        lines.append("# data-engine flywheel for the workforce; reads the trajectory store.")
        lines.append("enable = true")
    if advanced.get("operations_scientist"):
        lines.append("")
        lines.append("[operations_scientist]")
        lines.append("# Discover a better process and prove it: pair a harmful action with")
        lines.append("# the beneficial habit that should replace it, validate the swap in the")
        lines.append("# world-model, then experiment for real (maverick.operations_scientist).")
        lines.append("enable = true")
    if advanced.get("consequence"):
        lines.append("")
        lines.append("[consequence]")
        lines.append("# Ground learning in REAL downstream outcomes: a recorded consequence")
        lines.append("# (invoice paid, ticket reopened) overrides the model's self-graded")
        lines.append(
            "# proxy reward, so the data engine learns from reality (maverick.consequence)."
        )
        lines.append("enable = true")
    if advanced.get("earned_autonomy"):
        lines.append("")
        lines.append("[earned_autonomy]")
        lines.append("# Consequence-proven trust (maverick.earned_autonomy): pin a consequence")
        lines.append("# card per rehearsed high-stakes action, score it against reality, and")
        lines.append("# graduate a proven action type to policy-auto-approval -- demoted on")
        lines.append("# one miss. Enabling records evidence only; arming graduation is the")
        lines.append("# separate auto_graduate switch below.")
        lines.append("enable = true")
        lines.append("# auto_graduate = true      # arm the dial (authority-widening)")
        lines.append('# max_auto_risk = "medium"  # raise to "high" only deliberately')
        lines.append("# min_streak = 10           # consecutive accurate predictions required")
    return lines


def _cfg_advanced_flows_and_extensions(advanced: dict[str, Any]) -> list[str]:
    """Flows, workflow options, connections and the emergent protocol/codec."""
    lines: list[str] = []
    if advanced.get("flows"):
        lines.append("")
        lines.append("[flows]")
        lines.append("# Deterministic control-flow skeleton (branch/foreach/parallel/approval/")
        lines.append("# delay) over agentic + tool steps; migrated workflows keep their shape")
        lines.append("# while any node can still be a full agentic goal (maverick.flow).")
        lines.append("enable = true")
        lines.append("# Per-node retry cap; bounds repeated provider/tool calls.")
        lines.append("max_node_retries = 5")
        if "flows_learned_operators" in advanced:
            _emit_kv(lines, "learned_operators", advanced["flows_learned_operators"])
        if "flows_learned_operator_questions" in advanced:
            _emit_kv(lines, "learned_operator_questions",
                     advanced["flows_learned_operator_questions"])
        if "flows_composed_operators" in advanced:
            _emit_kv(lines, "composed_operators", advanced["flows_composed_operators"])
        if "flows_action_recipes" in advanced:
            _emit_kv(lines, "action_recipes", advanced["flows_action_recipes"])
        if "flows_action_recipe_transforms" in advanced:
            _emit_kv(lines, "action_recipe_transforms", advanced["flows_action_recipe_transforms"])
        if "flows_action_recipe_choices" in advanced:
            _emit_kv(lines, "action_recipe_choices", advanced["flows_action_recipe_choices"])
        if "flows_action_recipe_teaching" in advanced:
            _emit_kv(lines, "action_recipe_teaching", advanced["flows_action_recipe_teaching"])
        if "flows_action_episode_capture" in advanced:
            _emit_kv(lines, "action_episode_capture", advanced["flows_action_episode_capture"])
        if "flows_action_workflow_learning" in advanced:
            _emit_kv(lines, "action_workflow_learning", advanced["flows_action_workflow_learning"])
        if "flows_action_workflow_memory_learning" in advanced:
            _emit_kv(lines, "action_workflow_memory_learning", advanced["flows_action_workflow_memory_learning"])
        for key in ("action_recipe_lineage", "require_action_recipe_lineage",
                    "action_evidence_issuer", "action_evidence_revoked_keys"):
            if "flows_" + key in advanced:
                _emit_kv(lines, key, advanced["flows_" + key])
        if advanced.get("flows_auto_evolve"):
            lines.append("# Autonomously revert a node rewrite whose grounded outcomes")
            lines.append("# regressed (the loop undoes its own bad changes).")
            lines.append("auto_evolve = true")
        if advanced.get("flows_public_url"):
            lines.append("# Externally-reachable dashboard base URL for signed channel")
            lines.append("# Approve/Reject links (actionable approvals).")
            _emit_kv(lines, "public_url", advanced["flows_public_url"])
    if "workflow_typed_inputs" in advanced or "workflow_versioning" in advanced:
        lines.extend(["", "[workflows]"])
        _emit_kv(lines, "typed_inputs", advanced.get("workflow_typed_inputs", True) is True)
        _emit_kv(lines, "versioning", advanced.get("workflow_versioning", True) is True)
    if advanced.get("connections"):
        lines.append("")
        lines.append("[connections]")
        lines.append("# Named SaaS connections (base URL + sealed token) so a connector")
        lines.append("# can be wired from the dashboard without <NAME>_TOKEN env vars; an")
        lines.append("# existing env var still takes precedence (maverick.connections).")
        lines.append("enable = true")
        _emit_kv(lines, "allow_self_connect", advanced.get("connections_self_connect") is True)
        _emit_kv(lines, "self_connect_profiles", "google-drive")
    if advanced.get("emergent_protocol"):
        lines.append("")
        lines.append("[emergent_protocol]")
        lines.append("# Learn short codes for the swarm's repeated coordination boilerplate;")
        lines.append("# every code decodes exactly back to English, so nothing is hidden from")
        lines.append("# the Shield/audit (maverick.emergent_protocol). No-op until learned.")
        lines.append("enable = true")
    if advanced.get("emergent_codec"):
        lines.append("")
        lines.append("[emergent_codec]")
        lines.append("# Measure the token-aware codec (maverick.emergent_tokens) on the live")
        lines.append("# coordination stream: byte-stuffed cheap codes that save real tokens.")
        lines.append("# Telemetry only -- the rendered text agents/Shield see is unchanged.")
        lines.append("enable = true")
    return lines


def _cfg_advanced_quotas_and_tenancy(advanced: dict[str, Any]) -> list[str]:
    """Quotas, spending limits, tenancy, enterprise, residency and compliance."""
    lines: list[str] = []
    if advanced.get("enforce_quotas"):
        lines.append("")
        lines.append("[quotas]")
        lines.append("enforce = true")
        # Starter daily caps per principal; edit or set to 0 to disable a
        # dimension. The kernel also reads MAVERICK_QUOTA_* env overrides.
        lines.append("max_dollars_per_day = 25.0")
        lines.append("max_tokens_per_day = 5000000")
    _workspace_limit = _monthly_limit(advanced.get("spending_workspace_monthly", 0),
                                      label="Monthly spending limit for the whole workspace")
    _person_limit = _monthly_limit(advanced.get("spending_person_monthly", 0),
                                   label="Monthly spending limit for each person")
    _alert_at = _spending_alert_at(advanced.get("spending_alert_at"))
    _min_runs = _typical_cost_min_runs(advanced.get("typical_cost_min_runs"))
    if _workspace_limit > 0 or _person_limit > 0 or _alert_at is not None or _min_runs is not None:
        # Starting limits; administrators change them in the dashboard
        # (Admin > Spending limits), which then takes precedence.
        lines.append("")
        lines.append("[spending_limits]")
        if _workspace_limit > 0:
            lines.append(f"workspace_dollars = {_workspace_limit:.2f}")
            lines.append('workspace_period = "month"')
        if _person_limit > 0:
            lines.append(f"default_user_dollars = {_person_limit:.2f}")
            lines.append('default_user_period = "month"')
        if _alert_at is not None:
            # In-app alerts at these percentages of each limit (default 50, 75, 100).
            lines.append(f"alert_at = [{', '.join(str(p) for p in _alert_at)}]")
        if _min_runs is not None:
            # Finished tasks needed before a typical cost is shown (default 10).
            lines.append(f"typical_cost_min_runs = {_min_runs}")
    if advanced.get("tenant_by_user"):
        lines.append("")
        lines.append("[tenancy]")
        lines.append("by_user = true")
    _client_id = str(advanced.get("client_id") or "").strip()
    if _client_id:
        lines.append("")
        lines.append("[client]")
        _emit_kv(lines, "id", _client_id)
        # Enforced: refuse to start unbound so this client's data can never land
        # in the shared root. Also set MAVERICK_CLIENT_ID in the service unit.
        lines.append("enforce = true")
    if advanced.get("enterprise"):
        lines.append("")
        lines.append("[enterprise]")
        lines.append("mode = true")
    if advanced.get("residency_region"):
        lines.append("")
        lines.append("# Data-residency region hint (maverick.residency); strict")
        lines.append("# mode is a separate [residency] strict knob.")
        lines.append("[residency]")
        _emit_kv(lines, "region", advanced["residency_region"])
    if advanced.get("compliance_disclosure_text") or advanced.get("compliance_profiles"):
        lines.append("")
        lines.append("# AI-disclosure line surfaced to users (maverick.compliance), and the")
        lines.append("# regulatory obligations compiled into the action gate")
        lines.append("# (maverick.regulatory_compiler; strictest-wins).")
        lines.append("[compliance]")
        if advanced.get("compliance_disclosure_text"):
            _emit_kv(lines, "disclosure_text", advanced["compliance_disclosure_text"])
        if advanced.get("compliance_profiles"):
            lines.append("profiles = [" + ", ".join(
                _toml_str(p) for p in advanced["compliance_profiles"]) + "]")
    return lines


def _cfg_advanced_trust_and_audit(advanced: dict[str, Any], siem_dest: str) -> list[str]:
    """Agent trust, control plane, at-rest encryption, RLS and the audit sinks."""
    lines: list[str] = []
    if advanced.get("agent_trust"):
        lines.append("")
        lines.append("[agent_trust]")
        lines.append("enforce = true")
        # require_signed: refuse a federation peer that authenticates with only a
        # shared token (no pinned-key signature). Peers WITH a pinned key are
        # always signature-verified regardless of this flag.
        lines.append("require_signed = false")
        # Default-deny: external agents must be listed here, by pinned Ed25519
        # public key (lowercase id, e.g. "vega"), with the direction and ceiling
        # they're trusted within. Swap pubkeys out of band
        # (data_dir('audit','keys')/<key_id>.pub). expires_at/not_before (epoch
        # seconds) and revoked support key rotation/revocation.
        lines.append("# agents = [")
        lines.append(
            '#   { id = "vega", pubkey = "<64-hex Ed25519>", '
            'direction = "both", allow_tools = ["read_file", '
            '"http_fetch"], max_risk = "medium", max_dollars = 2.0, '
            'max_wall_seconds = 600, data_scopes = ["support"] },'
        )
        lines.append("# ]")
    if advanced.get("control_plane"):
        lines.append("")
        lines.append("# Agent Control Plane: arms principal verbs on the dashboard and CLI.")
        lines.append("# CLI HALT is local; dashboard cluster HALT needs a shared authority.")
        lines.append("# Roster/status/ledger reads work even when mutation verbs are off.")
        lines.append("[control_plane]")
        lines.append("enable = true")
    if advanced.get("anonymous_logs"):
        lines.append("")
        lines.append("[privacy]")
        lines.append("anonymous = true")
    if advanced.get("encrypt_at_rest"):
        lines.append("")
        lines.append("[encryption]")
        lines.append("at_rest = true")
        if advanced.get("encrypt_per_tenant"):
            lines.append("per_tenant = true")
    if advanced.get("pg_rls"):
        lines.append("")
        lines.append("[world_model]")
        # Database-enforced tenant isolation (Postgres backend only; ignored on
        # SQLite). The policy is strict, fail-closed equality, so prep BEFORE the
        # first start or pre-tenancy (NULL-tenant) rows become invisible:
        #   maverick tenant rls-preflight         # ownership + legacy-row check
        #   maverick tenant backfill --tenant ID  # assign pre-tenancy NULL rows
        lines.append(
            "# Run `maverick tenant rls-preflight` + `maverick tenant "
            "backfill` before first start (see docs/multi-tenancy.md)."
        )
        lines.append("rls = true")
    if advanced.get("audit_sign") or advanced.get("unified_audit") or siem_dest:
        lines.append("")
        lines.append("[audit]")
        if advanced.get("audit_sign") or advanced.get("unified_audit"):
            lines.append("sign = true")
        if siem_dest:
            lines.append(f"siem_dest = {_toml_str(siem_dest)}")
    if advanced.get("unified_audit"):
        lines.append("")
        lines.append("[audit.unified]")
        lines.append("# Fixed completeness floor: AI Governance, Consent & Preferences,")
        lines.append("# Data Use Governance, Privacy Automation, Tech Risk & Compliance,")
        lines.append("# and Third-Party Management. Sources cannot be removed in config.")
        lines.append("enable = true")
        lines.append("page_size = 100")
        lines.append("lease_seconds = 120")
        lines.append("max_lag_seconds = 300")
        lines.append("max_attempts = 5")
        lines.append("retry_backoff_seconds = 30")
        lines.append("poll_seconds = 60")
        lines.append("")
        lines.append("[audit.unified.custody]")
        lines.append("# Managed tenant-exact checkpoint/custody run after each projection sweep.")
        lines.append("# It never seals files automatically; run `maverick audit seal` explicitly.")
        lines.append("enable = true")
        lines.append("authority_revision = 1")
        lines.append("checkpoint_enable = true")
        lines.append(
            f"worm_enable = {'true' if advanced.get('audit_worm') else 'false'}"
        )
        lines.append("siem_enable = false")
        lines.append('# siem_destination_template = "https://siem.example/tenants/{tenant_sha256}/raw"')
        lines.append("max_siem_events_per_run = 500")
        lines.append("retry_backoff_seconds = 30")
        lines.append("max_retry_backoff_seconds = 3600")
    if advanced.get("audit_worm"):
        lines.append("")
        # WORM export of closed audit day-files. Defaults to a local read-only
        # mirror (best-effort, tamper-evident); switch provider to "s3" + an
        # Object-Lock bucket for regulator-grade immutability. Ship with
        # `maverick audit worm push` (see docs/security-hardening.md).
        lines.append("[audit.worm]")
        lines.append('provider = "local"   # or "s3" for S3 Object-Lock')
        lines.append("retention_days = 2555   # lock duration (~7y)")
        lines.append('# bucket = "my-audit-worm"   # s3: Object-Lock + versioning enabled')
        lines.append('# prefix = "maverick/audit/"')
        lines.append('# mode = "COMPLIANCE"        # COMPLIANCE | GOVERNANCE')
        lines.append('# region = "us-east-1"')
    return lines


_FEATURE_LOCKS: tuple[tuple[str, bool, str], ...] = (
    ("allow_employee_task_diagnostics", False, "employee_task_diagnostics = false"),
    ("allow_employee_activation", False, "employee_activation = false"),
    ("allow_copilot_operations", True, "copilot_operations = true"),
    ("allow_workflow_readiness", False, "workflow_readiness = false"),
    ("allow_project_reviews", True, "project_reviews = true"),
    ("allow_task_handoffs", True, "task_handoffs = true"),
    ("allow_deliverable_bundles", True, "deliverable_bundles = true"),
    ("allow_project_workspaces", True, "project_workspaces = true"),
    ("allow_employee_companions", True, "employee_companions = true"),
    ("allow_employee_content_access_requests", True, "employee_content_access_requests = true"),
    ("allow_personal_data_controls", True, "personal_data_controls = true"),
    ("allow_permission_access_requests", True, "permission_access_requests = true"),
    ("allow_employee_departures", True, "employee_departures = true"),
    ("allow_outcome_measurement", True, "outcome_measurement = true"),
    ("allow_commitment_viability", True, "commitment_viability = true"),
    ("allow_work_restructuring", True, "work_restructuring = true"),
    ("allow_portable_competence", True, "portable_competence = true"),
    ("allow_private_task_computation", True, "private_task_computation = true"),
    ("allow_procedure_interactions", True, "procedure_interactions = true"),
    ("allow_operational_competence_acquisition", True, "operational_competence_acquisition = true"),
    ("allow_request_program", True, "request_program = true"),
    ("allow_commitment_economic_alternatives", True, "commitment_economic_alternatives = true"),
    ("allow_workflow_step_checks", True, "workflow_step_checks = true"),
    ("allow_applicability_regions", True, "applicability_regions = true"),
    ("allow_governed_rule_evolution", True, "governed_rule_evolution = true"),
    ("allow_recovery_visibility", True, "recovery_visibility = true"),
    ("allow_semantic_rule_reuse", True, "semantic_rule_reuse = true"),
    ("allow_commitment_capability_learning", True, "commitment_capability_learning = true"),
    ("allow_shared_decision_evidence", True, "shared_decision_evidence = true"),
    ("allow_workspace_recovery", True, "workspace_recovery = true"),
    ("allow_signing_identity_transition", True, "signing_identity_transition = true"),
    ("allow_configuration_profiles", False, "configuration_profiles = false"),
    ("allow_personal_preferences", False, "personal_preferences = false"),
    ("allow_draft_recovery", False, "draft_recovery = false"),
    ("allow_support_center", False, "support_center = false"),
    ("allow_record_search", False, "record_search = false"),
    ("allow_action_center", False, "action_center = false"),
    ("allow_guided_onboarding", False, "guided_onboarding = false"),
    ("allow_pack_editing", False, "pack_editing = false"),
    ("allow_role_editing", False, "role_editing = false"),
)


def _cfg_advanced_feature_locks(advanced: dict[str, Any]) -> list[str]:
    """Dashboard feature locks: the ``[features]`` table plus its sibling tables.

    The features default on, so only the disables (and the deliberate enables
    of default-off features) are written -- as ONE ``[features]`` table, since
    two tables would be a duplicate-key TOML error. The kernel reads these via
    ``config.get_features``.
    """
    lines: list[str] = []
    if advanced.get("allow_runtime_configuration_status") is False:
        lines.extend(["[settings]", "runtime_status = false"])
    if advanced.get("allow_copilot_operations") is True:
        families = advanced.get("copilot_operation_families", ["learning"])
        allowed_families = {"learning", "preferences", "tasks", "clarifications", "reviews", "schedules",
                            "connections", "artifacts", "notifications", "models", "budget", "plugins",
                            "commitments"}
        if not isinstance(families, list) or any(value not in allowed_families for value in families):
            raise ValueError("Choose registered Copilot action families.")
        lines.append("[copilot]")
        _emit_kv(lines, "operation_families", list(dict.fromkeys(families)))
    if "allow_work_details" in advanced:
        lines.extend(["[work_details]"])
        _emit_kv(lines, "enable", advanced["allow_work_details"] is True)
    if advanced.get("allow_public_chat") is True:
        # Off by default: only a deliberate yes is written. Sites are added on the Channels page (docs/public-chat.md).
        lines.extend(["", "[public_chat]", "enabled = true"])
    locks = [line for key, wanted, line in _FEATURE_LOCKS if advanced.get(key) is wanted]
    if type(advanced.get("allow_human_conversation_handoffs")) is bool:
        locks.append("human_conversation_handoffs = " + str(advanced["allow_human_conversation_handoffs"]).lower())
    if locks:
        lines.append("")
        lines.append("[features]")
        lines.extend(locks)
    if advanced.get("allow_conversation_inbox") is True:
        lines.extend(["", "[conversation_inbox]", "enabled = true", "guidance = true", "queue = true", "independent = true", "max_pending = 20"])
    elif advanced.get("allow_conversation_inbox") is False:
        # On by default, so only a deliberate "no" is written (and stays off).
        lines.extend(["", "[conversation_inbox]", "enabled = false"])
    if type(advanced.get("allow_chat_message_actions")) is bool:
        lines.extend(["", "[chat_message_actions]",
                      "enabled = " + str(advanced["allow_chat_message_actions"]).lower()])
    return lines


def _cfg_advanced_context_and_attachments(advanced: dict[str, Any]) -> list[str]:
    """Planning, context compaction, voice, attachments and the recording opt-ins."""
    lines: list[str] = []
    if advanced.get("tree_of_thought"):
        lines.append("")
        lines.append("[planning]")
        lines.append('mode = "tree_of_thought"')
    _context_lines = []
    if advanced.get("compact_history"):
        _context_lines.append("compact = true")
    strat = advanced.get("compaction_strategy")
    if strat and strat != "default":
        _context_lines.append(f'compaction_strategy = "{strat}"')
    if advanced.get("model_scaled_context") is False:
        # Default-on; only a decline needs a line.
        _context_lines.append("model_scaled = false")
    if _context_lines:
        lines.append("")
        lines.append("[context]")
        lines.extend(_context_lines)
    _voice_lines = []
    if advanced.get("voice_commands") is False:
        # Default-on; only a decline needs a line.
        _voice_lines.append("dashboard_commands = false")
    if isinstance(advanced.get("voice_local_stt"), bool):
        # Persist the reviewed choice; absent configuration never downloads.
        _voice_lines.append("auto_fetch_model = " + str(advanced["voice_local_stt"]).lower())
    if _voice_lines:
        # ONE [voice] table -- two would be a duplicate-key TOML error.
        lines.append("")
        lines.append("[voice]")
        lines.extend(_voice_lines)
    _attach_lines = []
    if any(advanced.get(key) for key in ("macro_cell_edits", "native_recalculation", "pdf_ocr")):
        lines.extend(["", "[documents]"])
        for key in ("macro_cell_edits", "native_recalculation", "pdf_ocr"):
            lines.append(f"{key} = {str(bool(advanced.get(key))).lower()}")
        lines.append("engine_image = " + _toml_str(advanced.get("document_engine_image") or "lightwork-documents:local"))
    if advanced.get("attach_any_mime"):
        _attach_lines.append("allow_any_mime = true")
    if advanced.get("attachment_understanding") is False:
        # Default-on; only a decline needs lines.
        _attach_lines.append("transcribe_media = false")
        _attach_lines.append("extract_text = false")
    if _attach_lines:
        lines.append("")
        lines.append("[attachments]")
        lines.extend(_attach_lines)
    if "approval_challenges" in advanced:
        if type(advanced["approval_challenges"]) is not bool:
            raise ValueError("Local approval challenge permission must be on or off.")
        lines.append("")
        lines.append("[approval_challenges]")
        lines.append("enable = " + ("true" if advanced["approval_challenges"] else "false"))
    if "instruction_capture" in advanced:
        lines.append("")
        lines.append("[instruction_capture]")
        lines.append("enable = " + ("true" if advanced["instruction_capture"] else "false"))
    return lines


def _cfg_advanced_reflexion(advanced: dict[str, Any]) -> list[str]:
    """``[reflexion]``."""
    lines: list[str] = []
    if advanced.get("reflexion"):
        lines.append("")
        lines.append("[reflexion]")
        lines.append("enable = true")
    return lines


def _cfg_advanced_self_harness(advanced: dict[str, Any]) -> list[str]:
    """The ``[self_harness]`` table: validation floors by default, options on opt-in."""
    lines: list[str] = []
    if advanced.get("self_harness"):
        lines.append("")
        lines.append("[self_harness]")
        lines.append("enable = true")
        lines.append("risk_limited = true")
        # Ship production-safe validation floors by default (an operator can
        # relax them): never promote on only the mined examples, require an
        # unseen-sample floor, and an effect-size floor so noisy lifts don't
        # promote. No effect until a promotion pass actually runs.
        lines.append("require_held_out = true")
        lines.append("min_held_out = 5")
        lines.append("min_delta = 0.02")
        lines.extend(_cfg_advanced_self_harness_options(advanced))
    return lines


def _cfg_advanced_self_harness_options(advanced: dict[str, Any]) -> list[str]:
    """The optional self-harness paths, written only when the operator opted in.

    Each is at its historical default otherwise, so the block stays minimal.
    """
    lines: list[str] = []
    if advanced.get("self_harness_eval_corpus"):
        # Free-text path: escape via _toml_str so a path with a backslash or
        # quote can't corrupt the config the wizard writes.
        _emit_kv(lines, "eval_corpus", advanced["self_harness_eval_corpus"])
        eval_budget = advanced.get("self_harness_eval_budget")
        if eval_budget and eval_budget > 0:
            lines.append(f"eval_budget_dollars = {float(eval_budget)}")
    if advanced.get("self_harness_holdout_ledger"):
        _emit_kv(
            lines,
            "holdout_ledger",
            advanced["self_harness_holdout_ledger"],
        )
    if advanced.get("self_harness_holdout_container_image"):
        _emit_kv(
            lines,
            "holdout_container_image",
            advanced["self_harness_holdout_container_image"],
        )
    if advanced.get("self_harness_require_independent_custody"):
        lines.append("holdout_require_independent_custody = true")
    if advanced.get("self_harness_bucket_domain"):
        lines.append('mine_bucket_by = ["domain"]')
    if advanced.get("self_harness_semantic_mining"):
        lines.append("semantic_mining = true")
    if advanced.get("self_harness_efficacy_review"):
        lines.append("efficacy_review = true")
    if advanced.get("self_harness_canary"):
        lines.append("promote_as_canary = true")
    if advanced.get("self_harness_auto_run"):
        lines.append("auto_run = true")
    elif "self_harness_auto_run" in advanced:
        lines.append("auto_run = false")
    if advanced.get("self_harness_metamorphic"):
        lines.append("metamorphic = true")
    if advanced.get("self_harness_relapse"):
        lines.append("relapse_failure_share = 0.5")
    if advanced.get("self_harness_calibrate_judge"):
        lines.append("calibrate_judge = true")
    if advanced.get("self_harness_transfer_auto"):
        lines.append("transfer_auto = true")
    if advanced.get("self_harness_corpus_harvest"):
        _emit_kv(lines, "corpus_harvest", advanced["self_harness_corpus_harvest"])
    if advanced.get("self_harness_store"):
        _emit_kv(lines, "store", advanced["self_harness_store"])
    cands = advanced.get("self_harness_candidates")
    if cands and cands > 1:
        lines.append(f"candidates_per_signature = {int(cands)}")
    retire_days = advanced.get("self_harness_retire_days")
    if retire_days and retire_days > 0:
        lines.append(f"retire_after_days = {int(retire_days)}")
    return lines


def _cfg_advanced_memory_and_immune(advanced: dict[str, Any]) -> list[str]:
    """Fleet memory, codebase mode, IFC, swarm scale and the immune canaries."""
    lines: list[str] = []
    if advanced.get("fleet_memory"):
        lines.append("")
        lines.append("[fleet_memory]")
        lines.append("enable = true")
    if advanced.get("codebase_enable"):
        lines.append("")
        lines.append("[codebase]")
        lines.append("# Code vault and feature swarms (maverick.codebase): repositories sealed")
        lines.append("# at rest; changes merge or push only after a human approves.")
        lines.append("enable = true")
        protect = advanced.get("codebase_protect", "block")
        if protect in ("block", "approve", "audit"):
            lines.append(f'default_protect = "{protect}"')
    if advanced.get("ifc_mode"):
        lines.append("")
        lines.append("[ifc]")
        lines.append("# Information-flow control (maverick.ifc): labelled data reaching an")
        lines.append("# external sink is recorded (audit), held for approval, or blocked.")
        lines.append(f'mode = "{advanced["ifc_mode"]}"')
    if advanced.get("swarm_max_total_spawns"):
        lines.append("")
        lines.append("[swarm]")
        lines.append(f"max_total_spawns = {int(advanced['swarm_max_total_spawns'])}")
        lines.append("max_concurrent_model_calls = "
                     f"{int(advanced.get('swarm_max_concurrent_model_calls', 0))}")
    if advanced.get("immune_canaries") or advanced.get("immune_twin_record"):
        lines.append("")
        lines.append("[immune]")
    if advanced.get("immune_canaries"):
        lines.append("# Oversight canaries (maverick.immune.oversight): operators may seed")
        lines.append("# known-flawed approvals to measure reviewer catch rates.")
        lines.append("canaries = true")
    if advanced.get("immune_twin_record"):
        lines.append("# Production twin (maverick.immune.twin): record tool results so a")
        lines.append("# goal can be replayed against exactly what production saw.")
        lines.append("twin_record = true")
    return lines


def _cfg_advanced_products(advanced: dict[str, Any]) -> list[str]:
    """Cortex, commerce, shoring and Stripe billing."""
    lines: list[str] = []
    if advanced.get("cortex"):
        lines.append("")
        lines.append("[cortex]")
        lines.append("# Cortex, the company brain (maverick.cortex): one governed recall/deposit")
        lines.append("# surface over knowledge, skills, lessons, the Operating Record and fleet")
        lines.append("# memory -- tenant-exact, one audit row per read and per write. Each")
        lines.append("# source's own toggle still applies. `maverick cortex status` shows it.")
        lines.append("enable = true")
    if advanced.get("commerce"):
        lines.append("")
        lines.append("[commerce]")
        lines.append("enable = true")
        lines.append('backend = "demo"          # in-memory reference backend; register a real one')
        lines.append("#                           # via maverick.commerce.register_backend")
        lines.append("# max_session_spend = 500.0 # per-session cart cap, store currency")
        lines.append("# max_line_quantity = 10    # per-line quantity cap")
        lines.append("# max_cart_lines = 25       # distinct lines per cart")
    if advanced.get("shoring"):
        lines.append("")
        lines.append("[shoring]")
        lines.append("# Autonomous Shoring (maverick.shoring): the Book of Work, service levels")
        lines.append("# measured from the Operating Record, and the exception desk at /shoring.")
        lines.append("# Includes starter-team setup and offline structured-input sample checks.")
        lines.append("# Samples do not qualify providers, enable external actions or start schedules.")
        lines.append("# On by default; this section only lets an operator turn the surface off.")
        lines.append("enable = true")
    if advanced.get("stripe_billing"):
        lines.append("")
        lines.append("[billing.stripe]")
        lines.append("# Platform billing collection (maverick.billing_stripe): turn the metered")
        lines.append("# usage invoices into real Stripe charges. The secret key and webhook")
        lines.append("# signing secret live in the ENV, never here:")
        lines.append("#   MAVERICK_STRIPE_SECRET_KEY, MAVERICK_STRIPE_WEBHOOK_SECRET")
        lines.append("enable = true")
        lines.append("# Off: bill only the platform fee until the model-usage markup is set.")
        lines.append("# Turn on (or set MAVERICK_STRIPE_BILL_METERED=1) once it is.")
        lines.append("bill_metered_usage = false")
        lines.append('currency = "usd"')
        lines.append("# Recurring price id per plan (the platform fee). Fill in from your Stripe")
        lines.append("# dashboard; a plan with no price here is billed no platform fee.")
        lines.append("[billing.stripe.prices]")
        lines.append('# pro = "price_..."')
        lines.append('# enterprise = "price_..."')
    return lines


def _cfg_advanced_external_agents_and_memory(advanced: dict[str, Any]) -> list[str]:
    """External agents, the governed MCP sidecar, the REPL, harness refinement and memory options."""
    lines: list[str] = []
    if advanced.get("external_agents"):
        lines.append("")
        lines.append("[external_agents]")
        lines.append("enable = true")
        if advanced.get("external_require_signed"):
            lines.append("require_signed = true")
        if advanced.get("external_connectors"):
            _emit_kv(lines, "connectors", advanced["external_connectors"])
        if advanced.get("external_mint_approval"):
            lines.append("mint_approval = true")
    sidecar = advanced.get("mcp_sidecar")
    if isinstance(sidecar, dict) and sidecar.get("enable") is True:
        _require_secure_url(str(sidecar.get("upstream_url", "")), "The MCP sidecar")
        # The wizard only emits a closed reviewed manifest.  It never writes an
        # upstream bearer value, broad CORS origin, or arbitrary forwarded
        # header; those are hand-managed deployment controls if needed.
        lines.append("")
        lines.append("[mcp_sidecar]")
        lines.append("enable = true")
        for key in (
            "upstream_url",
            "upstream_token_env",
            "require_shield",
            "max_calls_per_window",
            "budget_window_seconds",
            "listen_host",
            "listen_port",
        ):
            if key in sidecar:
                _emit_kv(lines, key, sidecar[key])
        tool_rows = sidecar.get("tools")
        if isinstance(tool_rows, dict):
            for name, spec in sorted(tool_rows.items()):
                if (
                    not isinstance(name, str)
                    or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", name)
                    or "__" in name
                    or not isinstance(spec, dict)
                ):
                    continue
                lines.append("")
                lines.append(f"[mcp_sidecar.tools.{_toml_key(name)}]")
                _emit_kv(lines, "risk", spec.get("risk", "high"))
                _emit_kv(
                    lines,
                    "description",
                    spec.get("description", "Reviewed governed MCP tool"),
                )
                # Schema authoring is deliberately bounded in the wizard. A
                # stricter reviewed schema can be edited into config later.
                lines.append('input_schema = { type = "object", properties = {} }')
                tags = spec.get("obligation_tags")
                if isinstance(tags, list) and all(isinstance(tag, str) for tag in tags):
                    _emit_kv(lines, "obligation_tags", tags)
    if advanced.get("repl"):
        lines.append("")
        lines.append("[repl]")
        lines.append("enable = true")
    if advanced.get("harness_refine"):
        lines.append("")
        lines.append("[harness_refine]")
        lines.append("enable = true")
        # require_approval defaults ON (a proposal must never self-apply), so
        # only an explicit decline is written.
        if advanced.get("harness_refine_require_approval") is False:
            lines.append("require_approval = false")
    # Forking defaults ON (lineage only, no execution); only a decline writes.
    if advanced.get("session_tree") is False:
        lines.append("")
        lines.append("[session_tree]")
        lines.append("enable = false")
    if advanced.get("memory_guard"):
        lines.append("")
        lines.append("[memory_guard]")
        lines.append("enable = true")
    if advanced.get("temporal_memory") or advanced.get("fact_tags"):
        lines.append("")
        lines.append("[memory]")
        if advanced.get("temporal_memory"):
            lines.append("temporal = true")
        if advanced.get("fact_tags"):
            lines.append("fact_tags = true")
    return lines


def _cfg_advanced_governance_monitors(advanced: dict[str, Any]) -> list[str]:
    """The governance and compliance monitor sections."""
    lines: list[str] = []
    if advanced.get("fairness_monitor"):
        lines.append("")
        lines.append("[fairness_monitor]")
        lines.append("enable = true")
    if advanced.get("drift_monitoring"):
        lines.append("")
        lines.append("[drift_monitoring]")
        lines.append("enable = true")
    if advanced.get("ai_incident_reporting"):
        lines.append("")
        lines.append("[ai_incident_reporting]")
        lines.append("enable = true")
    if advanced.get("eu_conformity"):
        lines.append("")
        lines.append("[eu_conformity]")
        lines.append("enable = true")
    if advanced.get("explainability"):
        lines.append("")
        lines.append("[explainability]")
        lines.append("enable = true")
    if advanced.get("content_provenance"):
        lines.append("")
        lines.append("[content_provenance]")
        lines.append("enable = true")
    if advanced.get("llm_gateway"):
        lines.append("")
        lines.append("[llm_gateway]")
        lines.append("enable = true")
        lines.append('upstream_url = "https://api.openai.com"')
        lines.append("screen_prompts = true")
        lines.append("redact_prompts = true")
        lines.append("redact_completions = true")
    if advanced.get("vendor_management"):
        lines.append("")
        lines.append("[vendor_management]")
        lines.append("enable = true")
    if advanced.get("consent_registry"):
        lines.append("")
        lines.append("[consent_registry]")
        lines.append("enable = true")
        lines.append(f'subject_salt = "{_prior_consent_salt()}"')
    if advanced.get("data_map"):
        lines.append("")
        lines.append("[data_map]")
        lines.append("enable = true")
    if advanced.get("breach_notification"):
        lines.append("")
        lines.append("[breach_notification]")
        lines.append("enable = true")
    if advanced.get("ediscovery"):
        lines.append("")
        lines.append("[ediscovery]")
        lines.append("enable = true")
    if advanced.get("dsar_fulfillment"):
        lines.append("")
        lines.append("[dsar_fulfillment]")
        lines.append("enable = true")
    if advanced.get("grc_sync"):
        lines.append("")
        lines.append("[grc_sync]")
        lines.append("enable = true")
    if advanced.get("agent_topology"):
        lines.append("")
        lines.append("[agent_topology]")
        lines.append("enable = true")
    if advanced.get("governance_inventory"):
        lines.append("")
        lines.append("[governance_inventory]")
        lines.append("enable = true")
        lines.append("retention_seconds = 31536000")
        lines.append("max_source_records = 10000")
        lines.append("max_entities = 20000")
        lines.append("max_relationships = 40000")
        lines.append("max_export_bytes = 10485760")
        lines.append("max_snapshots = 10000")
    # Discipline defaults ON; only an explicit decline is written.
    if advanced.get("specialist_discipline") is False:
        lines.append("")
        lines.append("[domains]")
        lines.append("discipline = false")
    return lines


def _cfg_advanced_dreaming_and_tax(advanced: dict[str, Any]) -> list[str]:
    """``[dreaming]`` and the signed tax-constants channel."""
    lines: list[str] = []
    if advanced.get("dreaming"):
        lines.append("")
        lines.append("[dreaming]")
        lines.append("enable = true")
        if advanced.get("dreaming_llm_consolidation"):
            lines.append("llm_consolidation = true")
        keys = advanced.get("insight_pubkeys") or []
        if keys:
            # Free-text user input: route through _emit_kv so each key is
            # escaped via _toml_str (a key with a quote/backslash would
            # otherwise corrupt the config the wizard writes).
            _emit_kv(lines, "trusted_insight_pubkeys", keys)
    if advanced.get("tax_update_url") or advanced.get("tax_pubkeys"):
        lines.append("")
        lines.append("[tax]")
        lines.append("auto_update = true")
        if advanced.get("tax_update_url"):
            # User-entered free text: escape via _toml_str so a URL with a
            # backslash or quote can't corrupt the config the wizard writes.
            _emit_kv(lines, "update_url", advanced["tax_update_url"])
        tax_keys = advanced.get("tax_pubkeys") or []
        if tax_keys:
            # Same escaping concern as the insight pubkeys above.
            _emit_kv(lines, "trusted_constants_pubkeys", tax_keys)
    return lines


def _cfg_advanced_runtime_and_tools(advanced: dict[str, Any], providers: list[str]) -> list[str]:
    """Effort, caches, tool exposure, shield updates, eBPF, local runtime and local-first."""
    lines: list[str] = []
    if advanced.get("effort"):
        lines.append("")
        lines.append("[effort]")
        lines.append("enabled = true")
    if advanced.get("cache_prewarm"):
        lines.append("")
        lines.append("[cache]")
        lines.append("prewarm = true")
    if advanced.get("hedge_requests"):
        lines.append("")
        lines.append("[latency]")
        lines.append("hedge_ms = 1500")
    tool_lines: list[str] = []
    if advanced.get("tool_exposure") == "full":
        tool_lines.append('exposure = "full"')
    if advanced.get("output_cache"):
        tool_lines.append("output_cache = true")
    if advanced.get("hardware_sensors"):
        tool_lines.append("hardware_sensors = true")
    if tool_lines:
        lines.append("")
        lines.append("[tools]")
        lines.extend(tool_lines)
    if advanced.get("shield_updates"):
        lines.append("")
        lines.append("[shield]")
        lines.append("federated_updates = true")
        lines.append('# update_url    = "https://..."  # REQUIRED')
        lines.append('# update_pubkey = "<ed25519 hex>"  # REQUIRED')
    if advanced.get("ebpf_monitor"):
        lines.append("")
        lines.append("[ebpf_monitor]")
        lines.append("enable = true")
    if advanced.get("local_runtime"):
        lines.append("")
        lines.append("[local_runtime]")
        lines.append("enabled = true")
        lines.append('# engine = "vllm"  # vllm | tgi | llamacpp')
        lines.append('# model  = "..."   # REQUIRED before `maverick local-runtime plan`')
    if advanced.get("local_first"):
        lines.append("")
        lines.append("[system]")
        lines.append("local_first = true")
        local_model = _local_first_model(providers)
        if local_model:
            lines.append("")
            lines.append("[local_first]")
            _emit_kv(lines, "model", local_model)
    return lines


def _cfg_advanced_oidc(advanced: dict[str, Any]) -> list[str]:
    """``[auth.oidc]`` for SSO ID-token verification and the browser login flow."""
    lines: list[str] = []
    oidc = advanced.get("oidc") or {}
    if isinstance(oidc, dict) and oidc.get("enabled"):
        for key in ("issuer", "jwks_uri"):
            _require_secure_url(str(oidc.get(key, "")), f"OIDC {key}")
        if not (isinstance(oidc.get("audience"), str) and oidc["audience"].strip()):
            raise ValueError("Enabled OIDC requires an audience.")
        browser_fields = ("client_id", "client_secret", "redirect_uri", "session_secret")
        if any(oidc.get(key) for key in browser_fields) and not (
            all(isinstance(oidc.get(key), str) and oidc[key].strip() for key in browser_fields)
            and _secure_or_loopback_url(str(oidc["redirect_uri"]))
            and len(str(oidc["session_secret"]).strip()) >= 32
        ):
            raise ValueError("OIDC browser login requires all fields and a session secret of at least 32 characters.")
        # SSO ID-token verification for `maverick serve`. Its own table
        # (written once), so no duplicate-[auth.oidc] bug. The kernel reads
        # it via maverick.oidc.oidc_enabled() / load_oidc_config().
        lines.append("")
        lines.append("[auth.oidc]")
        lines.append("enabled = true")
        _emit_kv(lines, "issuer", oidc.get("issuer", ""))
        _emit_kv(lines, "audience", oidc.get("audience", ""))
        _emit_kv(lines, "jwks_uri", oidc.get("jwks_uri", ""))
        # Built-in browser-login fields, written ONLY when the operator
        # opted into that flow (so a bearer-only OIDC config is unchanged).
        # The kernel's login_enabled() additionally gates the routes.
        for key in (
            "client_id",
            "client_secret",
            "redirect_uri",
            "session_secret",
        ):
            val = oidc.get(key)
            if val:
                _emit_kv(lines, key, val)
    return lines


def _cfg_advanced_dashboard(advanced: dict[str, Any]) -> list[str]:
    """The single ``[dashboard]`` table and its group-role/suite sub-tables."""
    lines: list[str] = []
    dept = advanced.get("department_access") or {}
    compress_off = advanced.get("dashboard_compress") is False
    glass_on = advanced.get("dashboard_glass") is True
    navigation_lines = {key: value for key, value in (
        ("navigation", "areas" if advanced.get("dashboard_navigation") == "areas" else None),
        ("navigation_personal", True if advanced.get("dashboard_navigation_personal") is True else None),
    ) if value is not None}
    api_keys = advanced.get("api_keys") if isinstance(advanced.get("api_keys"), dict) else {}
    # Only a deliberate change is written: the app's defaults (on, 90 / 365
    # days, 24 hours) apply when the table says nothing.
    api_key_lines = {k: v for k, v in api_keys.items()
                     if k in ("api_key_default_days", "api_key_max_days",
                              "api_key_rotation_grace_hours")}
    if api_keys.get("api_keys") is False:
        api_key_lines = {"api_keys": False}
    if isinstance(dept, dict) and (
        "default_suites" in dept or "default_role" in dept or dept.get("group_roles") or dept.get("group_suites")
        or "local_owner_setup" in advanced or compress_off or glass_on or navigation_lines or api_key_lines
        or "employee_activation_jobs" in advanced or "extension_form_values" in advanced
        or "extension_page_structure" in advanced
    ):
        # Department (job-function) scoping for signed-in users. default_suites
        # is deny-by-default for users with no explicit grant; the group tables
        # turn IdP (SCIM) team membership into a role / department grant.
        lines.append("")
        lines.append("[dashboard]")
        if "employee_activation_jobs" in advanced:
            _emit_kv(lines, "employee_activation_jobs", advanced["employee_activation_jobs"])
        for capture_key in ("extension_form_values", "extension_page_structure"):
            if capture_key in advanced:
                _emit_kv(lines, capture_key, advanced[capture_key] is True)
        if "local_owner_setup" in advanced:
            _emit_kv(lines, "local_owner_setup", advanced["local_owner_setup"] is True)
        if compress_off:
            # Default-on in the app; only a deliberate "no" is written.
            lines.append("# Response compression off: a proxy in front already compresses.")
            _emit_kv(lines, "compress", False)
        if glass_on:
            # Default-off in the app; only a deliberate "yes" is written.
            lines.append("# Glass effects for everyone until people choose their own.")
            _emit_kv(lines, "glass", "on")
        if navigation_lines:
            # Default classic, chosen by nobody; only a deliberate "yes" is written.
            lines.append("# The job-named sidebar (areas), for everyone or for people who choose it.")
            for key, value in navigation_lines.items():
                _emit_kv(lines, key, value)
        if api_key_lines:
            lines.append("# API keys for scripts and integrations (maverick.config.api_key_settings).")
            for key in ("api_keys", "api_key_default_days", "api_key_max_days",
                        "api_key_rotation_grace_hours"):
                if key in api_key_lines:
                    _emit_kv(lines, key, api_key_lines[key])
        if "default_role" in dept:
            _emit_kv(lines, "default_role", dept["default_role"])
        if "default_suites" in dept:
            lines.append("# Departments a signed-in user may use until an admin grants more.")
            _emit_kv(lines, "default_suites", list(dept["default_suites"]))
        # Group names contain spaces, so the TOML key must be a quoted string
        # ("Finance Team" = ...), not the bare key _emit_kv would render.
        if dept.get("group_roles"):
            lines.append("")
            lines.append("[dashboard.group_roles]")
            for group, role in dept["group_roles"].items():
                lines.append(f"{_toml_str(group)} = {_toml_str(role)}")
        if dept.get("group_suites"):
            lines.append("")
            lines.append("[dashboard.group_suites]")
            for group, suites in dept["group_suites"].items():
                rendered = ", ".join(_toml_str(s) for s in suites)
                lines.append(f"{_toml_str(group)} = [{rendered}]")
    return lines


def _cfg_advanced_saml_and_sign_in(advanced: dict[str, Any]) -> list[str]:
    """``[auth.saml]`` template and the session, MFA, owner TOTP and IP allowlist tables."""
    lines: list[str] = []
    if advanced.get("saml"):
        lines.append("")
        # The ordinary guided setup supplies real values and separately reviews
        # activation. An installer template must never disable owner sign-in.
        lines.append("[auth.saml]")
        lines.append("enabled = false")
        lines.append('sp_entity_id = "https://YOUR-HOST/saml/metadata"')
        lines.append('acs_url = "https://YOUR-HOST/saml/acs"')
        lines.append('idp_metadata_url = "https://IDP/app/metadata"   # or idp_metadata_file')
        lines.append("# want_assertions_signed = true")
        lines.append('# sp_cert_file = ""   # to sign AuthnRequests / decrypt')
        lines.append('# sp_key_file = ""')
    security = advanced.get("sign_in_security") or {}
    if isinstance(security, dict) and any(key in security for key in ("company_hours", "idle_minutes")):
        lines.append("")
        lines.append("[auth.sessions]")
        for key in ("company_hours", "idle_minutes"):
            if key in security:
                _emit_kv(lines, key, int(security[key]))
    if isinstance(security, dict) and security.get("require"):
        # Second factor at sign-in + step-up for sensitive actions. Read by
        # maverick.config.get_auth_mfa (the dashboard's mfa_policy).
        lines.append("")
        lines.append("[auth.mfa]")
        lines.append("require = true")
        _emit_kv(lines, "step_up_minutes", int(security.get("step_up_minutes") or 15))
    if isinstance(security, dict) and security.get("local_owner_totp") in {"required", "off"}:
        # The owner's authenticator app at local sign-in. Read by
        # maverick.config.get_auth_local_owner_totp (the dashboard's owner sign-in).
        lines.append("")
        lines.append("[auth.local_owner]")
        _emit_kv(lines, "totp", str(security["local_owner_totp"]))
    if isinstance(security, dict) and security.get("cidrs"):
        # Network addresses allowed to reach the dashboard. Read by
        # maverick.config.get_ip_allowlist (the dashboard's ip_allowlist).
        lines.append("")
        lines.append("[auth.ip_allowlist]")
        _emit_kv(lines, "cidrs", [str(c) for c in security["cidrs"]])
    return lines
