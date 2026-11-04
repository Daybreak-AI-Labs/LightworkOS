"""Content-free memory posture alongside scoped presentation preferences."""
from __future__ import annotations

from maverick import config, personal_identity, personal_memory

from . import auth


def describe(request):
    """Project current native memory controls; never infer a channel identity."""
    principal = auth.caller_principal(request)
    result = {"available": False, "policy": "Unavailable", "source": "Administrator memory policy",
              "scopes": [], "sharing": "Channel-only unless you explicitly choose a verified shared source",
              "message": "Sign in with a named current workspace account to review personal memory."}
    if not principal or not personal_identity.principal_current(principal):
        return result
    if config.config_source_errors(include_tenant=True):
        result["message"] = "Current administrator memory policy could not be confirmed. Open My data after configuration is restored."
        return result
    allowed = config.get_dreaming().get("user_notes") is True
    result["policy"] = "Personal recall allowed within your choices" if allowed else "Personal recall disabled by administrator policy"
    if not personal_identity.enabled():
        result["message"] = "My data controls are disabled. Ask an administrator to enable Personal data controls. Previously saved personal recall restrictions remain enforced."
        return result
    try:
        scopes = personal_memory.owned_scopes(principal)
        profile = personal_memory.profile(principal)
        selected = next((scope for scope in scopes if scope["id"] == profile["shared_source"]), None)
        source_control = personal_memory.controls(selected["channel"], selected["user_id"]) if selected else None
        rows = []
        counts = {}
        for scope in scopes:
            channel = scope["channel"]
            counts[channel] = counts.get(channel, 0) + 1
            label = "This dashboard account" if channel == "dashboard" else f"Verified {channel.replace('_', ' ').capitalize()} account {counts[channel]}"
            control = personal_memory.controls(channel, scope["user_id"])
            effective = allowed and control["recall"] is True and (source_control is None or source_control["recall"] is True)
            rows.append({"label": label, "channel_label": channel.replace('_', ' ').capitalize() if channel != "dashboard" else None,
                         "account_number": counts[channel] if channel != "dashboard" else None,
                         "choice": "Allow within administrator policy" if control["recall"] else "Recall and collection off",
                         "effective": "Allowed" if effective else "Off",
                         "source": "Your saved channel choice" if control["revision"] else "Product default, constrained by administrator policy"})
        if not personal_identity.principal_current(principal):
            return result
        result.update(available=True, scopes=rows,
                      sharing="One explicitly chosen verified source supplies shared preferences" if selected else "Channel-only preferences",
                      message="These choices apply only to your verified account scopes. Use My data to narrow recall, inspect sources, reset sharing to channel-only, or change an individual channel choice. Tools, companion policy and retention remain separate.")
    except (ValueError, OSError, RuntimeError):
        result["message"] = "Saved personal memory choices could not be confirmed. Open My data to review current state before changing them."
    return result
