"""Organization-owned ceilings for the allowlisted preference hierarchy."""
from __future__ import annotations


def entries(S, C, Column):
    from maverick.experience_preferences import DEFAULTS, PERSONAL_ONLY
    from maverick.persona import style_choices
    from maverick.styles import BUILTIN_STYLES

    common = {"group": "People & access", "reader": "maverick.experience_preferences",
              "subgroup": "Personal preference policy"}
    choices = tuple((key, key.replace("_", " ").capitalize())
                    for key in sorted(DEFAULTS.keys() - PERSONAL_ONLY))
    result = [S("personalization", "locked_fields", "Preferences controlled by organization policy",
                "Choose which presentation preferences members and workspace administrators cannot override. "
                "An unlisted preference can follow organization, workspace, personal and conversation defaults. "
                "Names, pins and notification windows always belong to the individual.",
                "multiselect", default=[], choices=choices, max_items=len(choices),
                weaker="change", warning="This changes which presentation choices members may override.",
                aliases="personal workspace organization inheritance locked preference policy", **common)]
    options = {
        "tone": style_choices(),
        "language": (("en", "English"), ("fr", "French"), ("de", "German"), ("ja", "Japanese"), ("ar", "Arabic"), ("zh", "Chinese")),
        "verbosity": (("brief", "Brief"), ("balanced", "Balanced"), ("detailed", "Detailed")),
        "output_style": (("", "Ordinary response style"), *tuple((key, key.capitalize()) for key in BUILTIN_STYLES), ("custom", "Required named style")),
        "font": (("default", "Default"), ("dyslexic", "Dyslexia-friendly")),
        "density": (("comfortable", "Comfortable"), ("compact", "Compact")),
        "text_size": (("standard", "Standard"), ("large", "Large"), ("larger", "Larger")),
        "glass": (("off", "Off"), ("on", "On")),
    }
    for key, _label in choices:
        extra = {"choices_from": "preference_themes"} if key == "theme" else {"choices": options[key]} if key in options else {"max_length": 2000 if key == "custom_style" else 80}
        result.append(S("personalization.defaults", key, "Required " + key.replace("_", " "),
                        "Used only when this preference is controlled by organization policy above. "
                        "These choices change presentation, never tools, memory collection, retention or approval permissions.",
                        "select" if key in options or key == "theme" else "text", default=DEFAULTS[key],
                        **extra, **common))
    from maverick.product_operation_families import FAMILIES
    result.append(S("copilot", "operation_families", "Actions available through Copilot",
                    "Choose which registered native controls Copilot can open. Controls that only show "
                    "current status work as soon as their family is chosen. Controls that change something "
                    "also need Copilot actions turned on in Features, current access, a fresh before-and-after "
                    "review and explicit confirmation. A family with no adapter on a page adds no capability.",
                    "multiselect", "People & access", ["learning"], "maverick_dashboard.product_operations",
                    subgroup="Copilot actions", max_items=len(FAMILIES),
                    choices=tuple((name, name.capitalize()) for name in FAMILIES),
                    weaker="grow", warning="More native controls will be available through Copilot."))
    result.append(S("settings", "runtime_status", "Show configuration startup acknowledgements",
                    "Compare saved settings with the configuration acknowledged by running dashboard, worker, "
                    "channel and gRPC processes sharing this data folder. Stale or missing acknowledgements stay "
                    "unconfirmed. This reports startup configuration, separately from service health.",
                    "toggle", "People & access", True, "maverick.runtime_configuration", subgroup="Configuration status"))
    from maverick.config import EMPLOYEE_ACTIVATION_JOBS
    result.append(S("dashboard", "employee_activation_jobs", "Approved first-task guides",
                    "Choose the first-task guides this installation offers. Workspace choices may only narrow this catalog. Role selection never grants a department or tools; disabled departments remain hidden.",
                    "multiselect", "People & access", list(EMPLOYEE_ACTIVATION_JOBS), "maverick.config",
                    choices=tuple(EMPLOYEE_ACTIVATION_JOBS.items()), max_items=len(EMPLOYEE_ACTIVATION_JOBS),
                    weaker="grow", warning="Additional guided tasks become available within each person's existing access."))
    return result


REQUIRES_VALUE = {("personalization.defaults.output_style", "custom"): ("personalization.defaults.custom_style",)}
