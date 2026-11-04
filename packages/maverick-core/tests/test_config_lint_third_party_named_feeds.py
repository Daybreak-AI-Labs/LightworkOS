from __future__ import annotations

from copy import deepcopy

from maverick.config_lint import lint_config


def _config() -> dict[str, object]:
    return {
        "third_party_management": {
            "enable": True,
            "intelligence": {
                "enable": True,
                "providers": {
                    "enable": True,
                    "enabled_providers": [
                        "supplywisdom",
                        "iss_corporate_solutions",
                    ],
                    "supplywisdom_host": "tenant.supplywisdom.example",
                    "iss_corporate_solutions_host": (
                        "tenant.iss-corporate-solutions.example"
                    ),
                    "timeout_seconds": 20,
                    "scheduler": {"enable": True, "poll_seconds": 900},
                },
            },
        }
    }


def _messages(config: dict[str, object]) -> list[str]:
    return [finding.message for finding in lint_config(config)]


def test_named_provider_hosts_are_closed_exact_and_enable_bound() -> None:
    assert lint_config(_config()) == []

    missing = deepcopy(_config())
    del missing["third_party_management"]["intelligence"]["providers"][  # type: ignore[index]
        "supplywisdom_host"
    ]
    assert any(
        "supplywisdom requires one exact deployment-trusted hostname" in message
        for message in _messages(missing)
    )

    malformed = deepcopy(_config())
    malformed["third_party_management"]["intelligence"]["providers"][  # type: ignore[index]
        "iss_corporate_solutions_host"
    ] = "https://tenant.iss.example/path"
    assert any(
        "iss_corporate_solutions requires one exact deployment-trusted hostname"
        in message
        for message in _messages(malformed)
    )

    disabled = deepcopy(_config())
    providers = disabled["third_party_management"]["intelligence"]["providers"]  # type: ignore[index]
    providers["enabled_providers"] = ["supplywisdom"]
    assert any(
        "iss_corporate_solutions_host cannot be set" in message
        for message in _messages(disabled)
    )


def test_all_named_and_generic_provider_ids_are_accepted_only_once() -> None:
    config = _config()
    providers = config["third_party_management"]["intelligence"]["providers"]  # type: ignore[index]
    providers["enabled_providers"] = [
        "riskrecon",
        "securityscorecard",
        "hacknotice",
        "supplywisdom",
        "iss_corporate_solutions",
        "generic_approved",
    ]
    providers["generic_approved_host"] = "tenant.generic-feed.example"
    assert lint_config(config) == []

    providers["enabled_providers"].append("supplywisdom")
    assert any("unique closed provider list" in message for message in _messages(config))
