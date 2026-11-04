from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


def test_wizard_enrolls_exact_supplywisdom_and_iss_hosts(monkeypatch) -> None:
    from maverick.config_lint import lint_config
    from maverick_installer import wizard

    enabled_prompts = (
        "Enable the provider-neutral Third-Party Management intelligence",
        "Enable the bounded third-party intelligence provider runtime",
        "Enable the SupplyWisdom normalized reference contract",
        "Enable the ISS Corporate Solutions normalized reference contract",
        "Enable scheduled third-party provider collection",
    )

    def confirm(prompt: str, *args, **kwargs) -> bool:
        del args, kwargs
        return prompt.startswith(enabled_prompts)

    def text(prompt: str, *args, **kwargs) -> str:
        del args, kwargs
        if "SupplyWisdom" in prompt:
            return "Tenant.SupplyWisdom.Example "
        if "ISS Corporate Solutions" in prompt:
            return "TENANT.ISS-CORPORATE-SOLUTIONS.EXAMPLE"
        raise AssertionError(prompt)

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(wizard, "_q_text", text)

    selected = wizard.pick_security_suite()
    providers = selected["third_party_management"]["intelligence"]["providers"]
    assert providers == {
        "enable": True,
        "enabled_providers": [
            "riskrecon",
            "securityscorecard",
            "hacknotice",
            "supplywisdom",
            "iss_corporate_solutions",
        ],
        "supplywisdom_host": "tenant.supplywisdom.example",
        "iss_corporate_solutions_host": (
            "tenant.iss-corporate-solutions.example"
        ),
        "timeout_seconds": 20,
        "scheduler": {"enable": True, "poll_seconds": 900},
    }

    rendered = tomllib.loads("\n".join(wizard._cfg_security_suite(selected)))
    assert rendered["third_party_management"]["intelligence"]["providers"] == providers
    assert lint_config(rendered) == []
