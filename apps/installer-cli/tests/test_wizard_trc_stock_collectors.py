from __future__ import annotations

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib


def test_trc_stock_collector_step_selects_closed_adapters_and_renders_gate(monkeypatch):
    from maverick.config_lint import lint_config
    from maverick_installer import wizard

    def confirm(prompt, *_args, **_kwargs):
        return prompt.startswith("Enable Tech Risk & Compliance continuous evidence")

    monkeypatch.setattr(wizard, "_q_confirm", confirm)
    monkeypatch.setattr(
        wizard,
        "_q_checkbox",
        lambda *_args, **_kwargs: ["AWS Security Hub", "GitHub security streams"],
    )
    selected = wizard.pick_security_suite()
    continuous = selected["tech_risk_compliance"]["continuous_evidence"]
    assert continuous["enabled_collectors"] == [
        "local_soc2_v1",
        "aws_security_hub_v1",
        "github_security_v1",
    ]
    assert continuous["stock_collectors"] == {"enable": True, "sources": []}

    rendered = tomllib.loads("\n".join(wizard._cfg_security_suite(selected)))
    assert rendered["tech_risk_compliance"]["continuous_evidence"] == continuous
    assert lint_config(rendered) == []
