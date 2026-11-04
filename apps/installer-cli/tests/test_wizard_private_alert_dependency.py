"""Private alert delivery has a usable identity-linking path after setup."""
from __future__ import annotations

from maverick_installer import wizard


def test_private_delivery_can_turn_on_its_my_data_prerequisite(monkeypatch):
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_args, **_kwargs: True)
    advanced = {"allow_personal_data_controls": False}
    notifications = {"personal_alerts": True, "personal_external": True,
                     "personal_dashboard_url": "https://lightwork.example"}

    wizard._resolve_private_alert_linking(advanced, notifications)

    assert advanced["allow_personal_data_controls"] is True
    assert notifications["personal_external"] is True
    assert "personal_data_controls = true" in wizard._cfg_advanced(advanced, [])


def test_declining_my_data_leaves_in_product_alerts_and_disables_private_delivery(monkeypatch):
    monkeypatch.setattr(wizard, "_q_confirm", lambda *_args, **_kwargs: False)
    advanced = {"allow_personal_data_controls": False}
    notifications = {"personal_alerts": True, "personal_external": True,
                     "personal_dashboard_url": "https://lightwork.example"}

    wizard._resolve_private_alert_linking(advanced, notifications)

    assert advanced["allow_personal_data_controls"] is False
    assert notifications == {"personal_alerts": True, "personal_external": False}
