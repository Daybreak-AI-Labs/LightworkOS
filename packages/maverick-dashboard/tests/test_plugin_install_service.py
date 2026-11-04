"""POST /plugins/install — one-click install of an operator-allowlisted plugin
package, quad-gated (same-origin + MAVERICK_ALLOW_PLUGIN_INSTALL + admin +
allowlist). The pip work itself is covered in core test_plugin_install."""
from __future__ import annotations

from fastapi.testclient import TestClient
from maverick_dashboard.app import app

client = TestClient(app, base_url="http://127.0.0.1", headers={"Origin": "http://127.0.0.1"})


def test_install_blocked_without_opt_in(monkeypatch):
    monkeypatch.delenv("MAVERICK_ALLOW_PLUGIN_INSTALL", raising=False)
    called = []
    monkeypatch.setattr("maverick.plugins.install_plugin", lambda n: called.append(n))
    r = client.post("/plugins/install", data={"name": "approved-pkg"}, follow_redirects=False)
    assert r.status_code == 403
    assert called == []                       # never reached the installer


def test_install_runs_when_opted_in(monkeypatch):
    monkeypatch.setenv("MAVERICK_ALLOW_PLUGIN_INSTALL", "1")
    called = []
    monkeypatch.setattr("maverick.plugins.install_plugin",
                        lambda n: called.append(n) or {"tools": [], "channels": [], "skills": [], "personas": []})
    r = client.post("/plugins/install", data={"name": "approved-pkg"}, follow_redirects=False)
    assert r.status_code == 303                # redirect back to /plugins
    assert r.headers["location"] == "/plugins"
    assert called == ["approved-pkg"]


def test_install_surfaces_core_validation_error(monkeypatch):
    monkeypatch.setenv("MAVERICK_ALLOW_PLUGIN_INSTALL", "1")

    def boom(name):
        raise ValueError("'evil' is not on the [plugins] installable allowlist")

    monkeypatch.setattr("maverick.plugins.install_plugin", boom)
    r = client.post("/plugins/install", data={"name": "evil"}, follow_redirects=False)
    assert r.status_code == 400
    assert "allowlist" in r.json()["detail"]


def test_page_shows_install_section_when_allowlisted(tmp_path, monkeypatch):
    from maverick import world_model
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setattr("maverick.plugins.installable_plugins", lambda: ["acme-maverick-tools"])
    t = client.get("/plugins").text
    assert "acme-maverick-tools" in t
    assert "Install a plugin" in t
    # Approvals are a checklist of the current list plus one new-name field.
    assert 'type="checkbox" name="names" value="acme-maverick-tools" checked' in t
    assert "<textarea" not in t


def _isolate_config(tmp_path, monkeypatch):
    from maverick import config

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("MAVERICK_ALLOW_PLUGIN_INSTALL", raising=False)
    config.reset_config_cache()
    return config


def test_install_opt_in_via_config_switch(tmp_path, monkeypatch):
    """[plugins] allow_install is the in-app path to the install opt-in --
    no env var, no shell."""
    _isolate_config(tmp_path, monkeypatch)
    called = []
    monkeypatch.setattr("maverick.plugins.install_plugin",
                        lambda n: called.append(n) or {})
    r = client.post("/plugins/install-switch", data={"enabled": "on"},
                    follow_redirects=False)
    assert r.status_code == 303
    r = client.post("/plugins/install", data={"name": "approved-pkg"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert called == ["approved-pkg"]


def test_env_falsy_force_disables_despite_config(tmp_path, monkeypatch):
    """A hardened deployment pins installs off: an explicit falsy env value
    outranks the in-app switch in the OFF direction."""
    _isolate_config(tmp_path, monkeypatch)
    from maverick_dashboard import settings_store

    settings_store.set_plugin_install_allowed(True)
    monkeypatch.setenv("MAVERICK_ALLOW_PLUGIN_INSTALL", "0")
    called = []
    monkeypatch.setattr("maverick.plugins.install_plugin", lambda n: called.append(n))
    r = client.post("/plugins/install", data={"name": "approved-pkg"},
                    follow_redirects=False)
    assert r.status_code == 403
    assert called == []
    # And the page tells the admin the environment pinned it off.
    t = client.get("/plugins").text
    assert "locked off by this server" in t
    assert "MAVERICK_ALLOW_PLUGIN_INSTALL" not in t


def test_approvals_endpoint_writes_the_allowlist(tmp_path, monkeypatch):
    """Admins manage the pre-approved package list on the page itself --
    the old dead end ('no packages approved yet' with no way forward)."""
    _isolate_config(tmp_path, monkeypatch)
    r = client.post(
        "/plugins/approvals",
        data={"names": "acme-maverick-tools\n globex-channel , acme-maverick-tools"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    from maverick.plugins import installable_plugins

    assert installable_plugins() == ["acme-maverick-tools", "globex-channel"]
    # An unsafe name is rejected at approval time, not discovered at install.
    r = client.post("/plugins/approvals", data={"names": "evil pkg==1.0"},
                    follow_redirects=False)
    assert r.status_code == 400
    assert installable_plugins() == ["acme-maverick-tools", "globex-channel"]
    # Clearing fails closed.
    r = client.post("/plugins/approvals", data={"names": ""}, follow_redirects=False)
    assert r.status_code == 303
    assert installable_plugins() == []


def test_approvals_accept_ticked_boxes_plus_one_new_name(tmp_path, monkeypatch):
    """The page posts one `names` value per ticked box plus the new name;
    unticked names drop off the list, and an unsafe new name is refused."""
    _isolate_config(tmp_path, monkeypatch)
    r = client.post(
        "/plugins/approvals",
        data={"names": ["acme-maverick-tools", "globex-channel", ""]},
        follow_redirects=False,
    )
    assert r.status_code == 303
    from maverick.plugins import installable_plugins

    assert installable_plugins() == ["acme-maverick-tools", "globex-channel"]
    r = client.post("/plugins/approvals", data={"names": ["globex-channel", "bad;rm"]},
                    follow_redirects=False)
    assert r.status_code == 400
    assert installable_plugins() == ["acme-maverick-tools", "globex-channel"]
    r = client.post("/plugins/approvals", data={"names": ["globex-channel"]},
                    follow_redirects=False)
    assert r.status_code == 303
    assert installable_plugins() == ["globex-channel"]


def test_approvals_and_switch_require_admin(tmp_path, monkeypatch):
    _isolate_config(tmp_path, monkeypatch)
    import maverick_dashboard.auth as auth

    monkeypatch.setattr(auth, "caller_principal", lambda request: "user:viewer")
    monkeypatch.setattr(auth, "role_for_principal", lambda principal: "viewer")
    monkeypatch.setattr(auth, "global_role_for_principal", lambda principal: "viewer")
    assert client.post("/plugins/approvals", data={"names": "x"},
                       follow_redirects=False).status_code == 403
    assert client.post("/plugins/install-switch", data={"enabled": "on"},
                       follow_redirects=False).status_code == 403


def test_plugin_install_settings_wait_for_approval_under_a_quorum(tmp_path, monkeypatch):
    """[plugins] is protected by the settings quorum: the Plugins page's
    switch and allowlist wait for other administrators like All settings."""
    from maverick import world_model

    config = _isolate_config(tmp_path, monkeypatch)
    monkeypatch.setattr(world_model, "DEFAULT_DB", tmp_path / "world.db")
    monkeypatch.setenv("MAVERICK_QUORUM_REQUIRED", "2")
    r = client.post("/plugins/install-switch", data={"enabled": "on"},
                    follow_redirects=False)
    assert r.status_code == 202, r.text
    r = client.post("/plugins/approvals", data={"names": ["acme-tools"]},
                    follow_redirects=False)
    assert r.status_code == 202, r.text
    config.reset_config_cache()
    plugins = config.load_config().get("plugins") or {}
    assert "allow_install" not in plugins and "installable" not in plugins
