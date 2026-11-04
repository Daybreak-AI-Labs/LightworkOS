"""`maverick onboard` CLI: generate + approve + save a domain pack (CliRunner).

Imports maverick.cli (the full kernel + click), so it runs in CI. Uses
``--no-llm`` for deterministic, network-free generation.
"""
from __future__ import annotations


def test_onboard_generates_and_activates(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main

    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    doc = tmp_path / "policy.txt"
    doc.write_text("We ship within two business days.")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["onboard", "--no-llm", "--name", "Acme Co", "--doc", str(doc), "--yes"],
        input="an online store\nretail\n",  # description + industry prompts
    )
    assert result.exit_code == 0, result.output
    assert "Activated" in result.output

    from maverick.domain import available_domains
    domains = available_domains()
    assert "acme_co" in domains
    assert domains["acme_co"].compartment == "acme_co"


def test_onboard_discards_without_approval(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick.cli import main

    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.delenv("MAVERICK_DOMAINS_DIR", raising=False)
    monkeypatch.delenv("MAVERICK_TENANT", raising=False)
    doc = tmp_path / "policy.txt"
    doc.write_text("Beta Co's private retention schedule is confidential.")

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["onboard", "--no-llm", "--name", "Beta Co", "--doc", str(doc)],
        # description, industry (blank), decline
        input="a logistics firm\n\nn\n",
    )
    assert result.exit_code == 0, result.output
    assert "Discarded" in result.output

    from maverick.domain import available_domains

    assert "beta_co" not in available_domains()  # nothing saved without a yes


def test_onboard_respects_disabled_knowledge_without_importing(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    from click.testing import CliRunner
    from maverick.cli import main

    def fail(*_args, **_kwargs):
        raise AssertionError("knowledge layer should not be constructed when disabled")

    fake_knowledge = SimpleNamespace(
        KnowledgeBase=fail,
        build_embedder=fail,
        build_store=fail,
    )
    cfg = tmp_path / "config.toml"
    cfg.write_text("[knowledge]\nenable = false\n")
    doc = tmp_path / "secret.txt"
    doc.write_text("SECRET SHOULD NOT BE INGESTED")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setitem(sys.modules, "maverick_knowledge", fake_knowledge)

    result = CliRunner().invoke(
        main,
        ["onboard", "--no-llm", "--name", "Gamma Co", "--doc", str(doc)],
        input="a services firm\n\nn\n",
    )

    assert result.exit_code == 0, result.output
    # The warning must be actionable: name that the attached doc was NOT
    # loaded and how to enable knowledge.
    assert "knowledge is disabled" in result.output
    assert "were NOT loaded" in result.output
    assert "[knowledge] enable = true" in result.output
    assert "Discarded" in result.output


def test_onboard_decline_defers_enabled_knowledge_ingestion(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    from click.testing import CliRunner
    from maverick.cli import main

    ingested = []

    class FakeKnowledgeBase:
        def __init__(self, store, embedder, shield=None):
            self.store = store
            self.embedder = embedder
            self.shield = shield

        def ingest_path(self, collection, path, **kwargs):
            # Provenance kwargs (ingested_by, subject, …) are passed by
            # intake.ingest_docs; the double records the call and accepts them.
            ingested.append((collection, path))
            return 1

    fake_knowledge = SimpleNamespace(
        KnowledgeBase=FakeKnowledgeBase,
        build_embedder=lambda _cfg: object(),
        build_store=lambda _cfg: object(),
    )
    cfg = tmp_path / "config.toml"
    cfg.write_text("[knowledge]\nenable = true\nembedder = \"deterministic\"\n")
    doc = tmp_path / "secret.txt"
    doc.write_text("SECRET SHOULD NOT BE INGESTED BEFORE APPROVAL")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setitem(sys.modules, "maverick_knowledge", fake_knowledge)

    result = CliRunner().invoke(
        main,
        ["onboard", "--no-llm", "--name", "Delta Co", "--doc", str(doc)],
        input="a services firm\n\nn\n",
    )

    assert result.exit_code == 0, result.output
    assert "Discarded" in result.output
    assert ingested == []


def test_onboard_approval_ingests_enabled_knowledge_then_saves(tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    from click.testing import CliRunner
    from maverick.cli import main

    ingested = []

    class FakeKnowledgeBase:
        def __init__(self, store, embedder, shield=None):
            self.store = store
            self.embedder = embedder
            self.shield = shield

        def ingest_path(self, collection, path, **kwargs):
            # Provenance kwargs (ingested_by, subject, …) are passed by
            # intake.ingest_docs; the double records the call and accepts them.
            ingested.append((collection, path))
            return 1

    fake_knowledge = SimpleNamespace(
        KnowledgeBase=FakeKnowledgeBase,
        build_embedder=lambda _cfg: object(),
        build_store=lambda _cfg: object(),
    )
    cfg = tmp_path / "config.toml"
    cfg.write_text("[knowledge]\nenable = true\nembedder = \"deterministic\"\n")
    doc = tmp_path / "approved.txt"
    doc.write_text("Approved knowledge")
    monkeypatch.setenv("MAVERICK_CONFIG", str(cfg))
    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setitem(sys.modules, "maverick_knowledge", fake_knowledge)

    result = CliRunner().invoke(
        main,
        ["onboard", "--no-llm", "--name", "Epsilon Co", "--doc", str(doc), "--yes"],
        input="a services firm\n\n",
    )

    assert result.exit_code == 0, result.output
    assert "Activated" in result.output
    assert len(ingested) == 1
    assert ingested[0][0].startswith("intake_pending_epsilon_co_")
    assert ingested[0][1] == str(doc)


def test_onboard_cannot_activate_a_new_specialist_while_the_switch_is_on(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick import config
    from maverick.cli import main
    from maverick.domain import available_domains

    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("[agent_tests]\nrequire_for_new_specialists = true\n", encoding="utf-8")
    config.reset_config_cache()
    try:
        result = CliRunner().invoke(main, ["onboard", "--no-llm", "--name", "Acme Co", "--yes"],
                                    input="an online store\nretail\n")
        assert result.exit_code != 0 and "saved check" in result.output, result.output
        assert "acme_co" not in available_domains()
    finally:
        config.reset_config_cache()


def test_learn_demo_cannot_activate_a_new_specialist_while_the_switch_is_on(tmp_path, monkeypatch):
    from click.testing import CliRunner
    from maverick import config
    from maverick.cli import main
    from maverick.domain import available_domains

    monkeypatch.setenv("MAVERICK_DOMAINS_DIR", str(tmp_path / "domains"))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))
    (tmp_path / "config.toml").write_text("[agent_tests]\nrequire_for_new_specialists = true\n", encoding="utf-8")
    config.reset_config_cache()
    demo = tmp_path / "digest.txt"
    demo.write_text("ACTION[email]: send the weekly digest -> ops@example.test\n"
                    "ACTION[email]: send the weekly digest to finance -> finance@example.test\n", encoding="utf-8")
    try:
        result = CliRunner().invoke(main, ["learn-demo", str(demo), "--no-llm", "--yes", "--name", "Weekly Digest"])
        assert result.exit_code != 0 and "saved check" in result.output, result.output
        assert not [name for name in available_domains() if "digest" in name]
    finally:
        config.reset_config_cache()
