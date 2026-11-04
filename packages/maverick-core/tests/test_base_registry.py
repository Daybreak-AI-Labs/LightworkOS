"""Tests that base_registry registers each tool by default, or only when its
opt-in is enabled.
"""
from __future__ import annotations


def test_base_registry_excludes_web_search_by_default_but_keeps_recall():
    """web_search is opt-in; recall remains enabled by default."""
    from maverick.tools import base_registry

    class _FakeSandbox:
        pass

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    assert "web_search" not in names
    assert "recall_past_goals" in names


def test_base_registry_can_enable_web_search_explicitly():
    from maverick.tools import base_registry

    class _FakeSandbox:
        pass

    class _FakeWorld:
        pass

    reg = base_registry(
        world=_FakeWorld(),
        sandbox=_FakeSandbox(),
        enable_web_search=True,
    )
    names = {t.name for t in reg.all()}
    assert "web_search" in names


def test_fetch_pdf_and_image_tools_register_by_default():
    """http_fetch, read_pdf, view_image must register by default."""
    from maverick.tools import base_registry

    class _FakeSandbox:
        pass

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    assert "http_fetch" in names
    assert "read_pdf" in names
    assert "view_image" in names


def test_dep_graph_and_ast_edit_register():
    from maverick.tools import base_registry

    class _FakeSandbox:
        workdir = "."

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    assert "dep_graph" in names
    assert "ast_edit" in names


def test_clipboard_diff_arxiv_and_voice_tools_register():
    """The clipboard, preview_diff, arxiv and voice tools register by default."""
    from maverick.tools import base_registry

    class _FakeSandbox:
        workdir = "."

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    for expected in (
        "clipboard", "preview_diff", "arxiv",
        "transcribe_audio", "speak",
        # kv_memory needs a non-None world+goal_id; skip in this no-goal test.
    ):
        assert expected in names, f"missing tool: {expected}"


def test_semantic_scholar_in_registry():
    from maverick.tools import base_registry

    class _FakeSandbox:
        workdir = "."

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    assert "semantic_scholar" in names


def test_patch_compute_email_pandas_and_git_tools_register():
    from maverick.tools import base_registry

    class _FakeSandbox:
        workdir = "."

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    for expected in (
        "apply_patch", "compute", "email",
        "pandas_query", "git_advanced",
    ):
        assert expected in names, f"missing tool: {expected}"


def test_calendar_in_registry():
    from maverick.tools import base_registry

    class _FakeSandbox:
        workdir = "."

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    assert "calendar" in names


def test_linear_and_jira_register(tmp_path):
    """Both tools register cleanly via base_registry."""
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    assert "linear" in names
    assert "jira" in names


def test_mongodb_redis_and_sentry_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    for n in ("mongodb", "redis", "sentry"):
        assert n in names, f"{n} not registered"


def test_ops_crm_and_cloud_tools_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    for n in ("pagerduty", "salesforce", "cloudflare", "datadog",
              "hubspot", "twilio", "s3", "elasticsearch", "github_actions"):
        assert n in names, f"{n} not registered"


def test_credentialed_tools_not_registered_by_default(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    for n in ("airtable", "asana", "clickup", "lambda",
              "dynamodb", "vercel", "gdrive"):
        assert n not in names, f"{n} should be opt-in"


def test_credentialed_tools_register_when_enabled(tmp_path, monkeypatch):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    monkeypatch.setenv("MAVERICK_ENABLE_CRED_TOOLS", "true")
    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    for n in ("airtable", "asana", "clickup", "lambda",
              "dynamodb", "vercel", "gdrive"):
        assert n in names, f"{n} not registered"


def test_saas_and_media_tools_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    expected = (
        "plausible", "mixpanel", "calendly", "zoom", "spotify",
        "home_assistant", "reddit", "bitbucket", "ses", "sns",
        "ffmpeg", "pandoc", "imagemagick", "ga4", "plaid",
    )
    missing = [n for n in expected if n not in names]
    assert not missing, f"unregistered: {missing}"


def test_productivity_and_api_tools_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    for n in ("trello", "replicate", "newsapi", "wolfram", "dropbox",
              "msgraph", "confluence", "gmail"):
        assert n in names, f"{n} not registered"


def test_view_video_registered_by_default():
    from maverick.tools import base_registry

    class _FakeSandbox:
        pass

    class _FakeWorld:
        pass

    reg = base_registry(world=_FakeWorld(), sandbox=_FakeSandbox())
    names = {t.name for t in reg.all()}
    assert "view_video" in names


def test_gitlab_and_embeddings_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    assert "gitlab" in names
    assert "embeddings" in names


def test_notify_and_diagnose_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    assert "notify" in names
    assert "diagnose" in names


def test_huggingface_registers(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path / "workspace"))
    names = {t.name for t in reg.all()}
    assert "huggingface" in names


def test_mobile_tools_register_only_when_enabled(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg_default = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names_default = {t.name for t in reg_default.all()}
    assert "android" not in names_default
    assert "ios_sim" not in names_default
    assert "spend_report" in names_default

    reg_mobile = base_registry(
        _W(),
        LocalBackend(workdir=tmp_path),
        enable_mobile_tools=True,
    )
    names_mobile = {t.name for t in reg_mobile.all()}
    assert "android" in names_mobile
    assert "ios_sim" in names_mobile


def test_youtube_notion_translate_slack_bot_and_test_impact_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    for n in ("test_impact", "youtube", "notion", "translate", "slack_bot"):
        assert n in names, f"{n} not registered"


def test_stripe_currency_and_a11y_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    for n in ("stripe", "currency", "a11y"):
        assert n in names, f"{n} not registered"


def test_discord_hackernews_dns_and_geocode_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    for n in ("discord_bot", "hackernews", "dns_lookup", "geocode"):
        assert n in names, f"{n} not registered"


def test_openapi_ocr_posthog_and_shopify_register(tmp_path):
    from maverick.sandbox.local import LocalBackend
    from maverick.tools import base_registry

    class _W:
        def open_questions(self, gid):
            return []

    reg = base_registry(_W(), LocalBackend(workdir=tmp_path))
    names = {t.name for t in reg.all()}
    for n in ("openapi_runner", "ocr", "posthog", "shopify"):
        assert n in names, f"{n} not registered"


def test_voice_grammar_digest_gui_memory_and_adversarial_eval_register():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    for name in ("voice_command_grammar", "what_changed_digest",
                 "gui_element_memory", "adversarial_eval"):
        assert name in names


def test_knowledge_graph_citation_repo_deps_and_test_gen_register(tmp_path):
    from maverick.tools import base_registry

    class _FakeWorld:
        pass

    class _RegistrySandbox:
        workdir = str(tmp_path)

    reg = base_registry(world=_FakeWorld(), sandbox=_RegistrySandbox())
    tools = getattr(reg, "_tools", {})
    all_names = set(tools.keys())
    for n in ("knowledge_graph", "citation_verifier", "cross_repo_deps", "test_gen"):
        assert n in all_names, f"{n} not registered"
    assert tools["cross_repo_deps"].parallel_safe is False


def test_code_search_mutation_and_constrained_output_register():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    reg = base_registry(world=_W(), sandbox=_S())
    names = set(getattr(reg, "_tools", {}).keys())
    for n in ("semantic_code_search", "mutation_test", "constrained_output"):
        assert n in names, f"{n} not registered"


def test_model3d_and_synthetic_data_register():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    assert "model3d_inspect" in names and "synthetic_data" in names


def test_collusion_disclosure_and_identity_tools_register():
    from maverick.tools import base_registry

    class _W:
        pass

    class _S:
        pass

    names = set(getattr(base_registry(world=_W(), sandbox=_S()), "_tools", {}).keys())
    for name in ("collusion_detector", "coordinated_disclosure",
                 "agent_identity"):
        assert name in names
