"""Governed code self-modification: the editable-surface boundary + code rung.

The load-bearing safety primitive is the boundary: a proposed patch is refused
structurally if it touches ANY control-plane path, before and independently of
the promotion gate. These pin that refusal, the fail-closed defaults, and that a
clean change still has to clear the full self_improvement ladder.
"""
from __future__ import annotations

import pytest
from maverick import self_modify as sm


def _patch(path: str) -> str:
    return (f"diff --git a/{path} b/{path}\n"
            f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n")


PROTECTED = [
    "packages/maverick-core/maverick/self_improvement.py",
    "packages/maverick-core/maverick/self_modify.py",
    "packages/maverick-core/maverick/approval_signing.py",
    "packages/maverick-core/maverick/calibration.py",
    "packages/maverick-core/maverick/verifier.py",
    "packages/maverick-core/maverick/capability.py",
    "packages/maverick-core/maverick/config.py",
    "packages/maverick-core/maverick/migrate.py",
    "packages/maverick-core/maverick/audit/writer.py",
    "packages/maverick-core/maverick/sandbox/backends.py",
    "/etc/passwd",                                   # absolute -> forbidden
    "../../etc/passwd",                              # traversal -> forbidden
    "packages/maverick-core/maverick/audit/../self_improvement.py",  # traversal
    # Build and test-support files outside the package can change how the
    # candidate is built or how its tests behave.
    "test_support/provider_env.py",
    "Makefile",
    "build/maverick.spec",
    "vendor/x.py",
    ".gitattributes",
    "release-cohort.toml",
    "sitecustomize.py",
]

NOT_PROTECTED = [
    "packages/maverick-core/maverick/domains/foo.toml",
    "docs/readme.md",
]


class TestBoundary:
    @pytest.mark.parametrize("path", PROTECTED)
    def test_control_plane_is_protected(self, path):
        assert sm.is_protected(path) is True

    @pytest.mark.parametrize("path", NOT_PROTECTED)
    def test_ordinary_paths_are_not_protected(self, path):
        assert sm.is_protected(path) is False

    def test_classify_precedence(self):
        s = sm.EditableSurface(
            editable_globs=("packages/maverick-core/maverick/domains/*.toml",))
        assert s.classify("packages/maverick-core/maverick/self_improvement.py") == "protected"
        assert s.classify("packages/maverick-core/maverick/domains/a.toml") == "editable"
        assert s.classify("packages/maverick-core/maverick/domains/a.py") == "unknown"

    def test_empty_allowlist_makes_everything_unknown(self):
        # Fail-closed default: no allowlist -> nothing editable.
        s = sm.EditableSurface()
        assert s.classify("packages/maverick-core/maverick/domains/a.toml") == "unknown"

    def test_protected_wins_over_a_permissive_allowlist(self):
        # Even '**' cannot make a control-plane file editable.
        s = sm.EditableSurface(editable_globs=("**",))
        assert s.classify("packages/maverick-core/maverick/audit/writer.py") == "protected"

    @pytest.mark.parametrize("module", [
        "self_modify.py",
        "self_modify_archive.py",
        "self_modify_capability.py",
        "self_modify_context.py",
        "self_modify_corpus.py",
        "self_modify_eval.py",
        "self_modify_loop.py",
        "self_modify_runner.py",
        "self_modify_gate.py",  # future family members fail closed, too
    ])
    def test_entire_self_modify_family_beats_broad_allowlist(self, module):
        surface = sm.EditableSurface(editable_globs=("**",))
        path = f"packages/maverick-core/maverick/{module}"
        assert surface.classify(path) == "protected"
        review = sm.review_patch(_patch(path), surface)
        assert review.ok is False
        assert path in review.protected

    @pytest.mark.parametrize("path", [
        "PACKAGES/MAVERICK-CORE/MAVERICK/SELF_MODIFY.PY",
        "Packages/Maverick-Core/Maverick/Self_Modify_Eval.py",
        "packages/maverick-core/MAVERICK/SELF_MODIFY_APPLY.PY",
    ])
    def test_self_modify_family_case_variants_beat_broad_allowlist(self, path):
        surface = sm.EditableSurface(editable_globs=("**",))
        assert surface.classify(path) == "protected"
        assert sm.review_patch(_patch(path), surface).ok is False

    @pytest.mark.parametrize("path", [
        # DLP/security dependencies and the agent/fleet authority plane.
        "packages/maverick-core/maverick/secrets.py",
        "packages/maverick-core/maverick/provable_redaction.py",
        "packages/maverick-core/maverick/security_defaults.py",
        "packages/maverick-core/maverick/access_policy.py",
        "packages/maverick-core/maverick/containment.py",
        "packages/maverick-core/maverick/a2a.py",
        "packages/maverick-core/maverick/agent.py",
        "packages/maverick-core/maverick/fleet.py",
        "packages/maverick-core/maverick/self_learning.py",
        # Whole orchestration and tenant boundaries.
        "packages/maverick-core/maverick/flow/evolve.py",
        "packages/maverick-core/maverick/tenant/egress.py",
        # Separate packages can carry auth, transport, UI approval, evaluator,
        # or knowledge-ingestion authority and are never candidate surfaces.
        "packages/maverick-channels/maverick_channels/base.py",
        "packages/maverick-dashboard/maverick_dashboard/app.py",
        "packages/maverick-evolve/maverick_evolve/engine.py",
        "packages/maverick-knowledge/maverick_knowledge/store.py",
        "packages/maverick-mcp/maverick_mcp/server.py",
        "packages/maverick-shield/agent_shield/__init__.py",
    ])
    def test_control_plane_beats_a_repo_wide_allowlist(self, path):
        surface = sm.EditableSurface(editable_globs=("**",))
        assert surface.classify(path) == "protected"
        result = sm.review_patch(_patch(path), surface)
        assert result.ok is False
        assert path in result.protected

    @pytest.mark.parametrize("path", [
        ".devcontainer/devcontainer.json",
        ".devcontainer/post-create.sh",
        ".pre-commit-config.yaml",
        ".secrets.baseline",
    ])
    def test_repository_security_artifacts_beat_a_broad_allowlist(self, path):
        surface = sm.EditableSurface(editable_globs=("**",))
        assert surface.classify(path) == "protected"
        assert sm.review_patch(_patch(path), surface).ok is False


class TestReviewPatch:
    def _surface(self):
        return sm.EditableSurface(
            editable_globs=("packages/maverick-core/maverick/domains/*.toml",))

    def test_ok_when_all_paths_editable(self):
        r = sm.review_patch(
            _patch("packages/maverick-core/maverick/domains/a.toml"), self._surface())
        assert r.ok is True and not r.protected and not r.unknown

    def test_rejects_protected_even_alongside_editable(self):
        s = sm.EditableSurface(editable_globs=("**",))
        patch = (_patch("packages/maverick-core/maverick/domains/a.toml")
                 + _patch("packages/maverick-core/maverick/audit/writer.py"))
        r = sm.review_patch(patch, s)
        assert r.ok is False
        assert any("audit" in p for p in r.protected)
        assert "protected" in r.reason

    def test_rejects_unknown_paths(self):
        r = sm.review_patch(
            _patch("packages/maverick-core/maverick/domains/a.py"), self._surface())
        assert r.ok is False and r.unknown

    def test_timestamped_diff_header_cannot_smuggle_a_protected_edit(self):
        # Regression: git ---/+++ headers may carry a trailing tab+timestamp that
        # git apply ignores. A plain unified diff (no `diff --git` line) editing a
        # control-plane file with that suffix must still be classified protected
        # -- even against a permissive '**' allowlist -- or the boundary is blind
        # to an edit git apply then applies to the real control-plane file.
        prot = "packages/maverick-core/maverick/self_improvement.py"
        ts = "\t2024-01-01 00:00:00.000000000 +0000"
        patch = (f"--- a/{prot}{ts}\n+++ b/{prot}{ts}\n@@ -1 +1 @@\n-old\n+new\n")
        r = sm.review_patch(patch, sm.EditableSurface(editable_globs=("**",)))
        assert r.ok is False
        assert any("self_improvement" in p for p in r.protected)

    def test_rejects_empty_patch(self):
        assert sm.review_patch("", sm.EditableSurface(editable_globs=("**",))).ok is False

    def test_new_file_diff_excludes_dev_null(self):
        p = "packages/maverick-core/maverick/domains/a.toml"
        patch = (f"diff --git a/{p} b/{p}\nnew file mode 100644\n"
                 f"--- /dev/null\n+++ b/{p}\n@@ -0,0 +1 @@\n+x\n")
        r = sm.review_patch(patch, self._surface())
        assert r.ok is True
        assert "/dev/null" not in " ".join(r.touched)

    def test_rename_paths_are_classified(self):
        s = sm.EditableSurface(editable_globs=("**",))
        patch = ("diff --git a/packages/maverick-core/maverick/domains/a.toml "
                 "b/packages/maverick-core/maverick/audit/x.py\n"
                 "rename from packages/maverick-core/maverick/domains/a.toml\n"
                 "rename to packages/maverick-core/maverick/audit/x.py\n")
        r = sm.review_patch(patch, s)
        assert r.ok is False  # the rename target is under the protected audit/ dir

    def test_nonstandard_prefix_cannot_retarget_past_review_with_p1(self):
        # ``git apply -p1`` strips any first component.  Reviewing x/apps while
        # applying apps would let a broad surface rewrite a protected package.
        patch = (
            "diff --git x/apps/pwn.txt y/apps/pwn.txt\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            "+++ y/apps/pwn.txt\n"
            "@@ -0,0 +1 @@\n+pwn\n"
        )
        result = sm.review_patch(
            patch, sm.EditableSurface(editable_globs=("**",)))
        assert result.ok is False
        assert "git apply -p1" in result.reason

    @pytest.mark.parametrize("sep", ["\u2028", "\x85", "\x1c", "\x0c"])
    def test_header_is_split_on_newline_only_like_git(self, sep):
        # git keeps these characters inside the header line, so the reviewed
        # path must be the whole name git would create, not the prefix before
        # the separator.
        p = "packages/maverick-core/maverick/domains/a.toml"
        patch = (f"--- /dev/null\n+++ b/{p}{sep}x.py\n"
                 "@@ -0,0 +1 @@\n+x\n")
        surface = sm.EditableSurface(
            editable_globs=("packages/maverick-core/maverick/domains/*.toml",))
        result = sm.review_patch(patch, surface)
        assert result.ok is False
        assert p not in result.touched

    def test_crlf_patch_to_an_allowed_path_is_reviewed_by_its_real_path(self):
        p = "packages/maverick-core/maverick/domains/a.toml"
        patch = (f"diff --git a/{p} b/{p}\r\n--- a/{p}\r\n+++ b/{p}\r\n"
                 "@@ -1 +1 @@\r\n-x\r\n+y\r\n")
        surface = sm.EditableSurface(
            editable_globs=("packages/maverick-core/maverick/domains/*.toml",))
        result = sm.review_patch(patch, surface)
        assert result.ok is True and result.touched == (p,)

    def test_custom_surface_authority_is_refused_even_if_it_says_editable(self):
        class FakeSurface:
            @staticmethod
            def classify(_path):
                return "editable"

        result = sm.review_patch(
            _patch("docs/readme.md"), FakeSurface())  # type: ignore[arg-type]
        assert result.ok is False
        assert "invalid editable surface authority" in result.reason

    def test_malformed_surface_allowlist_is_refused(self):
        surface = sm.EditableSurface(editable_globs=["**"])  # type: ignore[arg-type]
        result = sm.review_patch(_patch("docs/readme.md"), surface)
        assert result.ok is False
        assert "invalid editable surface allowlist" in result.reason

    @pytest.mark.parametrize("metadata", [
        "new file mode 100755",
        "new file mode 120000",
        "new file mode 160000",
        "old mode 100644\nnew mode 100755",
        "old mode 100755\nnew mode 100644",
        "index 1234567..7654321 120000",
        "index 1234567..7654321 160000",
    ])
    def test_rejects_executable_mode_changes_and_special_modes(self, metadata):
        path = "packages/maverick-core/maverick/domains/a.toml"
        patch = (f"diff --git a/{path} b/{path}\n{metadata}\n"
                 f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n")
        result = sm.review_patch(patch, self._surface())
        assert result.ok is False
        assert "mode" in result.reason

    @pytest.mark.parametrize("artifact", [
        "GIT binary patch",
        "Binary files a/x and b/x differ",
        "+Subproject commit 0123456789abcdef",
        "-Subproject commit fedcba9876543210",
    ])
    def test_rejects_binary_and_gitlink_artifacts(self, artifact):
        path = "packages/maverick-core/maverick/domains/a.toml"
        patch = f"diff --git a/{path} b/{path}\n{artifact}\n"
        result = sm.review_patch(patch, self._surface())
        assert result.ok is False
        assert "binary" in result.reason or "artifact" in result.reason

    def test_existing_executable_can_receive_a_text_only_edit(self):
        path = "packages/maverick-core/maverick/domains/a.toml"
        patch = (f"diff --git a/{path} b/{path}\n"
                 "index 1234567..7654321 100755\n"
                 f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-old\n+new\n")
        assert sm.review_patch(patch, self._surface()).ok is True


class TestGate:
    def test_off_by_default(self, monkeypatch):
        monkeypatch.delenv("MAVERICK_SELF_MODIFY", raising=False)
        monkeypatch.setattr(sm, "_settings", lambda: {"enable": False, "editable_paths": []})
        assert sm.enabled() is False

    def test_env_enables(self, monkeypatch):
        monkeypatch.setenv("MAVERICK_SELF_MODIFY", "1")
        assert sm.enabled() is True
        monkeypatch.setenv("MAVERICK_SELF_MODIFY", "0")
        assert sm.enabled() is False


class TestProposeCodeChange:
    def _surface(self):
        return sm.EditableSurface(
            editable_globs=("packages/maverick-core/maverick/domains/*.toml",))

    def _controller(self, tmp_path):
        from maverick import self_improvement as si
        return si.SelfImprovementController(
            min_improvement=0.0, max_auto_rung="policy",
            frozen_fn=lambda: False, audit_fn=lambda **k: None,
            ledger=si.PromotionLedger(path=tmp_path / "promotion-ledger.json"))

    def test_disabled_is_a_noop(self, monkeypatch):
        monkeypatch.setattr(sm, "enabled", lambda: False)
        res = sm.propose_code_change(
            _patch("packages/maverick-core/maverick/domains/a.toml"),
            summary="s", baseline_score=0.5, candidate_score=0.9, samples=8,
            rollback="snap")
        assert res.ok is False
        assert "disabled" in res.reason

    def test_control_plane_edit_refused_before_the_gate(self, monkeypatch):
        # The boundary refuses a control-plane edit WITHOUT ever consulting the
        # promotion gate -- defense in depth.
        from maverick import self_improvement as si
        monkeypatch.setattr(sm, "enabled", lambda: True)
        called = []
        monkeypatch.setattr(si, "consider",
                            lambda *a, **k: called.append(1) or None)
        res = sm.propose_code_change(
            _patch("packages/maverick-core/maverick/self_improvement.py"),
            summary="s", baseline_score=0.5, candidate_score=0.9, samples=20,
            rollback="snap", surface=sm.EditableSurface(editable_globs=("**",)),
            rung="code")
        assert res.review.ok is False
        assert res.verdict is None
        assert called == []                 # the gate was never reached
        assert "protected" in res.reason

    @pytest.mark.parametrize("rung", ["prompt", "policy", "weights", "CODE", None])
    def test_rung_downgrade_is_refused_before_any_side_effect(self, monkeypatch, rung):
        calls = []
        monkeypatch.setattr(sm, "enabled", lambda: calls.append("enabled") or True)
        monkeypatch.setattr(
            sm, "review_patch", lambda *a, **k: calls.append("review") or None)
        res = sm.propose_code_change(
            _patch("packages/maverick-core/maverick/domains/foo.toml"),
            summary="tune pack", baseline_score=0.5, candidate_score=0.9, samples=8,
            rollback="snap-1", surface=self._surface(), capability_widens=False,
            rung=rung)
        assert res.ok is False
        assert res.review.ok is False
        assert "requires rung='code'" in res.reason
        assert calls == []

    def test_code_rung_never_reaches_legacy_promotion_gate(
        self, monkeypatch, tmp_path,
    ):
        from maverick import self_improvement as si
        monkeypatch.setattr(sm, "enabled", lambda: True)
        monkeypatch.setattr(si, "enabled", lambda: True)
        called = []
        monkeypatch.setattr(
            si, "consider", lambda *_args, **_kwargs: called.append(True))
        res = sm.propose_code_change(
            _patch("packages/maverick-core/maverick/domains/foo.toml"),
            summary="risky", baseline_score=0.5, candidate_score=0.9, samples=20,
            rollback="snap-1", surface=self._surface(), capability_widens=False,
            rung="code", controller=self._controller(tmp_path))
        assert res.review.ok is True
        assert res.ok is False
        assert "live code promotion is disabled" in res.reason
        assert called == []

    def test_insufficient_evidence_refused(self, monkeypatch, tmp_path):
        from maverick import self_improvement as si
        monkeypatch.setattr(sm, "enabled", lambda: True)
        monkeypatch.setattr(si, "enabled", lambda: True)
        res = sm.propose_code_change(
            _patch("packages/maverick-core/maverick/domains/foo.toml"),
            summary="no gain", baseline_score=0.9, candidate_score=0.9, samples=8,
            rollback="snap-1", surface=self._surface(), capability_widens=False,
            rung="code", controller=self._controller(tmp_path))
        assert res.ok is False               # no improvement over baseline


class TestBypassRegression:
    """Every bypass the security review confirmed must now be refused."""

    def test_git_quoted_path_is_protected(self):
        # git C-quoted spelling of a control-plane path -> boundary un-quotes it.
        assert sm.is_protected('"a/maverick/self_improvement.py"') is True
        assert sm.is_protected('"b/packages/maverick-core/maverick/verifier.py"') is True

    def test_octal_escaped_path_is_protected(self):
        # \163 == 's': "\163elf_improvement.py" -> self_improvement.py
        assert sm.is_protected(r'"a/maverick/\163elf_improvement.py"') is True

    @pytest.mark.parametrize("path", [
        r'"a/ordinary\q.py"',       # unknown C-quote escape
        r'"a/ordinary\400.py"',     # octal value outside a byte
        r'"a/ordinary\377.py"',     # invalid standalone UTF-8 byte
    ])
    def test_malformed_git_quoting_fails_closed(self, path):
        assert sm.is_protected(path) is True

    def test_double_slash_path_is_protected(self):
        assert sm.is_protected("maverick//self_improvement.py") is True
        assert sm.is_protected("packages/maverick-core/maverick//audit/writer.py") is True

    def test_dot_segment_path_is_protected(self):
        assert sm.is_protected("maverick/./self_improvement.py") is True

    def test_case_variant_is_protected(self):
        # macOS/Windows are case-insensitive: these resolve to the real file.
        assert sm.is_protected("packages/maverick-core/maverick/Self_Improvement.py") is True
        assert sm.is_protected("packages/maverick-core/maverick/AUDIT/writer.py") is True

    @pytest.mark.parametrize("mod", [
        "budget.py", "promotion_effect.py", "llm.py",
        "evaluator_evolution.py", "migration_governance.py", "approval_delegation.py",
        "release_manifest_signing.py",
    ])
    def test_newly_protected_governance_modules(self, mod):
        assert sm.is_protected(f"packages/maverick-core/maverick/{mod}") is True

    @pytest.mark.parametrize("path", [
        "packages/maverick-core/maverick/server.py",
        "packages/maverick-core/maverick/catalog_trust.py",
        "packages/maverick-core/maverick/shield_policy.py",
        "packages/maverick-core/maverick/web_session.py",
        "packages/maverick-core/maverick/webhooks.py",
        "packages/maverick-core/maverick/orchestrator.py",
        "packages/maverick-core/maverick/worker.py",
        "packages/maverick-core/maverick/world_model.py",
        "packages/maverick-core/maverick/crypto_at_rest.py",
        "packages/maverick-core/maverick/kms_backends.py",
        "packages/maverick-core/maverick/governance.py",
        "packages/maverick-core/maverick/privacy_egress.py",
        "packages/maverick-core/maverick/quotas.py",
        "packages/maverick-core/maverick/plugin_ca.py",
        "packages/maverick-core/maverick/workspace_snapshot.py",
        "packages/maverick-core/maverick/adapter_rung.py",
        "packages/maverick-core/maverick/automation_import/to_flow.py",
        "apps/installer-cli/maverick_installer/wizard.py",
        "deploy/docker-compose.yml",
        "rust/Cargo.toml",
        "sdks/typescript/src/index.ts",
        "web/src/app.ts",
    ])
    def test_broad_surface_cannot_rewrite_runtime_control_planes(self, path):
        surface = sm.EditableSurface(editable_globs=("**",))
        assert surface.classify(path) == "protected"

    def test_uncanonicalizable_paths_fail_closed(self):
        for bad in ["/etc/passwd", "../../etc/passwd",
                    'packages/maverick-core/maverick/audit/../self_improvement.py']:
            assert sm.is_protected(bad) is True

    @pytest.mark.parametrize("path", [
        r"C:\repo\ordinary.py",                 # absolute drive path
        r"C:repo\ordinary.py",                  # drive-relative path
        "ordinary.py:payload",                   # NTFS alternate data stream
        r"\\server\share\ordinary.py",          # UNC path
        "ordinary.py.",                          # Windows strips trailing dot
        '"a/ordinary.py "',                     # Windows strips trailing space
        "CON", "con.txt", "NUL.json",          # reserved device names
        "COM1.log", "lpt9", "CLOCK$",          # reserved device names
        "SELF_I~1.PY",                           # DOS 8.3 alias
        "src//ordinary.py", "src/./ordinary.py",  # ambiguous segments
        "src/ordinary\x00.py",                   # control character
    ])
    def test_cross_platform_ambiguous_paths_fail_closed(self, path):
        assert sm.is_protected(path) is True

    def test_ambiguous_allowlisted_patch_path_is_refused(self):
        surface = sm.EditableSurface(editable_globs=("**",))
        patch = ("diff --git a/src/ordinary.py. b/src/ordinary.py.\n"
                 "--- a/src/ordinary.py.\n+++ b/src/ordinary.py.\n"
                 "@@ -1 +1 @@\n-old\n+new\n")
        result = sm.review_patch(patch, surface)
        assert result.ok is False
        assert result.protected

    def test_unquoted_trailing_space_is_not_stripped_before_review(self):
        surface = sm.EditableSurface(editable_globs=("**",))
        patch = ("--- a/src/ordinary.py \n+++ b/src/ordinary.py \n"
                 "@@ -1 +1 @@\n-old\n+new\n")
        result = sm.review_patch(patch, surface)
        assert result.ok is False
        assert result.protected

    def test_review_refuses_quoted_real_path_behind_a_clean_decoy(self):
        # Decoy clean header + the real edit riding on quoted +++/--- lines.
        s = sm.EditableSurface(editable_globs=("**",))
        patch = ('diff --git a/x b/x\n'
                 '--- "a/maverick/verifier.py"\n'
                 '+++ "b/maverick/verifier.py"\n'
                 '@@ -1 +1 @@\n-o\n+n\n')
        r = sm.review_patch(patch, s)
        assert r.ok is False
        assert any("verifier.py" in p for p in r.protected)

    def test_review_refuses_double_slash_under_permissive_allowlist(self):
        s = sm.EditableSurface(editable_globs=("**",))
        patch = _patch("packages/maverick-core/maverick//self_improvement.py")
        r = sm.review_patch(patch, s)
        assert r.ok is False


def _patch_with_added(path: str, added: str) -> str:
    return (f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n"
            f"@@ -1 +1,2 @@\n old\n+{added}\n")


class TestCapabilityDiff:
    """The heuristic capability screen: a one-directional non-escalation SIGNAL."""

    def test_clean_added_lines_do_not_widen(self):
        widens, reasons = sm.capability_diff(
            _patch_with_added("a.toml", "value = 42"))
        assert widens is False and reasons == []

    def test_empty_patch_does_not_widen(self):
        assert sm.capability_diff("") == (False, [])

    @pytest.mark.parametrize("added,needle", [
        ("subprocess.run(['ls'])", "process spawn"),
        ("proc = os.system('rm -rf /')", "process spawn"),
        ("run(cmd, shell=True)", "process spawn"),
        ("data = eval(user_input)", "dynamic code"),
        # obfuscation constructs are treated as dynamic-code capability
        ("fn = getattr(os, 'sys' + 'tem')", "dynamic code"),
        ("payload = base64.b64decode(blob)", "dynamic code"),
        ("obj = pickle.loads(blob)", "deserialization"),
        ("import socket", "network"),
        ("resp = requests.get(url)", "network"),
        ("mod = __import__(name)", "dynamic import"),
        ("os.remove(path)", "filesystem"),
        ("shutil.rmtree(d)", "filesystem"),
        ("p.write_text('x')", "filesystem"),
        ("f = open('out.txt', 'w')", "filesystem"),
        ("grant = new_entitlement()", "authority"),
        ("editable_paths = ['**']", "authority"),
    ])
    def test_widening_constructs_are_flagged(self, added, needle):
        widens, reasons = sm.capability_diff(_patch_with_added("a.py", added))
        assert widens is True
        assert any(needle in r for r in reasons), reasons

    def test_only_added_lines_are_scanned(self):
        # A REMOVED subprocess line (context/`-`) is not a new capability.
        patch = ("diff --git a/a.py b/a.py\n--- a/a.py\n+++ b/a.py\n"
                 "@@ -1,2 +1 @@\n-subprocess.run(x)\n remaining\n")
        assert sm.capability_diff(patch) == (False, [])

    def test_the_plusplusplus_header_is_not_a_construct(self):
        # The +++ b/... file header must not be scanned as an added line.
        widens, _ = sm.capability_diff(
            _patch_with_added("packages/x/subprocess_helper.py", "value = 1"))
        assert widens is False

    def test_comment_only_addition_does_not_widen(self):
        widens, reasons = sm.capability_diff(
            _patch_with_added("a.py", "# subprocess is intentionally avoided here"))
        assert widens is False and reasons == []


class TestCapabilityScreenIntoGate:
    """The screen can only make the gate STRICTER, never weaker."""

    def _surface(self):
        return sm.EditableSurface(
            editable_globs=("packages/maverick-core/maverick/domains/*.py",))

    def _controller(self, tmp_path):
        from maverick import self_improvement as si
        return si.SelfImprovementController(
            min_improvement=0.0, max_auto_rung="policy",
            frozen_fn=lambda: False, audit_fn=lambda **k: None,
            ledger=si.PromotionLedger(path=tmp_path / "promotion-ledger.json"))

    def test_screen_blocks_a_widening_code_change(self, monkeypatch, tmp_path):
        # An allowlisted source edit is refused because it adds a process-spawn
        # capability, independently of the code rung's human approval backstop.
        from maverick import self_improvement as si
        monkeypatch.setattr(sm, "enabled", lambda: True)
        monkeypatch.setattr(si, "enabled", lambda: True)
        patch = _patch_with_added(
            "packages/maverick-core/maverick/domains/foo.py",
            "os.system('curl evil')")
        res = sm.propose_code_change(
            patch, summary="sneaky", baseline_score=0.5, candidate_score=0.9,
            samples=20, rollback="snap", surface=self._surface(),
            capability_widens=False,  # caller claims bounded...
            rung="code", controller=self._controller(tmp_path))
        assert res.review.ok is True         # surface is clean
        assert res.ok is False               # ...but the screen overrode -> blocked
        assert "capability" in res.reason.lower()

    def test_clean_screen_still_cannot_reach_legacy_gate(self, monkeypatch):
        from maverick import self_improvement as si
        monkeypatch.setattr(sm, "enabled", lambda: True)
        captured = []
        monkeypatch.setattr(
            si, "consider",
            lambda candidate, **kwargs: captured.append(candidate)
            or type("Verdict", (), {"ok": True})(),
        )
        patch = _patch_with_added(
            "packages/maverick-core/maverick/domains/foo.py", "TUNING = 0.7")
        res = sm.propose_code_change(
            patch, summary="tune", baseline_score=0.5, candidate_score=0.9,
            samples=8, rollback="snap", surface=self._surface(),
            capability_widens=False, rung="code")
        assert res.ok is False
        assert "live code promotion is disabled" in res.reason
        assert captured == []
