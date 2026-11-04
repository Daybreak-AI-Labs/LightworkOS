"""Regression contracts for high-impact dashboard deployment mutations."""

from __future__ import annotations

from pathlib import Path

TEMPLATES = Path(__file__).parents[1] / "maverick_dashboard" / "templates"
STATIC = Path(__file__).parents[1] / "maverick_dashboard" / "static"


def _source(name: str) -> str:
    return (TEMPLATES / name).read_text(encoding="utf-8")


def _static(name: str) -> str:
    return (STATIC / name).read_text(encoding="utf-8")


def test_learning_mutations_confirm_targets_and_recover_for_retry():
    source = _source("learning.html")

    assert "This changes the deployment-wide learning posture" in source
    assert "sw.label + '” for this deployment? ' + impact" in source
    assert "Scheduled and triggered workflows may start running" in source
    assert "Disable automatic rollback of workflow regressions?" in source
    # Automatic application of workflow improvements was retired: suggestions
    # now wait for complete human review, so no unconfirmed toggle may return.
    assert "lrn-auto-apply" not in source
    assert "wire('lrn-auto-evolve', 'auto_evolve');" in source
    assert "Workflow suggestions require your review." in source
    assert "Stop these experiments? Results so far are kept." in source
    assert source.count("if (btn.dataset.inFlight === 'true') return;") >= 5
    assert source.count("btn.setAttribute('aria-busy', 'true')") >= 5
    assert source.count("delete btn.dataset.inFlight") >= 10
    assert "window.mvErrorText(r, 'change “' + sw.label + '”')" in source
    assert "window.mvErrorText(r, 'turn on workflows')" in source
    assert "check your connection and try again" in source


def test_workforce_deploy_is_single_flight_and_surfaces_response_details():
    source = _source("workforce.html")
    teams = _static("lightwork-department-team-updates.js")

    deploy = source[source.index('if (act === "deploy")') : source.index("openModal(", source.index('if (act === "deploy")'))]
    # The button opens the shared before-and-after review; nothing saves on click.
    assert "await window.LWDepartmentTeamUpdates.open(key, btn);" in deploy
    assert "fetch(" not in deploy
    # Single flight: a second open or save while one is running is ignored,
    # and the save button stays disabled while busy.
    assert "async function open(key,source){if(busy||invalid)" in teams
    assert "async function saveReviewed(){if(!active||busy||invalid||!active.token)return;" in teams
    assert "function controls(){save.disabled=busy||invalid;" in teams
    assert "finally{if(started===generation){busy=false;controls();}}" in teams
    # Failures read as the server's plain sentence, never an HTTP code.
    # (mvFetchJSON's serverDetail: the server's sentence, else the page's.)
    assert "var F='This team review is unavailable. Reload and check current access.'" in teams
    assert "serverDetail:F" in teams
    assert "HTTP" not in teams
    assert "Check the original result before another save. No save will be repeated automatically." in teams


def test_agent_factory_deploy_and_reset_mutations_are_guarded():
    source = _source("agents.html")
    overrides = _static("lightwork-agent-override-changes.js")
    drafts = _static("lightwork-specialist-drafts.js")
    from maverick_dashboard import specialist_drafts

    # Both team buttons use the reviewed, single-flight team client.
    assert source.count("await window.LWDepartmentTeamUpdates.open(") == 2
    assert "function beginMutation(button)" in source
    assert "if (button.dataset.inFlight === 'true') return false;" in source
    assert "if (failure.unreadable) throw new Error('The result could not be confirmed. Refresh the page to check.');" in source
    assert "plainError(failure, 'reach Lightwork')" in source
    # Save has no direct write path: it opens the complete reviewed draft
    # decision, and refuses outright when that client is unavailable.
    assert "if (window.LWSpecialistDrafts) { await window.LWSpecialistDrafts.reviewEntered('save'); return; }" in source
    assert "The complete draft controls are unavailable. Refresh Agent Factory before saving." in source
    assert "I reviewed every setting and consequence above." in drafts
    assert "if (!consent.checked || busy || reviewed !== value || current !== generation) return;" in drafts
    assert "lock(true); apply.disabled = true;" in drafts
    assert "Publishing or restoring changes new work" in specialist_drafts.NOTICE
    # Reset and removal go through a reviewed, consented, single-flight change.
    assert "'Review reset to the built-in definition'" in overrides
    assert "if (busy || !consent.checked || started !== generation) return" in overrides
    assert "request('/apply', {token:checked.token, confirmed:true})" in overrides
    assert "finally { if (started === generation) lock(false)" in overrides


def test_other_global_or_executable_deployments_have_the_same_safety_contract():
    assurance = _source("model_risk_assurance.html")
    governance = _source("_governance_operations.html")
    store = _source("store.html")
    roles = _source("roles.html")

    assert "let actionInFlight = false" in assurance
    assert "Turn on policy pack “${target}” for all workspaces?" in assurance
    assert "Every workspace that uses this pack may move to this version" in assurance
    assert 'snapshotButton.dataset.inFlight === "true"' in assurance
    assert "Save the overall AI risk report" in assurance
    assert "Could not reach the server — check your connection and try again." in assurance
    # Failures are plain sentences, never status codes.
    assert "(HTTP ${" not in assurance

    assert 'if (form.dataset.inFlight === "true") return null;' in governance
    assert 'delete form.dataset.inFlight' in governance
    assert 'policyActivate.dataset.confirmationPending === "true"' in governance
    assert "Turn on version ${version} of “${title}” for this workspace?" in governance
    assert "Could not reach the server — check your connection and try again." in governance

    assert "if (btn.dataset.inFlight === 'true') return;" in store
    assert "Add the skill “' + label + '”?" in store
    assert "window.mvErrorText(r, 'add the skill')" in store
    assert "HTTP" not in store
    assert "if (!installed)" in store

    assert "function beginMutation(button)" in roles
    assert "'Save changes to the ' + roleName + ' role?" in roles
    assert "'Put the ' + roleName + ' role back to its built-in settings?" in roles
    assert "Could not reach the server — check your connection and try again." in roles
    assert "finishMutation(saveBtn)" in roles
    assert "finishMutation(resetBtn)" in roles


def test_tenant_policy_and_notice_publication_are_confirmed_and_retryable():
    data_use = _source("data_use_governance.html")
    privacy = _source("privacy.html")

    # Switching a rule on is a single-flight row button, confirmed with its
    # plain consequence first; a stale or same-author 409 is explained.
    assert "CW.busy(b, function () { return activatePolicy(p); })" in data_use
    assert "New requests will be decided with it straight away." in data_use
    assert "expected_revision: policy.revision" in data_use
    assert "error.status === 409" in data_use
    # Replies are read by the shared consent client, which fails closed on an
    # unreadable one (consent_workbench.test.js).
    assert "window.LightworkConsentWorkbench.client(API)(path, options)" in data_use

    assert "if (noticeBtn.dataset.inFlight === 'true') return;" in privacy
    assert "Publish privacy notice version “' + version + '”? It cannot be changed afterwards" in privacy
    assert "noticeBtn.setAttribute('aria-busy', 'true')" in privacy
    assert "errText(e, 'publish the notice')" in privacy
    assert "delete noticeBtn.dataset.inFlight" in privacy


def test_consent_lifecycle_mutations_are_targeted_single_flight_actions():
    experiments = _source("consent_experiments.html")
    opt_out = _static("lightwork-consent-global-opt-out.js")

    # Each lifecycle action is a row button: single-flight through CW.busy and
    # confirmed with its plain consequence first.
    assert "CW.busy(button, async function" in experiments
    assert "Visitors taking part will begin to see the test versions." in experiments
    assert "Everyone will see the original from now on." in experiments
    assert "expected_revision: x.revision" in experiments
    assert "Delete visitor records that are past their keep-until date?" in experiments

    # Opt-out set-ups: single-flight row buttons with plain confirmations.
    assert "return CW.busy(button, async function" in opt_out
    assert "Switch on opt-out for " in opt_out
    assert "Switch off opt-out for " in opt_out
    assert "expected_revision: item.revision" in opt_out
    assert "Delete opt-out records that are past their keep-until date?" in opt_out
