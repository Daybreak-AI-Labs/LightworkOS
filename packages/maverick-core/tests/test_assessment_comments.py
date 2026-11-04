"""Question-comment governance on pinned assessment sessions."""
from __future__ import annotations

import json

import pytest
from maverick import assessment as A


@pytest.fixture(autouse=True)
def _fresh_home(tmp_path, monkeypatch):
    monkeypatch.setenv("MAVERICK_HOME", str(tmp_path))
    monkeypatch.setenv("MAVERICK_CONFIG", str(tmp_path / "config.toml"))


def _saved(*, assessment_id: str = "comment-assessment") -> A.AssessmentSession:
    session = A.AssessmentSession(type="pia", subject="Acme CRM", id=assessment_id)
    session.record("pia_necessity", "no")
    A.save_session(session)
    return session


def _add(session: A.AssessmentSession, *, revision: int, key: str, text: str = "Review note"):
    return A.add_assessment_comment(
        session.id,
        section_id="Necessity",
        question_id="pia_necessity",
        comment=text,
        commented_by="user:reviewer",
        expected_revision=revision,
        idempotency_key=key,
    )


def test_comment_preserves_workflow_binds_actor_and_emits_content_hash(monkeypatch):
    seen: list[dict] = []
    monkeypatch.setattr(A, "_deliver_audit", lambda receipt: seen.append(receipt) or True)
    session = _saved()
    before = A.add_followups(session.id, ["Which processors?"], asked_by="user:reviewer")

    record = _add(session, revision=before["revision"], key="comment-core-1")

    assert record["status"] == "needs_more"
    assert record["revision"] == before["revision"] + 1
    assert record["comments"][0]["commented_by"] == "user:reviewer"
    assert "_idempotency_sha256" not in record["comments"][0]
    assert seen[-1]["kind"] == "ASSESSMENT_COMMENT_CREATED"
    assert seen[-1]["payload"]["comment_sha256"]
    assert "Review note" not in json.dumps(seen[-1])


def test_comment_retry_is_noop_and_key_reuse_or_stale_cas_conflicts():
    session = _saved()
    initial = A.load_saved(session.id)
    first = _add(session, revision=initial["revision"], key="comment-core-retry")
    replay = _add(session, revision=initial["revision"], key="comment-core-retry")

    assert replay["revision"] == first["revision"]
    assert replay["comments"] == first["comments"]
    with pytest.raises(A.AssessmentConflict, match="different assessment comment"):
        _add(
            session,
            revision=first["revision"],
            key="comment-core-retry",
            text="Changed meaning",
        )
    with pytest.raises(A.AssessmentConflict, match="assessment changed"):
        _add(session, revision=initial["revision"], key="comment-core-stale")


def test_comments_require_pinned_question_and_apply_count_quota(monkeypatch):
    session = _saved()
    current = A.load_saved(session.id)
    with pytest.raises(A.AssessmentTransitionError, match="section/question"):
        A.add_assessment_comment(
            session.id,
            section_id="Invented",
            question_id="pia_necessity",
            comment="Misbound",
            commented_by="user:reviewer",
            expected_revision=current["revision"],
            idempotency_key="comment-core-misbound",
        )

    first = _add(session, revision=current["revision"], key="comment-core-quota-1")
    monkeypatch.setattr(A, "_MAX_ASSESSMENT_COMMENTS", 1)
    with pytest.raises(A.AssessmentStateError, match="comment limit"):
        _add(session, revision=first["revision"], key="comment-core-quota-2")


def test_comments_are_tenant_scoped_and_pagination_can_pin_revision():
    from maverick.paths import reset_tenant, set_tenant

    token = set_tenant("tenant-a")
    try:
        session = _saved(assessment_id="shared-assessment")
        current = A.load_saved(session.id)
        created = _add(session, revision=current["revision"], key="comment-tenant-a")
        page = A.assessment_comments(
            session.id,
            expected_revision=created["revision"],
        )
        assert page["total"] == 1
    finally:
        reset_tenant(token)

    token = set_tenant("tenant-b")
    try:
        assert A.load_saved("shared-assessment") is None
        assert A.assessment_comments("shared-assessment") is None
    finally:
        reset_tenant(token)


def test_legacy_unpinned_assessment_cannot_receive_bound_comment():
    session = _saved()
    path = A._assessment_path(session.id)
    record = json.loads(path.read_text(encoding="utf-8"))
    record.pop("template_snapshot")
    path.write_text(json.dumps(record), encoding="utf-8")

    with pytest.raises(A.AssessmentTransitionError, match="pinned questionnaire"):
        _add(session, revision=record["revision"], key="comment-core-legacy")
