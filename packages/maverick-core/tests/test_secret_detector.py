"""Tests for the secret detector (maverick.safety.secret_detector)."""
from __future__ import annotations

import pytest
from maverick.safety.secret_detector import redact as sd_redact
from maverick.secrets import scrub


def test_secret_detector_redacts_colon_delimited_secret():
    # YAML / k8s style. Previously leaked because the separator was `=` only.
    # Plain value (no sk-/aws- prefix) so it can only be caught by env_secret.
    red, matches = sd_redact("API_TOKEN: plainvalue9876543210abc")
    assert "plainvalue9876543210abc" not in red
    assert any(m.name == "env_secret" for m in matches)


def test_secret_detector_still_redacts_equals_form():
    red, _ = sd_redact("DB_PASSWORD=hunter2hunter2hunter2")
    assert "hunter2hunter2hunter2" not in red


def test_secret_detector_and_secrets_agree_on_colon():
    # The two redactors are advertised as mirrors; both must catch the colon form.
    payload = "INTERNAL_API_KEY: abcdEFGH1234567890zz"
    assert "abcdEFGH1234567890zz" not in sd_redact(payload)[0]
    assert "abcdEFGH1234567890zz" not in scrub(payload)


def test_secret_detector_redacts_lightwork_capability_tokens():
    agent_token = "lw-rest-" + "A" * 43
    flow_token = "eyJ" + "B" * 40 + "." + "c" * 64

    redacted, matches = sd_redact(
        f"selector=[value={agent_token}] callback={flow_token}"
    )

    assert agent_token not in redacted
    assert flow_token not in redacted
    assert {match.name for match in matches} >= {
        "lightwork_agent_token",
        "lightwork_flow_approval_token",
    }


# ---------- secret detector ----------

@pytest.mark.parametrize("secret_name,secret_value", [
    ("anthropic_api_key",  "sk-ant-api03-AbCdEf1234567890abcdefghijklmno_PQRST"),
    ("openai_api_key",     "sk-proj-AbCdEf1234567890abcdefghijklmno"),
    ("aws_access_key_id",  "AKIAIOSFODNN7EXAMPLE"),
    ("github_pat_classic", "ghp_AbCdEf1234567890AbCdEf1234567890abcd"),
    ("google_api_key",     "AIzaSyB6CdEf1234567890abcdefghijklmnopq"),
    ("stripe_live_key",    "sk_" + "live_" + "1234567890abcdefghijklmnop"),  # pragma: allowlist secret -- synthetic sequential digits and alphabet detector fixture
    ("jwt",                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature"),
])
def test_secret_detector_finds(secret_name, secret_value):
    from maverick.safety.secret_detector import scan
    matches = scan(f"hello {secret_value} world")
    assert any(m.name == secret_name for m in matches), \
        f"expected to find {secret_name} in: {[m.name for m in matches]}"


def test_secret_detector_redact_replaces_secret():
    from maverick.safety.secret_detector import redact
    text = "MY KEY: sk-ant-api03-AbCdEf1234567890abcdefghijklmno_PQRST end."
    out, matches = redact(text)
    assert "sk-ant-api03" not in out
    assert "[REDACTED:anthropic_api_key]" in out
    assert len(matches) == 1


def test_secret_detector_redact_no_secrets_returns_unchanged():
    from maverick.safety.secret_detector import redact
    text = "no secrets here, just words and numbers like 12345"
    out, matches = redact(text)
    assert out == text
    assert matches == []


def test_secret_detector_redact_multiple():
    from maverick.safety.secret_detector import redact
    text = (
        "first sk-ant-api03-AbCdEf1234567890abcdefghijklmno_PQRST "
        "then AKIAIOSFODNN7EXAMPLE and "
        "ghp_AbCdEf1234567890AbCdEf1234567890abcd done"
    )
    out, matches = redact(text)
    assert "sk-ant" not in out
    assert "AKIA" not in out
    assert "ghp_" not in out
    assert "[REDACTED:anthropic_api_key]" in out
    assert "[REDACTED:aws_access_key_id]" in out
    assert "[REDACTED:github_pat_classic]" in out
    assert len(matches) >= 3


def test_secret_detector_empty():
    from maverick.safety.secret_detector import redact, scan
    assert scan("") == []
    assert redact("") == ("", [])


# ---------- secret_detector generic env secret ----------

@pytest.mark.parametrize("text", [
    "INTERNAL_API_TOKEN=zzz-internal-token-value-1234",
    "export DB_PASSWORD=correcthorsebatterystaple",
    "MY_CUSTOM_SECRET=hunter2supersecretvalue",
])
def test_secret_detector_redacts_generic_env_secret(text):
    from maverick.safety.secret_detector import redact
    out, matches = redact(text)
    assert matches and "[REDACTED:env_secret]" in out
    # The raw value must be gone; the var name stays for readability.
    assert "=" in out
    assert out.split("=", 1)[1] == "[REDACTED:env_secret]"


def test_secret_detector_ignores_non_secret_assignment():
    from maverick.safety.secret_detector import redact
    out, matches = redact("LOG_LEVEL=debug\nMAX_RETRIES=5")
    assert not matches and out == "LOG_LEVEL=debug\nMAX_RETRIES=5"


class TestSecretDetectorProjKey:
    def test_sk_proj_key_with_separators_fully_detected(self):
        from maverick.safety.secret_detector import redact
        key = "sk-proj-AbC_def-GhiJklMno_pqrStuv0123"
        text = f"OPENAI_API_KEY={key}"
        red, matches = redact(text)
        # The whole key must be gone, not just the prefix before the `_`.
        assert key not in red
        assert "def-GhiJklMno" not in red
        assert any(m.name == "openai_api_key" for m in matches)


class TestSecretDetectorBearer:
    def test_base64_bearer_detected(self):
        from maverick.safety.secret_detector import scan
        m = scan("Authorization: Bearer abcd+efgh/ijkl==mnopQRSTuvwx")
        assert any(x.name == "bearer_header" for x in m)
