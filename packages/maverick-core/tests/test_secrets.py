"""Tests for secret scrubbing (maverick.secrets)."""
from __future__ import annotations

from maverick.secrets import scrub


def test_secrets_redacts_truncated_pem_without_end_marker():
    # A key cut off by a buffer/summary boundary: BEGIN header + body, no END.
    pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "MIIEowIBAAKCAQEAtruncatedKeyBodyAAAA1234567890\n"
           "...buffer cut here, no END marker...")
    out = scrub(pem)
    assert "MIIEowIBAAKCAQEAtruncatedKeyBodyAAAA1234567890" not in out


def test_secrets_still_redacts_complete_pem():
    pem = ("-----BEGIN PRIVATE KEY-----\n"
           "ABCDEFbody123456\n"
           "-----END PRIVATE KEY-----")
    assert "ABCDEFbody123456" not in scrub(pem)


class TestSecretsScrubQuotedValues:
    def test_double_quoted_value_with_spaces_fully_redacted(self):
        from maverick.secrets import scrub
        out = scrub('API_SECRET="my secret value"')
        assert "secret value" not in out
        assert "my" not in out.split("=", 1)[1]
        assert "[REDACTED:env_secret]" in out

    def test_single_quoted_value_with_spaces_fully_redacted(self):
        from maverick.secrets import scrub
        out = scrub("export DB_PASSWORD='a b c d'")
        assert "a b c d" not in out
        assert "[REDACTED:env_secret]" in out

    def test_bare_value_still_redacted(self):
        from maverick.secrets import scrub
        out = scrub("FOO_TOKEN=abc123def456")
        assert "abc123def456" not in out


class TestSecretsURLToken:
    def test_query_string_credential_redacted(self):
        from maverick.secrets import scrub
        out = scrub("GET https://api.x.com/cb?access_token=abc123secret&page=2")
        assert "abc123secret" not in out
        assert "[REDACTED:url_secret]" in out
        # Non-secret params are preserved.
        assert "page=2" in out

    def test_presigned_sig_redacted(self):
        from maverick.secrets import scrub
        out = scrub("https://s3/obj?X=1&sig=DEADBEEFsignature123")
        assert "DEADBEEFsignature123" not in out


class TestSecretScrubbing:
    def test_anthropic_key_redacted(self):
        text = "Calling Anthropic with sk-ant-api01-abc123def456ghi789jklmnopqrs failed"
        out = scrub(text)
        assert "sk-ant-api01" not in out
        assert "[REDACTED:anthropic_key]" in out

    def test_openai_key_redacted(self):
        text = "OPENAI_API_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz123456"
        out = scrub(text)
        # env_secret pattern redacts the value half.
        assert "sk-proj-abcdefghijklmnopqrstuvwxyz123456" not in out

    def test_aws_key_redacted(self):
        text = "aws config: AKIAIOSFODNN7EXAMPLE in env"
        out = scrub(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert "[REDACTED:aws_access_key]" in out

    def test_bearer_header_redacted(self):
        text = "Authorization: Bearer abc123secrettokenvalue4567890"
        out = scrub(text)
        assert "abc123secrettokenvalue4567890" not in out
        assert "Authorization: Bearer [REDACTED:bearer]" in out

    def test_jwt_redacted(self):
        text = "Token: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NSJ9.abcdefghijklmnop"
        out = scrub(text)
        assert "eyJhbGciOiJIUzI1NiJ9" not in out

    def test_dotenv_secret_redacted(self):
        text = "MAVERICK_DASHBOARD_TOKEN=my-secret-token-here"
        out = scrub(text)
        assert "my-secret-token-here" not in out
        assert "MAVERICK_DASHBOARD_TOKEN=" in out  # key name preserved

    def test_non_secret_text_untouched(self):
        text = "Just regular text with no secrets in it."
        assert scrub(text) == text

    def test_pem_private_key_redacted(self):
        text = (
            "key:\n-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEAabc123\nLINE2\n"
            "-----END RSA PRIVATE KEY-----\nrest"
        )
        out = scrub(text)
        assert "MIIEpAIBAAKCAQEAabc123" not in out
        assert "[REDACTED:private_key]" in out
        assert out.endswith("rest")

    def test_url_credentials_redacted(self):
        text = "DB at postgres://admin:s3cretPw@db.example.com:5432/app now"
        out = scrub(text)
        assert "s3cretPw" not in out
        assert "[REDACTED:url_credentials]" in out
        # Host + scheme + user stay readable for debugging.
        assert "postgres://admin:" in out and "@db.example.com:5432/app" in out

    def test_url_without_credentials_untouched(self):
        # A plain URL (no user:pass@) must not be mangled.
        text = "see https://example.com/path?x=1"
        assert scrub(text) == text

    def test_stripe_key_redacted(self):
        text = "stripe: sk_live_abcdef 0123456789ABCDEFGH".replace(" ", "")
        out = scrub(text)
        assert "[REDACTED:stripe_key]" in out

    def test_github_token_redacted(self):
        text = "GITHUB_TOKEN=ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
        out = scrub(text)
        # env_secret pattern catches this first since GITHUB_TOKEN matches.
        assert "ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789" not in out


def test_common_credential_shapes_are_redacted():
    # Formerly left in clear: an empty URL user, a password containing "@",
    # fine-grained GitHub PATs, Basic auth, and lowercase or JSON key/values.
    cases = {
        "redis://:s3cr3tpass@cache:6379/0": "s3cr3tpass",  # pragma: allowlist secret
        "postgres://u:p@ssw0rd@h/db": "ssw0rd",  # pragma: allowlist secret
        "token github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuv": "github_pat_11ABCDEFG",  # pragma: allowlist secret
        "Authorization: Basic dXNlcjpwYXNz": "dXNlcjpwYXNz",  # pragma: allowlist secret
        "password=hunter2": "hunter2",  # pragma: allowlist secret
        "api_key: abc123def": "abc123def",  # pragma: allowlist secret
        "api_key = abc999": "abc999",  # pragma: allowlist secret
        "password = hunter3": "hunter3",  # pragma: allowlist secret
        "auth_token: tok123": "tok123",  # pragma: allowlist secret
        "access_token: ya29.abcdef": "ya29.abcdef",  # pragma: allowlist secret
        "passwd : r00tpw": "r00tpw",  # pragma: allowlist secret
        "client_secret:  cs3cret": "cs3cret",  # pragma: allowlist secret
        "refreshToken=rtok1": "rtok1",  # pragma: allowlist secret
        '{"api_key": "zzz-secret"}': "zzz-secret",  # pragma: allowlist secret
        # httpx logs request URLs at INFO: Wolfram's appid, Trello's key and a
        # Telegram bot token in the URL path.
        "GET https://api.wolframalpha.com/v2/query?input=pi&appid=WXYZ12-ABCDEF1234": "ABCDEF1234",  # pragma: allowlist secret
        "GET https://api.trello.com/1/boards?key=0123abcdkey&token=tok": "0123abcdkey",  # pragma: allowlist secret
        "POST https://api.telegram.org/bot123456:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/getUpdates": "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",  # pragma: allowlist secret
        "https://api.telegram.org/file/bot42:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw/doc.pdf": "AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw",  # pragma: allowlist secret
    }
    for text, secret in cases.items():
        assert secret not in scrub(text), text
    assert scrub("see http://host:8080/p") == "see http://host:8080/p"
    # JSON stays valid, prose is not a key/value pair, and a host after the
    # password stays readable.
    assert scrub('{"api_key": "zzz"}') == '{"api_key": "[REDACTED:kv_secret]"}'  # pragma: allowlist secret
    assert scrub("invalid password: user bob") == "invalid password: user bob"
    assert scrub("the token: see below") == "the token: see below"
    # Source code names variables after secrets; those lines pass unchanged.
    for code in (
        "token = get_token()",
        "def login(user, password: str, token: str):",
        "self.token = token",
        "if token: return",
        "x = {'token': token}",
        "return Token(token=tok)",
        "max_token: 5",
        "token = tokens[0]",
        "secret = sha256(data)",
        "if flags&key==mask: return",
        "def bot(self, key=None):",
    ):
        assert scrub(code) == code, code
    with_query = scrub("https://u:pw@host?next=a@b.com")  # pragma: allowlist secret
    assert with_query == "https://u:[REDACTED:url_credentials]@host?next=a@b.com"
    with_list = scrub("redis://u:pw@cache:6379,user=a@b")  # pragma: allowlist secret
    assert with_list == "redis://u:[REDACTED:url_credentials]@cache:6379,user=a@b"
