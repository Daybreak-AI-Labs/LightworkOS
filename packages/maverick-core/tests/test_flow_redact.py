"""Redaction + payload bounds for a flow run's threaded data."""
from __future__ import annotations

from maverick.flow.redact import cap, redact


class TestRedact:
    def test_masks_secret_looking_keys_at_any_depth(self):
        out = redact({"user": "ada", "api_key": "sk-123",  # pragma: allowlist secret
                      "nested": {"password": "p", "note": "keep"},  # pragma: allowlist secret
                      "list": [{"access_token": "t"}]})  # pragma: allowlist secret
        assert out["user"] == "ada"
        assert out["api_key"] == "***redacted***"
        assert out["nested"]["password"] == "***redacted***"
        assert out["nested"]["note"] == "keep"
        assert out["list"][0]["access_token"] == "***redacted***"

    def test_key_masking_never_narrows_except_for_listed_ordinary_names(self):
        import re

        previous = re.compile(
            r"(token|secret|password|passwd|api[_-]?key|apikey|authorization|auth|"
            r"bearer|credential|private[_-]?key|client[_-]?secret|access[_-]?key)", re.IGNORECASE)
        ordinary = {"author", "authors", "author_association", "authored_date", "authority",
                    "secretary", "token_count", "tokenCount", "max_tokens", "maxTokens",
                    "input_tokens", "total_tokens", "tokens_used"}
        credentials = [
            "accesstoken", "refreshtoken", "authtoken", "privatekey", "clientsecret",
            "secretaccesskey", "mysecret", "userpassword", "dbpassword", "DBPASSWORD",
            "securitytoken", "api_keys", "apikeys", "tokens", "token_value", "auth_header",
            "authHeader", "api_key", "x-api-key", "access_token", "X-Auth-Token",
            "Authorization", "AWS_SECRET_ACCESS_KEY", "credentials", "oauth_scopes",
            "is_authenticated", "author_token", "max_tokens_secret",
        ]
        for key in credentials + sorted(ordinary):
            assert previous.search(key)
            masked = redact({key: "v"})[key] == "***redacted***"  # pragma: allowlist secret
            assert masked is (key not in ordinary), key

    def test_non_secret_data_is_untouched(self):
        d = {"amount": 100, "items": [1, 2], "flag": True}
        assert redact(d) == d


class TestCap:
    def test_truncates_oversized_strings(self):
        big = "x" * 20_000
        out = cap({"blob": big})
        assert out["blob"].endswith("…[truncated]") and len(out["blob"]) < 9_000

    def test_bounds_wide_lists(self):
        out = cap({"rows": list(range(1000))})
        assert out["rows"][-1].startswith("…[") and len(out["rows"]) <= 501

    def test_small_data_passes_through(self):
        d = {"a": "short", "b": [1, 2, 3]}
        assert cap(d) == d
