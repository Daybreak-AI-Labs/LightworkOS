"""Fuzz + ReDoS hardening for the secret redactors.

Lightwork has two mirror secret redactors -- ``maverick.secrets.scrub`` and
``maverick.safety.secret_detector.redact`` -- and both are security
controls: they run on tool stdout, MCP stderr drains, and LLM error
payloads before any of those are logged / audited / replay-exported. All
of those can carry attacker-influenced bytes (a prompt-injected agent can
echo a crafted string; a hostile page can land text in an error). So the
redactors have to survive arbitrary input without crashing and without
blowing up super-linearly.

These tests pin three properties:

1. No ReDoS -- both redactors stay roughly linear on long single-character
   runs, including whitespace runs. Regressions guarded:
     - ``url_credentials``: an unbounded greedy scheme run
       ``[a-zA-Z0-9+.\\-]*://`` backtracked O(N^2) on a long run of
       scheme-class chars that never reached ``://`` (~70s / 300KB).
     - ``env_secret``: ``(?:^|\\n)\\s*`` backtracked O(N^2) on a long run of
       newlines (``\\s`` matches ``\\n``; re.MULTILINE anchors at every line
       start) -- ~13s / 16KB. Present identically in both redactors.
   Either is a remote agent-hang (DoS).
2. No crash -- random adversarial inputs never raise.
3. Still effective -- a real secret embedded in noise is still redacted,
   and scrubbing is idempotent.
"""
from __future__ import annotations

import random
import subprocess
import sys
import textwrap

from maverick.secrets import scrub


def test_secret_redactors_do_not_redos_on_long_runs():
    # Covers BOTH mirror redactors -- maverick.secrets.scrub and
    # maverick.safety.secret_detector.redact -- against long single-character
    # runs, including whitespace runs ("\n"/"\t"/" ") that triggered the
    # env_secret O(N^2) (its `(?:^|\n)\s*` backtracked on newline runs because
    # `\s` matches `\n` and re.MULTILINE anchors at every line start).
    #
    # Run in a child process: a regex stuck in catastrophic backtracking holds
    # the GIL, so neither a thread join-timeout nor signal.alarm can preempt it
    # -- only killing the process can. With the patterns fixed every case is
    # linear (~3s total); a regression blows past the timeout and is killed.
    prog = textwrap.dedent(
        """
        from maverick.secrets import scrub
        from maverick.safety import secret_detector
        N = 300_000
        evil = (
            "a" * N,                                  # url_credentials scheme run
            "A" * N,                                  # uppercase env / url classes
            "A" * N + "KEY",                          # env_secret name run, no '='
            "\\n" * N,                                # newline run: env_secret O(N^2)
            "\\t" * N,                                # tab run
            " " * N,                                  # space run
            "http://" + "a" * N + ":",                # scheme + host run, no '@'
            "sk-ant-" + "a" * N,                      # long key-ish run
            "eyJ" + "a" * N,                          # jwt-ish run, no dots
            "?token=" + "a" * N,                      # url_secret value run
            "-----BEGIN RSA PRIVATE KEY-----" + "a" * N,  # pragma: allowlist secret (fake PEM)
        )
        for s in evil:
            scrub(s)                      # maverick.secrets redactor
            secret_detector.redact(s)     # maverick.safety mirror redactor
        """
    )
    try:
        subprocess.run(
            [sys.executable, "-c", prog],
            check=True,
            timeout=20,
            capture_output=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError(
            "a secret redactor did not finish within 20s on long single-"
            "character runs -- a regex is backtracking super-linearly (ReDoS). "
            "The redactors run on tool output / LLM error payloads, so this is "
            "a remote-DoS vector: bound the offending greedy quantifier or stop "
            "it from spanning newlines."
        ) from exc


def test_scrub_never_raises_on_random_input():
    # Deterministic fuzz: mean alphabet (secret-trigger chars, delimiters,
    # quotes, newlines, controls, non-ASCII) x fixed seed so CI is stable.
    alphabet = (
        "abcdefABCDEF0123456789"
        "=:/@.-_+ \n\t\"'?&#"          # delimiters the patterns key off
        "skAIKAghpxoxbeyJ"              # fragments of real secret prefixes
        "\x00\x1f\x7f\udcff"            # control + lone surrogate-ish
        "Ωпример世界"                    # non-ASCII
    )
    rng = random.Random(0xC0FFEE)
    for _ in range(2000):
        n = rng.randint(0, 256)
        s = "".join(rng.choice(alphabet) for _ in range(n))
        out = scrub(s)
        assert isinstance(out, str)
    # Empty + falsy fast-path.
    assert scrub("") == ""


# (label, text containing a fake secret, the sensitive substring that must
#  NOT survive scrubbing). Each secret is delimited by whitespace so the
#  patterns' word boundaries fire, as they do in real logs.
# Every value below is an intentional FAKE fixture (AWS's own docs example
# key, sequential `AbCdEf123...` filler, etc.). The trailing pragmas keep the
# repo's own detect-secrets CI gate quiet on them -- the workflow that gate
# prescribes for fixtures -- so this file is safe regardless of merge order.
_SECRETS = [
    ("anthropic", "err: sk-ant-api03-AbCdEf1234567890abcdefGHIJK done", "AbCdEf1234567890abcdefGHIJK"),  # pragma: allowlist secret
    ("stripe",    "key sk_live_AbCdEf1234567890abcdef tail",            "sk_live_AbCdEf1234567890abcdef"),  # pragma: allowlist secret
    ("openai",    "OPENAI sk-AbCdEf1234567890abcdefghij used",          "sk-AbCdEf1234567890abcdefghij"),  # pragma: allowlist secret
    ("google",    "g AIzaSyB1234567890abcdefghijklmnopqrstuv x",        "AIzaSyB1234567890abcdefghijklmnopqrstuv"),  # pragma: allowlist secret
    ("aws",       "aws AKIAIOSFODNN7EXAMPLE region",                    "AKIAIOSFODNN7EXAMPLE"),  # pragma: allowlist secret
    ("github",    "tok ghp_AbCdEf1234567890AbCdEf1234567890abcd end",   "ghp_AbCdEf1234567890AbCdEf1234567890abcd"),  # pragma: allowlist secret
    ("slack",     "slack xoxb-123456789012-abcdefABCDEF here",          "xoxb-123456789012-abcdefABCDEF"),  # pragma: allowlist secret
    ("jwt",       "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij z", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghij"),  # pragma: allowlist secret
    ("url_creds", "dsn postgres://user:s3cr3tPassw0rd@db:5432/app q",   "s3cr3tPassw0rd"),  # pragma: allowlist secret
    ("bearer",    "hdr Authorization: Bearer abc123secrettokenVALUE456 x", "abc123secrettokenVALUE456"),  # pragma: allowlist secret
    ("env",       "FOO_SECRET=my-Sup3r-secret-value\nnext",             "my-Sup3r-secret-value"),  # pragma: allowlist secret
    ("url_secret","GET /x?api_key=q1w2e3r4t5y6u7 HTTP",                 "q1w2e3r4t5y6u7"),  # pragma: allowlist secret
    ("pem",       "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKabc\n-----END RSA PRIVATE KEY-----\nrest", "MIIEpAIBAAKabc"),  # pragma: allowlist secret
    # lowercase ~/.aws/credentials secret (the 40-char value, not the AKIA id)
    ("aws_secret","creds aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY tail", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),  # pragma: allowlist secret
    # colon-delimited (YAML / k8s / log) secret
    ("env_colon", "DB_PASSWORD: hunter2pass123word\nnext",              "hunter2pass123word"),  # pragma: allowlist secret
]


def test_scrub_redacts_known_secrets_embedded_in_noise():
    rng = random.Random(42)
    noise_chars = "the quick brown fox 0123 .,;\n\t/"
    for label, payload, sensitive in _SECRETS:
        for _ in range(20):
            pre = "".join(rng.choice(noise_chars) for _ in range(rng.randint(0, 40)))
            post = "".join(rng.choice(noise_chars) for _ in range(rng.randint(0, 40)))
            # Newline-delimited (a realistic log line): the env_secret pattern
            # only redacts a KEY=value at the start of a line -- by design, so
            # arbitrary inline `word=value` prose isn't over-redacted -- so the
            # payload must sit at a line boundary, not glued mid-line.
            out = scrub(f"{pre}\n{payload}\n{post}")
            assert sensitive not in out, f"{label}: secret survived scrubbing"
            assert "[REDACTED:" in out, f"{label}: nothing was redacted"


def test_scrub_is_idempotent():
    # A second pass must not re-mangle or leak: scrub(scrub(x)) == scrub(x).
    for _, payload, _ in _SECRETS:
        once = scrub(payload)
        assert scrub(once) == once
