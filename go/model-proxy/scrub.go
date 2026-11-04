package proxy

import "regexp"

// scrub is a faithful port of maverick.secrets.scrub: it redacts
// credential-shaped substrings (API keys, bearer tokens, URL credentials,
// .env-style secrets, PEM private keys, JWTs) to [REDACTED:<kind>] before a
// string is returned to the client or logged.
//
// The Python original wraps both of handle()'s error paths in scrub() so a
// credential-shaped string embedded in an upstream URL/error can't leak into
// the proxy response or the log. This port restores that control on the Go
// listener, which sits in the inference data path and holds the real provider
// key. Patterns and ordering mirror secrets._PATTERNS (longer/more specific
// first); Go's RE2 has no backtracking, so the Python ReDoS-guard bounds are
// kept but are not load-bearing here.
type scrubRule struct {
	re   *regexp.Regexp
	repl string
}

var scrubRules = []scrubRule{
	// PEM private-key block (whole block, or a truncated BEGIN+body). RE2 is
	// backtracking-free, so unbounded .*? / * is linear-time here -- no need
	// for the Python ReDoS-guard length bound (which also exceeds RE2's repeat cap).
	{regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----(?:.*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|[A-Za-z0-9+/=\s]*)`), `[REDACTED:private_key]`},
	// scheme://user:password@host -- redact only the password segment.
	{regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.\-]{0,31}://[^\s:/@]+:)([^\s/@]+)(@)`), `${1}[REDACTED:url_credentials]${3}`},
	// Anthropic API key (sk-ant-...).
	{regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`), `[REDACTED:anthropic_key]`},
	// Stripe secret/restricted key (sk_live_/sk_test_/rk_live_/rk_test_).
	{regexp.MustCompile(`\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}\b`), `[REDACTED:stripe_key]`},
	// OpenAI / OpenRouter key (sk-...).
	{regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`), `[REDACTED:openai_key]`},
	// Google / GCP API key (AIza...).
	{regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`), `[REDACTED:google_api_key]`},
	// AWS access key id.
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), `[REDACTED:aws_access_key]`},
	// AWS secret access key (lowercase key name as in ~/.aws/credentials).
	{regexp.MustCompile(`(?i)(aws_secret_access_key\s*[:=]\s*['"]?)([A-Za-z0-9/+]{40})`), `${1}[REDACTED:aws_secret_key]`},
	// GitHub PAT (ghp_/gho_/ghu_/ghr_/ghs_ prefix).
	{regexp.MustCompile(`\bgh[ps]_[A-Za-z0-9_]{30,}\b|\bghu_[A-Za-z0-9_]{30,}\b|\bgho_[A-Za-z0-9_]{30,}\b|\bghr_[A-Za-z0-9_]{30,}\b`), `[REDACTED:github_token]`},
	// Slack tokens (xoxb-/xoxp-/xapp-...).
	{regexp.MustCompile(`\bxox[bpaors]-[A-Za-z0-9-]{10,}\b`), `[REDACTED:slack_token]`},
	// Authorization: Bearer <token> -- keep the header name, redact the value.
	{regexp.MustCompile(`(?i)\b(authorization\s*:\s*bearer\s+)([A-Za-z0-9._\-+/=]{16,})`), `${1}[REDACTED:bearer]`},
	// .env-style KEY=value (TOKEN/KEY/SECRET/PASSWORD/PASS/CREDENTIAL) -- value only.
	{regexp.MustCompile(`(?m)((?:^|\n)[^\S\n]*(?:export\s+)?[A-Z][A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASS|CREDENTIAL)[A-Z0-9_]*\s*[:=]\s*)("[^"\n]*"|'[^'\n]*'|[^\s\n]+)`), `${1}[REDACTED:env_secret]`},
	// JWT (three base64url segments).
	{regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`), `[REDACTED:jwt]`},
	// Credential carried in a URL query string (?token=..., &api_key=...).
	{regexp.MustCompile(`(?i)([?&](?:access_token|api_key|apikey|auth_token|token|secret|password|passwd|sig|signature|client_secret)=)([^&#\s"']+)`), `${1}[REDACTED:url_secret]`},
}

func scrub(text string) string {
	if text == "" {
		return text
	}
	out := text
	for _, r := range scrubRules {
		out = r.re.ReplaceAllString(out, r.repl)
	}
	return out
}
