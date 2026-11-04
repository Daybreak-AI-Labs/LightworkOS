package proxy

import (
	"strings"
	"testing"
)

// scrub must redact credential-shaped substrings from strings that flow to the
// client / log on the proxy error paths, matching maverick.secrets.scrub.
func TestScrubRedactsCredentials(t *testing.T) {
	cases := []struct {
		name string
		in   string
		gone string // substring that must NOT survive
		mark string // redaction marker that must appear
	}{
		{"url_credentials", "dial postgres://user:s3cr3tpw@db:5432 failed", "s3cr3tpw", "[REDACTED:url_credentials]"},
		{"openai_key", "bad key sk-abcdefghijklmnopqrstuvxyz12345", "sk-abcdefghijklmnopqrstuvxyz12345", "[REDACTED:openai_key]"},
		{"bearer", "Authorization: Bearer abcdef0123456789ABCDEF", "abcdef0123456789ABCDEF", "[REDACTED:bearer]"},
		{"url_secret", "GET https://api.host/v1?api_key=SECRETVALUE123 502", "SECRETVALUE123", "[REDACTED:url_secret]"},
		{"env_secret", "OPENAI_API_KEY=sk-shouldnotleak-1234567890", "sk-shouldnotleak-1234567890", "[REDACTED:"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := scrub(c.in)
			if strings.Contains(out, c.gone) {
				t.Fatalf("secret survived scrub: %q -> %q", c.in, out)
			}
			if !strings.Contains(out, c.mark) {
				t.Fatalf("expected %q in scrubbed output, got %q", c.mark, out)
			}
		})
	}
}

func TestScrubLeavesBenignTextUnchanged(t *testing.T) {
	in := "proxy error: dial tcp 10.0.0.5:443: connect: connection refused"
	if out := scrub(in); out != in {
		t.Fatalf("benign error text was altered: %q -> %q", in, out)
	}
}
