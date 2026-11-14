package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRepeatedConnectionHeadersKeepEveryNomination(t *testing.T) {
	seen := make(chan http.Header, 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.Header().Add("Connection", "X-Upstream-Private")
		w.Header().Add("Connection", "keep-alive")
		w.Header().Set("X-Upstream-Private", "origin-only")
		w.Header().Set("X-Trace", "ordinary-response")
		_, _ = io.WriteString(w, "ok")
	}))
	defer origin.Close()
	cfg := authedConfig()
	cfg.Upstream = origin.URL
	server := httptest.NewServer(&Server{Config: cfg, Upstream: NewHTTPUpstream(time.Second)})
	defer server.Close()
	req, _ := http.NewRequest("POST", server.URL+"/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer CLIENT")
	req.Header.Add("Connection", "X-Client-Private")
	req.Header.Add("Connection", "keep-alive")
	req.Header.Set("X-Client-Private", "client-only")
	req.Header.Set("X-Trace", "ordinary-request")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	headers := <-seen
	if headers.Get("X-Client-Private") != "" || resp.Header.Get("X-Upstream-Private") != "" {
		t.Error("a header nominated by an earlier Connection field crossed the proxy")
	}
	if headers.Get("X-Trace") != "ordinary-request" || resp.Header.Get("X-Trace") != "ordinary-response" {
		t.Error("ordinary end-to-end headers were dropped")
	}
	if _, kept := StripResponseHeaders(map[string]string{"Trailer": "X-Checksum"})["Trailer"]; kept {
		t.Error("the HTTP Trailer field crossed the proxy")
	}
}

func TestHandleRedactsConfiguredOpaqueCredentials(t *testing.T) {
	cfg := authedConfig()
	cfg.APIKey = "<opaque-provider-value>"
	cfg.ClientToken = "<opaque-client-value>"
	for _, encode := range []func(string) string{func(s string) string { return s }, url.QueryEscape} {
		up := &fakeUpstream{err: fmt.Errorf("provider rejected %s with client %s", encode(cfg.APIKey), encode(cfg.ClientToken))}
		status, _, body := Handle(cfg, "POST", "/v1/messages", map[string]string{
			"Authorization": "Bearer " + cfg.ClientToken,
		}, nil, up)
		if status != 502 || strings.Contains(string(body), encode(cfg.APIKey)) || strings.Contains(string(body), encode(cfg.ClientToken)) {
			t.Error("the error response exposed an explicitly configured credential")
		}
	}
	for _, tc := range []struct{ token, message, redaction, forbidden string }{
		{"abcdefghijklmnopqrstuv", "upstream rejected sk-abcdefghijklmnopqrstuvxyz12345", "[REDACTED:openai_key]", "xyz12345"}, // pragma: allowlist secret -- synthetic overlap regression
		{"Authorization", "Authorization: Bearer abcdef0123456789ABCDEF", "[REDACTED:bearer]", "abcdef0123456789ABCDEF"},       // pragma: allowlist secret -- synthetic bearer regression
	} {
		cfg.ClientToken = tc.token
		status, _, body := Handle(cfg, "POST", "/v1/messages", map[string]string{
			"Authorization": "Bearer " + cfg.ClientToken,
		}, nil, &fakeUpstream{err: fmt.Errorf("%s", tc.message)})
		if status != 502 || !strings.Contains(string(body), tc.redaction) || strings.Contains(string(body), tc.forbidden) {
			t.Error("configured-value replacement weakened existing credential redaction")
		}
	}
}
