package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
)

// Upstream performs the actual forwarded call. It is an interface so tests can
// inject a fake (mirroring the Python `client=` injection) and the real path
// uses HTTPUpstream over net/http.
type Upstream interface {
	Open(context.Context, string, string, map[string]string, []byte) (*UpstreamResponse, error)
}

// UpstreamResponse owns its body; every caller must Close on all exits.
type UpstreamResponse struct {
	Status  int
	Headers map[string]string
	Body    io.ReadCloser
}

// BufferedUpstream is the legacy embedding/test adapter, not the server contract.
type BufferedUpstream interface {
	// Do issues the upstream request and returns the buffered response.
	Do(method, url string, headers map[string]string, body []byte) (status int, respHeaders map[string]string, respBody []byte, err error)
}

type BufferedAdapter struct{ Upstream BufferedUpstream }

func (a BufferedAdapter) Open(ctx context.Context, method, url string, headers map[string]string, body []byte) (*UpstreamResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	status, responseHeaders, data, err := a.Upstream.Do(method, url, headers, body)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return &UpstreamResponse{status, responseHeaders, io.NopCloser(bytes.NewReader(data))}, nil
}

var textPlain = map[string]string{"Content-Type": "text/plain"}

// Forward mirrors model_proxy.forward: build the upstream request (SSRF-guarded,
// key injected), call it, and strip hop-by-hop headers from the response.
func Forward(c *Config, method, path string, headers map[string]string, body []byte, up BufferedUpstream) (int, map[string]string, []byte, error) {
	limits, err := c.limits()
	if err != nil {
		return 0, nil, nil, err
	}
	if int64(len(body)) > limits.requestBytes {
		return 0, nil, nil, errors.New("proxy request body limit exceeded")
	}
	outURL, fwdHeaders, err := BuildRequest(c, path, headers)
	if err != nil {
		return 0, nil, nil, err
	}
	status, respHeaders, respBody, err := up.Do(method, outURL, fwdHeaders, body)
	if err != nil {
		return 0, nil, nil, err
	}
	if int64(len(respBody)) > limits.responseBytes {
		return 0, nil, nil, errors.New("proxy upstream body limit exceeded")
	}
	return status, StripResponseHeaders(respHeaders), respBody, nil
}

// Handle mirrors model_proxy.handle: whole-request handling that never returns
// an error to the listener — auth, route allow-listing, forward, or a clean
// error response (401/403/502).
func Handle(c *Config, method, path string, headers map[string]string, body []byte, up BufferedUpstream) (int, map[string]string, []byte) {
	if !Authenticate(c, headers) {
		return 401, cloneTextPlain(), []byte("proxy authentication required")
	}
	if !RouteAllowed(c, method, path) {
		return 403, cloneTextPlain(), []byte("model proxy route not allowed")
	}
	limits, err := c.limits()
	if err != nil {
		return 503, cloneTextPlain(), []byte("proxy configuration invalid")
	}
	if int64(len(body)) > limits.requestBytes {
		return 413, cloneTextPlain(), []byte("proxy request body limit exceeded")
	}
	status, respHeaders, respBody, err := Forward(c, method, path, headers, body, up)
	if err != nil {
		// Scrub before returning to the (untrusted) client or logging: an
		// upstream URL/error can embed a credential-shaped string, and this
		// proxy holds the real provider key. Mirrors model_proxy.handle, which
		// wraps both error paths in scrub().
		if hostErr, ok := err.(*HostNotAllowedError); ok { // blocked host / bad request
			return 403, cloneTextPlain(), []byte(scrub(hostErr.Error()))
		}
		return 502, cloneTextPlain(), []byte(scrub("proxy error: " + err.Error()))
	}
	return status, respHeaders, respBody
}

// cloneTextPlain returns a fresh header map so callers can't mutate the shared
// default.
func cloneTextPlain() map[string]string {
	out := make(map[string]string, len(textPlain))
	for k, v := range textPlain {
		out[k] = v
	}
	return out
}
