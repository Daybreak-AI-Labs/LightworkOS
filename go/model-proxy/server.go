package proxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// lastHeaderValue returns the last value of a (possibly multi-valued) header,
// matching Python's dict(headers) semantics in model_proxy.py: a duplicate
// header collapses to its LAST value, not a comma-join. Joining diverged from
// the source of truth on the auth-header comparison (a client sending two
// Authorization headers would be compared against "a, b").
func lastHeaderValue(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[len(values)-1]
}

// Connection is a list-valued routing control: all field values nominate
// hop-by-hop headers. Other fields retain the existing last-value contract.
func forwardedHeaderValue(name string, values []string) string {
	if strings.EqualFold(name, "Connection") {
		return strings.Join(values, ",")
	}
	return lastHeaderValue(values)
}

// HTTPUpstream owns a reusable transport and returns an unbuffered response.
type HTTPUpstream struct{ Client *http.Client }

func NewHTTPUpstream(timeout time.Duration) *HTTPUpstream {
	return &HTTPUpstream{Client: &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{Proxy: nil, DisableCompression: true,
			MaxIdleConns: 64, MaxIdleConnsPerHost: 20, MaxConnsPerHost: 64,
			IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 10 * time.Second},
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (h *HTTPUpstream) Open(ctx context.Context, method, url string, headers map[string]string, body []byte) (*UpstreamResponse, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	// net/http may retry requests with an idempotency key on a reused connection.
	// This boundary never grants replay merely because a caller supplied that key.
	req.GetBody = nil
	req.Body = io.NopCloser(bytes.NewReader(body))
	if h.Client == nil {
		return nil, errors.New("proxy upstream client missing")
	}
	client := *h.Client
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	responseHeaders := make(map[string]string, len(resp.Header))
	for key, values := range resp.Header {
		responseHeaders[key] = forwardedHeaderValue(key, values)
	}
	return &UpstreamResponse{resp.StatusCode, responseHeaders, resp.Body}, nil
}

// Do preserves the bounded buffered compatibility surface for embedders/tests.
func (h *HTTPUpstream) Do(method, url string, headers map[string]string, body []byte) (int, map[string]string, []byte, error) {
	response, err := h.Open(context.Background(), method, url, headers, body)
	if err != nil {
		return 0, nil, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, defaultMaxResponseBytes+1))
	if err != nil {
		return 0, nil, nil, err
	}
	if int64(len(data)) > defaultMaxResponseBytes {
		return 0, nil, nil, errors.New("proxy upstream body limit exceeded")
	}
	return response.Status, response.Headers, data, nil
}

const defaultMaxRequestBytes int64 = 8 * 1024 * 1024
const defaultMaxResponseBytes int64 = 64 * 1024 * 1024
const streamChunkBytes = 16384

type resourceLimits struct {
	requestBytes, responseBytes int64
	duration                    time.Duration
	connections                 int
}

func (c *Config) limits() (resourceLimits, error) {
	limits := resourceLimits{c.MaxRequestBytes, c.MaxResponseBytes, 600 * time.Second, c.MaxConnections}
	if limits.requestBytes == 0 {
		limits.requestBytes = defaultMaxRequestBytes
	}
	if limits.responseBytes == 0 {
		limits.responseBytes = defaultMaxResponseBytes
	}
	if limits.connections == 0 {
		limits.connections = 64
	}
	if c.TotalSeconds != 0 {
		if math.IsNaN(c.TotalSeconds) || math.IsInf(c.TotalSeconds, 0) || c.TotalSeconds < 0 || c.TotalSeconds > float64(math.MaxInt64)/float64(time.Second) {
			return limits, errors.New("model_proxy.total_seconds must be finite and positive")
		}
		limits.duration = time.Duration(c.TotalSeconds * float64(time.Second))
	}
	if limits.requestBytes < 1 || limits.responseBytes < 1 || limits.connections < 1 || limits.duration <= 0 {
		return limits, errors.New("model proxy resource limits must be positive")
	}
	return limits, nil
}

func (c *Config) Validate() error { _, err := c.limits(); return err }

// Server snapshots configuration at first use. Each request owns context,
// bounded input, one upstream body and cancellation until cleanup finishes.
type Server struct {
	Config              *Config
	Upstream            Upstream
	once                sync.Once
	admitted            *Config
	upstream            Upstream
	limits              resourceLimits
	initializationError error
	slots               chan struct{}
}

func cloneSet(source map[string]struct{}) map[string]struct{} {
	clone := make(map[string]struct{}, len(source))
	for value := range source {
		clone[value] = struct{}{}
	}
	return clone
}

func (s *Server) initialize() {
	s.once.Do(func() {
		if s.Config == nil || s.Upstream == nil {
			s.initializationError = errors.New("proxy configuration missing")
			return
		}
		snapshot := *s.Config
		snapshot.AllowHosts = cloneSet(snapshot.AllowHosts)
		snapshot.AllowedRoutes = cloneSet(snapshot.configuredRoutes())
		s.admitted = &snapshot
		s.upstream = s.Upstream
		s.limits, s.initializationError = snapshot.limits()
		if s.initializationError == nil {
			s.slots = make(chan struct{}, s.limits.connections)
		}
	})
}

func proxyError(w http.ResponseWriter, status int, message string) {
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(time.Second))
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Length", strconv.Itoa(len(message)))
	w.WriteHeader(status)
	_, _ = io.WriteString(w, message)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.initialize()
	if s.initializationError != nil {
		proxyError(w, 503, "proxy configuration invalid")
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		proxyError(w, 503, "proxy capacity exceeded")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), s.limits.duration)
	defer cancel()
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	_ = controller.SetReadDeadline(deadline)
	_ = controller.SetWriteDeadline(deadline)
	headers := make(map[string]string, len(r.Header))
	for key, values := range r.Header {
		headers[key] = forwardedHeaderValue(key, values)
	}
	if !Authenticate(s.admitted, headers) {
		proxyError(w, 401, "proxy authentication required")
		return
	}
	if !RouteAllowed(s.admitted, r.Method, r.URL.RequestURI()) {
		proxyError(w, 403, "model proxy route not allowed")
		return
	}
	url, forwarded, err := BuildRequest(s.admitted, r.URL.RequestURI(), headers)
	if err != nil {
		proxyError(w, 403, "model proxy upstream not allowed")
		return
	}
	if r.ContentLength > s.limits.requestBytes {
		proxyError(w, 413, "proxy request body limit exceeded")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.limits.requestBytes))
	if err != nil {
		var sizeError *http.MaxBytesError
		switch {
		case errors.As(err, &sizeError):
			proxyError(w, 413, "proxy request body limit exceeded")
		case ctx.Err() != nil:
			proxyError(w, 504, "proxy request deadline exceeded")
		default:
			proxyError(w, 400, "invalid proxy request")
		}
		return
	}
	response, err := s.upstream.Open(ctx, r.Method, url, forwarded, body)
	if err != nil {
		if ctx.Err() != nil {
			proxyError(w, 504, "proxy request deadline exceeded")
		} else {
			proxyError(w, 502, "proxy upstream request failed")
		}
		return
	}
	defer response.Body.Close()
	for key, value := range response.Headers {
		if strings.EqualFold(key, "Content-Length") {
			length, err := strconv.ParseInt(value, 10, 64)
			if err != nil || length < 0 {
				proxyError(w, 502, "proxy upstream body length invalid")
				return
			}
			if length > s.limits.responseBytes {
				proxyError(w, 502, "proxy upstream body limit exceeded")
				return
			}
		}
	}
	for key, value := range StripResponseHeaders(response.Headers) {
		w.Header().Set(key, value)
	}
	w.Header().Set("Connection", "close")
	w.WriteHeader(response.Status)
	if err := controller.Flush(); err != nil {
		panic(http.ErrAbortHandler)
	}
	buffer := make([]byte, streamChunkBytes)
	var received int64
	for {
		count, readError := response.Body.Read(buffer)
		received += int64(count)
		if received > s.limits.responseBytes {
			panic(http.ErrAbortHandler)
		}
		if count > 0 {
			if _, err := w.Write(buffer[:count]); err != nil {
				panic(http.ErrAbortHandler)
			}
			if err := controller.Flush(); err != nil {
				panic(http.ErrAbortHandler)
			}
		}
		if readError == io.EOF {
			return
		}
		if readError != nil || ctx.Err() != nil {
			panic(http.ErrAbortHandler)
		}
	}
}
