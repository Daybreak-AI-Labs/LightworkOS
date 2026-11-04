package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestSharedStreamingParityFixture(t *testing.T) {
	data, err := os.ReadFile("testdata/stream_parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		ContentType string   `json:"content_type"`
		Chunks      []string `json:"chunks"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil || len(fixture.Chunks) < 2 {
		t.Fatalf("invalid shared stream fixture: %v", err)
	}
	var calls atomic.Int32
	proxy, _ := streamingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", fixture.ContentType)
		for _, chunk := range fixture.Chunks {
			_, _ = io.WriteString(w, chunk)
			w.(http.Flusher).Flush()
		}
	}), nil)
	response := request(t, proxy.URL, strings.NewReader("{}"))
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != strings.Join(fixture.Chunks, "") {
		t.Fatalf("stream mismatch: status=%d body=%q error=%v", response.StatusCode, body, err)
	}
	if response.Header.Get("Content-Type") != fixture.ContentType || calls.Load() != 1 {
		t.Fatal("stream response headers or upstream request count differ")
	}
}

func streamingProxy(t *testing.T, upstream http.Handler, configure func(*Config)) (*httptest.Server, *httptest.Server) {
	t.Helper()
	origin := httptest.NewServer(upstream)
	config := authedConfig()
	config.Upstream = origin.URL
	config.TotalSeconds = 2
	if configure != nil {
		configure(config)
	}
	proxy := httptest.NewServer(&Server{Config: config, Upstream: NewHTTPUpstream(2 * time.Second)})
	t.Cleanup(proxy.Close)
	t.Cleanup(origin.Close)
	return proxy, origin
}

func request(t *testing.T, url string, body io.Reader) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", url+"/v1/messages", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer CLIENT")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestStreamingFirstChunkAndDisconnectCancelUpstream(t *testing.T) {
	closed := make(chan struct{})
	var calls atomic.Int32
	proxy, _ := streamingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer REAL_KEY" {
			t.Error("wrong upstream authentication")
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(closed)
	}), nil)
	response := request(t, proxy.URL, strings.NewReader("{}"))
	first := make([]byte, len("data: first\n\n"))
	if _, err := io.ReadFull(response.Body, first); err != nil {
		t.Fatal(err)
	}
	if string(first) != "data: first\n\n" {
		t.Fatalf("first chunk: %q", first)
	}
	select {
	case <-closed:
		t.Fatal("upstream ended before client cancellation")
	default:
	}
	response.Body.Close()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("upstream context not cancelled")
	}
	if calls.Load() != 1 {
		t.Fatal("request replayed")
	}
}

func TestMidstreamFailureIsTruncatedWithoutReplay(t *testing.T) {
	var calls atomic.Int32
	proxy, _ := streamingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_, _ = io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		connection.Close()
	}), nil)
	response := request(t, proxy.URL, strings.NewReader("{}"))
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err == nil || string(data) != "data: first\n\n" {
		t.Fatalf("wanted partial stream plus error; got %q %v", data, err)
	}
	if calls.Load() != 1 {
		t.Fatal("request replayed")
	}
}

func TestRequestBoundsDeclaredChunkedAndMisleadingLength(t *testing.T) {
	var calls atomic.Int32
	proxy, _ := streamingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}), func(c *Config) { c.MaxRequestBytes = 8 })
	for _, body := range []io.Reader{strings.NewReader("123456789"), io.NopCloser(strings.NewReader("123456789"))} {
		response := request(t, proxy.URL, body)
		response.Body.Close()
		if response.StatusCode != 413 {
			t.Fatalf("status %d", response.StatusCode)
		}
	}
	up := &fakeUpstream{status: 200}
	config := authedConfig()
	config.MaxRequestBytes = 8
	server := &Server{Config: config, Upstream: BufferedAdapter{Upstream: up}}
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader("123456789"))
	req.ContentLength = 1 // An adapter must bound actual bytes, not trust this value.
	req.Header.Set("Authorization", "Bearer CLIENT")
	recorder := httptest.NewRecorder()
	server.ServeHTTP(recorder, req)
	if recorder.Code != 413 || up.calls != 0 || calls.Load() != 0 {
		t.Fatal("oversized request reached upstream")
	}
}

func TestAuthAndDeclaredLimitRespondBeforeBodyArrives(t *testing.T) {
	var calls atomic.Int32
	proxy, _ := streamingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1) }), func(c *Config) { c.MaxRequestBytes = 8 })
	for _, test := range []struct {
		auth   string
		status int
	}{{"", 401}, {"Authorization: Bearer CLIENT\r\n", 413}} {
		connection, err := net.DialTimeout("tcp", strings.TrimPrefix(proxy.URL, "http://"), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		_, _ = io.WriteString(connection, "POST /v1/messages HTTP/1.1\r\nHost: fixture\r\n"+test.auth+"Content-Length: 100000\r\n\r\n")
		response, err := http.ReadResponse(bufio.NewReader(connection), nil)
		if err != nil {
			connection.Close()
			t.Fatal(err)
		}
		if response.StatusCode != test.status {
			t.Errorf("status %d, wanted %d", response.StatusCode, test.status)
		}
		connection.Close()
	}
	if calls.Load() != 0 {
		t.Fatal("unadmitted body reached upstream")
	}
}

func TestResponseByteLimitAndTotalDeadline(t *testing.T) {
	for _, limit := range []bool{true, false} {
		closed := make(chan struct{})
		proxy, _ := streamingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer close(closed)
			_, _ = io.WriteString(w, "0123456789")
			w.(http.Flusher).Flush()
			if !limit {
				<-r.Context().Done()
			}
		}), func(c *Config) {
			if limit {
				c.MaxResponseBytes = 8
			} else {
				c.TotalSeconds = .05
			}
		})
		response := request(t, proxy.URL, strings.NewReader("{}"))
		_, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err == nil {
			t.Fatal("partial stream falsely completed")
		}
		select {
		case <-closed:
		case <-time.After(time.Second):
			t.Fatal("deadline did not close upstream")
		}
	}
}

type streamingFixture struct{ body io.ReadCloser }

func (u streamingFixture) Open(context.Context, string, string, map[string]string, []byte) (*UpstreamResponse, error) {
	return &UpstreamResponse{200, map[string]string{}, u.body}, nil
}

type countingBody struct {
	reads  int
	closed bool
}

func (b *countingBody) Read(output []byte) (int, error) {
	b.reads++
	if b.reads > 2 {
		return 0, io.EOF
	}
	copy(output, "chunk")
	return 5, nil
}
func (b *countingBody) Close() error { b.closed = true; return nil }

type blockedWriter struct {
	*httptest.ResponseRecorder
	blocked, release chan struct{}
	flushes          int
}

func (w *blockedWriter) Flush() {
	w.flushes++
	if w.flushes == 2 {
		close(w.blocked)
		<-w.release
	}
	w.ResponseRecorder.Flush()
}

func TestBackpressureStopsFurtherUpstreamReads(t *testing.T) {
	body := &countingBody{}
	server := &Server{Config: authedConfig(), Upstream: streamingFixture{body}}
	writer := &blockedWriter{httptest.NewRecorder(), make(chan struct{}), make(chan struct{}), 0}
	req := httptest.NewRequest("POST", "/v1/messages", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer CLIENT")
	done := make(chan struct{})
	go func() { defer close(done); server.ServeHTTP(writer, req) }()
	<-writer.blocked
	if body.reads != 1 {
		t.Fatalf("read ahead %d chunks", body.reads)
	}
	close(writer.release)
	<-done
	if !body.closed {
		t.Fatal("upstream body not closed")
	}
}

func TestIdempotencyHeaderDoesNotEnableAutomaticTransportReplay(t *testing.T) {
	var calls atomic.Int32
	proxy, _ := streamingProxy(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if calls.Add(1) == 1 {
			_, _ = io.WriteString(w, "warm")
			return
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		connection.Close() // Simulate effect committed, then EOF before acknowledgement.
	}), nil)
	response := request(t, proxy.URL, strings.NewReader("{}"))
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	req, _ := http.NewRequest("POST", proxy.URL+"/v1/messages", nil)
	req.Header.Set("Authorization", "Bearer CLIENT")
	req.Header.Set("Idempotency-Key", "caller-correlation-is-not-replay-proof")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 502 || calls.Load() != 2 {
		t.Fatalf("status=%d calls=%d", response.StatusCode, calls.Load())
	}
}
