package proxy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// The Go port must make byte-identical decisions to Python's
// maverick.model_proxy. testdata/parity.json is generated from the real Python
// functions by gen_parity.py; this test replays it through the Go port. If
// either side changes, regenerate the fixture and both stay in lockstep.

type jsonConfig struct {
	Upstream      string   `json:"upstream"`
	APIKey        string   `json:"api_key"`
	AuthStyle     string   `json:"auth_style"`
	ClientToken   string   `json:"client_token"`
	AllowedRoutes []string `json:"allowed_routes"`
	AllowHosts    []string `json:"allow_hosts"`
}

func (jc jsonConfig) toConfig() *Config {
	c := &Config{
		Upstream:      jc.Upstream,
		APIKey:        jc.APIKey,
		AuthStyle:     jc.AuthStyle,
		ClientToken:   jc.ClientToken,
		AllowedRoutes: sliceToSet(jc.AllowedRoutes),
	}
	if len(jc.AllowHosts) > 0 {
		c.AllowHosts = sliceToSet(jc.AllowHosts)
	}
	return c
}

func sliceToSet(s []string) map[string]struct{} {
	m := make(map[string]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}
	return m
}

type parityFixture struct {
	BuildRequest []struct {
		Config  jsonConfig        `json:"config"`
		Path    string            `json:"path"`
		Headers map[string]string `json:"headers"`
		Result  struct {
			URL     string            `json:"url"`
			Headers map[string]string `json:"headers"`
			Error   string            `json:"error"`
		} `json:"result"`
	} `json:"build_request"`
	Authenticate []struct {
		Config  jsonConfig        `json:"config"`
		Headers map[string]string `json:"headers"`
		Result  bool              `json:"result"`
	} `json:"authenticate"`
	RouteAllowed []struct {
		Config jsonConfig `json:"config"`
		Method string     `json:"method"`
		Path   string     `json:"path"`
		Result bool       `json:"result"`
	} `json:"route_allowed"`
	ParseAllowedRoutes []struct {
		Value  string   `json:"value"`
		Result []string `json:"result"`
	} `json:"parse_allowed_routes"`
}

func loadFixture(t *testing.T) parityFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "parity.json"))
	if err != nil {
		t.Fatalf("read fixture: %v (run: python3 go/model-proxy/gen_parity.py)", err)
	}
	var f parityFixture
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return f
}

func TestParityBuildRequest(t *testing.T) {
	f := loadFixture(t)
	if len(f.BuildRequest) == 0 {
		t.Fatal("no build_request cases in fixture")
	}
	for i, c := range f.BuildRequest {
		cfg := c.Config.toConfig()
		url, headers, err := BuildRequest(cfg, c.Path, c.Headers)
		if c.Result.Error != "" {
			if err == nil {
				t.Errorf("case %d: expected error %q, got url=%q", i, c.Result.Error, url)
				continue
			}
			if err.Error() != c.Result.Error {
				t.Errorf("case %d: error mismatch\n  Go:     %q\n  Python: %q", i, err.Error(), c.Result.Error)
			}
			continue
		}
		if err != nil {
			t.Errorf("case %d: unexpected error %v", i, err)
			continue
		}
		if url != c.Result.URL {
			t.Errorf("case %d: url\n  Go:     %q\n  Python: %q", i, url, c.Result.URL)
		}
		if !reflect.DeepEqual(headers, c.Result.Headers) {
			t.Errorf("case %d: headers\n  Go:     %v\n  Python: %v", i, headers, c.Result.Headers)
		}
	}
}

func TestParityAuthenticate(t *testing.T) {
	f := loadFixture(t)
	for i, c := range f.Authenticate {
		if got := Authenticate(c.Config.toConfig(), c.Headers); got != c.Result {
			t.Errorf("authenticate case %d: Go=%v Python=%v (headers=%v)", i, got, c.Result, c.Headers)
		}
	}
}

func TestParityRouteAllowed(t *testing.T) {
	f := loadFixture(t)
	for i, c := range f.RouteAllowed {
		if got := RouteAllowed(c.Config.toConfig(), c.Method, c.Path); got != c.Result {
			t.Errorf("route_allowed case %d: Go=%v Python=%v (%s %s)", i, got, c.Result, c.Method, c.Path)
		}
	}
}

func TestParityParseAllowedRoutes(t *testing.T) {
	f := loadFixture(t)
	for i, c := range f.ParseAllowedRoutes {
		got := sortedKeys(ParseAllowedRoutes(c.Value))
		want := append([]string(nil), c.Result...)
		sort.Strings(want)
		if len(got) == 0 && len(want) == 0 {
			continue // nil vs empty slice are equivalent
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("parse_allowed_routes case %d (%q):\n  Go:     %v\n  Python: %v", i, c.Value, got, want)
		}
	}
}
