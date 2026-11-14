package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCheckDoesNotPrintUpstreamCredentials(t *testing.T) {
	t.Setenv("MAVERICK_PROXY_UPSTREAM", "https://account:private-password@models.example/proxy/private-route?token=private-query") // pragma: allowlist secret -- synthetic URL components
	t.Setenv("MAVERICK_PROXY_KEY", "<fixture-provider-key>")
	t.Setenv("MAVERICK_PROXY_CLIENT_TOKEN", "<fixture-client-token>")
	output, err := exec.Command("go", "run", ".", "-check").CombinedOutput()
	if err != nil {
		t.Fatalf("config check failed: %v", err)
	}
	for _, value := range []string{"account", "private-password", "private-route", "private-query"} {
		if strings.Contains(string(output), value) {
			t.Error("the configuration check printed credential-bearing URL components")
		}
	}
	if !strings.Contains(string(output), "https://models.example") {
		t.Error("the configuration check omitted the upstream origin")
	}
}
