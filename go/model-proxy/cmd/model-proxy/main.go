// Command model-proxy is the out-of-process model proxy: it holds the provider
// API key the agent process must not, and forwards only allow-listed
// model-inference routes to a single configured upstream.
//
// Config comes from the proxy's own environment (MAVERICK_PROXY_*), mirroring
// `python -m maverick.model_proxy`:
//
//	MAVERICK_PROXY_UPSTREAM        required, e.g. https://api.anthropic.com
//	MAVERICK_PROXY_KEY            the real provider key (injected, never in the agent)
//	MAVERICK_PROXY_CLIENT_TOKEN   shared secret the agent must present (required)
//	MAVERICK_PROXY_AUTH_STYLE     "bearer" (default) | "x-api-key"
//	MAVERICK_PROXY_LISTEN         host:port (default 127.0.0.1:8765)
//	MAVERICK_PROXY_ALLOWED_ROUTES "POST /v1/messages, ..." (default: inference routes)
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	proxy "github.com/Daybreak-AI-Labs/LightworkOS/go/model-proxy"
)

func main() {
	check := flag.Bool("check", false, "validate config and exit without listening")
	flag.Parse()

	config := proxy.ConfigFromEnv()
	if config == nil {
		fmt.Println("ERROR: no upstream configured (MAVERICK_PROXY_UPSTREAM)")
		os.Exit(1)
	}
	if config.ClientToken == "" {
		fmt.Println("ERROR: MAVERICK_PROXY_CLIENT_TOKEN is required")
		os.Exit(1)
	}
	if err := config.Validate(); err != nil {
		fmt.Println("ERROR:", err)
		os.Exit(1)
	}
	if config.APIKey == "" {
		fmt.Println("WARNING: MAVERICK_PROXY_KEY is empty; forwarded requests will be unauthenticated upstream")
	}
	if *check {
		fmt.Printf("OK: %s:%d -> %s (auth=%s)\n",
			config.ListenHost, config.ListenPort, config.Upstream, config.AuthStyle)
		return
	}

	addr := fmt.Sprintf("%s:%d", config.ListenHost, config.ListenPort)
	timeout := 600 * time.Second
	if config.TotalSeconds > 0 {
		timeout = time.Duration(config.TotalSeconds * float64(time.Second))
	}
	srv := &proxy.Server{Config: config, Upstream: proxy.NewHTTPUpstream(timeout)}
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: min(10*time.Second, timeout),
		MaxHeaderBytes:    65536,
	}
	log.Printf("model proxy on %s -> %s (auth=%s)", addr, config.Upstream, config.AuthStyle)
	log.Fatal(httpSrv.ListenAndServe())
}
