package proxy

import (
	"net/url"
	"sort"
	"strings"
)

// scrubError also removes known credentials that have no recognizable shape.
// Longest-first replacement handles a client token contained in the API key.
func (c *Config) scrubError(message string) string {
	secrets := make([]string, 0, 6)
	for _, value := range []string{c.APIKey, c.ClientToken} {
		if value != "" {
			secrets = append(secrets, value, url.QueryEscape(value), url.PathEscape(value))
		}
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	pairs := make([]string, 0, 2*len(secrets))
	for _, value := range secrets {
		if value != "" {
			pairs = append(pairs, value, "[REDACTED:configured_credential]")
		}
	}
	// Preserve recognizable credential shapes before replacing overlapping literals.
	return strings.NewReplacer(pairs...).Replace(scrub(message))
}

// UpstreamLogLabel reports only the configured origin. Userinfo, path, query
// and fragment can carry credentials and are not needed in startup logs.
func (c *Config) UpstreamLogLabel() string {
	u, err := url.Parse(c.Upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "configured upstream"
	}
	return c.scrubError(u.Scheme + "://" + u.Host)
}
