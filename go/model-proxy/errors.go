package proxy

import (
	"fmt"
	"strings"
)

// HostNotAllowedError is the SSRF guard failure from BuildRequest: the resolved
// upstream host is outside the allow-set. Its message mirrors the Python
// ValueError: `upstream host 'h' not in allow-set ['a', 'b']`.
type HostNotAllowedError struct {
	Host    string
	Allowed []string // sorted, like Python's sorted(allowed)
}

func (e *HostNotAllowedError) Error() string {
	quoted := make([]string, len(e.Allowed))
	for i, h := range e.Allowed {
		quoted[i] = "'" + h + "'"
	}
	// Mirror Python's f"upstream host {host!r} ...": a real host reprs as
	// 'host', but an unparseable upstream URL yields host=None, which reprs as
	// the bare word None (no quotes). The Go zero value for that case is "".
	host := "'" + e.Host + "'"
	if e.Host == "" {
		host = "None"
	}
	return fmt.Sprintf("upstream host %s not in allow-set [%s]",
		host, strings.Join(quoted, ", "))
}
