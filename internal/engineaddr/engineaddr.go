// Package engineaddr checks an engine address: the https origin a person's
// tunnel publishes for their engine (CONTRACT.md, Direct transport, the
// grammar). laptop init, record_engine in Postgres and the portal's pin
// page apply the same grammar, and each refuses rather than repairs.
package engineaddr

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Limits of the grammar.
const (
	maxHost   = 253
	maxPort   = 65535
	httpsPort = 443
)

// hostPort is the grammar a pattern can state: LDH labels of 1 to 63
// characters, two or more, the last starting with a letter, then an
// optional decimal port with no leading zero.
var hostPort = regexp.MustCompile(`^((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)(?::([1-9][0-9]{0,4}))?$`)

// refusedSuffixes are names the portal never calls: the person's own
// machine, their local network, and Basalt's own hosts.
var refusedSuffixes = []string{"localhost", "local", "internal", "home.arpa", "basaltvault.app"}

// ErrInvalid is wrapped by every refusal.
var ErrInvalid = errors.New("not an engine address")

// Parse checks raw and returns its written form: the origin with no
// trailing slash. A trailing "/" is the only thing it drops.
func Parse(raw string) (string, error) {
	rest, ok := strings.CutPrefix(raw, "https://")
	if !ok {
		return "", fmt.Errorf("%w: it must start with https://", ErrInvalid)
	}
	rest = strings.TrimSuffix(rest, "/")
	m := hostPort.FindStringSubmatch(rest)
	if m == nil {
		return "", fmt.Errorf("%w: give https://<host>[:<port>] with a lowercase DNS name (not an IP address; an internationalized name in its xn-- form), no path, query or user part", ErrInvalid)
	}
	host := m[1]
	if len(host) > maxHost {
		return "", fmt.Errorf("%w: the host name is longer than %d characters", ErrInvalid, maxHost)
	}
	for _, s := range refusedSuffixes {
		if host == s || strings.HasSuffix(host, "."+s) {
			return "", fmt.Errorf("%w: %s names your own machine, your local network or Basalt's own hosts; give your tunnel's public name", ErrInvalid, host)
		}
	}
	if m[2] != "" {
		port, err := strconv.Atoi(m[2])
		if err != nil || port > maxPort || port == httpsPort {
			return "", fmt.Errorf("%w: the port must be 1 to %d, and 443 is left out", ErrInvalid, maxPort)
		}
	}
	return "https://" + rest, nil
}
