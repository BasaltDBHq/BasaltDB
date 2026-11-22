package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/pkg/trustpin"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// defaultPGPort is Postgres's port when a connection string names none.
const defaultPGPort = 5432

// fetchChain reads the chain host:port presents with the TLS handshake
// alone (trustpin.Fetch); cliIO.fetchChain outside tests.
func fetchChain(ctx context.Context, host string, port int) ([]*x509.Certificate, error) {
	return trustpin.Fetch(ctx, nil, host, port)
}

// pinTarget is the host and port a pin is for.
type pinTarget struct {
	host string
	port int
}

// targetOf is the first host and port of a postgres:// URL, or false for a
// Unix socket or a string without a host.
func targetOf(dsn string) (pinTarget, bool) {
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() == "" || strings.HasPrefix(u.Query().Get(paramHost), "/") {
		return pinTarget{}, false
	}
	host := strings.Split(u.Host, ",")[0]
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		h, p = strings.Trim(host, "[]"), ""
	}
	port := defaultPGPort
	if p != "" {
		if port, err = strconv.Atoi(p); err != nil {
			return pinTarget{}, false
		}
	}
	return pinTarget{host: trustprofile.NormalizeHost(h), port: port}, true
}

// codeTrustRootChanged starts the error of a connection to a pinned host
// that presents another root.
const codeTrustRootChanged = "TRUST_ROOT_CHANGED"

// rootChanged is TRUST_ROOT_CHANGED for err, a certificate of dsn's host
// that did not verify, when that host is pinned and the chain top it
// presents now (read with the TLS handshake alone) is not the pinned one:
// both fingerprints and where the new one is accepted. Nil
// otherwise. Never accepted automatically.
func rootChanged(ctx context.Context, dsn string, err error) error {
	return rootChangedVia(ctx, dsn, err, nil)
}

// rootChangedVia is rootChanged reaching the host through dial (nil: the
// network).
func rootChangedVia(ctx context.Context, dsn string, err error, dial trustpin.Dial) error {
	if !pgdial.CertificateNotVerified(err) {
		return nil
	}
	cfg, perr := pgconn.ParseConfig(dsn)
	if perr != nil {
		return nil //nolint:nilerr // a string pgx cannot parse has no pinned host to compare
	}
	a := trustprofile.Explain(cfg, pgdial.Trust())
	host := trustprofile.NormalizeHost(cfg.Host)
	if a.Profile == nil || a.Profile.Name != trustprofile.PinName(host) {
		return nil
	}
	chain, ferr := trustpin.Fetch(ctx, dial, host, int(cfg.Port))
	if ferr != nil {
		return nil //nolint:nilerr // the chain cannot be read now: the certificate error is said as it is
	}
	top := chain[len(chain)-1]
	pinnedTo := make([]string, 0, len(a.Profile.Certificates()))
	for _, c := range a.Profile.Certificates() {
		if trustprofile.DERSHA256(c) == trustprofile.DERSHA256(top) {
			return nil
		}
		pinnedTo = append(pinnedTo, trustprofile.Fingerprint(c))
	}
	return fmt.Errorf("%w; %s: %s presents the certificate authority SHA-256 %s, but it is pinned to %s. Check it against your "+
		"provider's console; to accept it, run basalt init (basalt init --remote on an agent-operated engine) and trust it on the page it opens",
		err, codeTrustRootChanged, host, trustprofile.Fingerprint(top), strings.Join(pinnedTo, ", "))
}
