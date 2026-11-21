// Package supabaseca is Supabase's root certificate and the hosts Basalt
// trusts it for. Supabase signs its databases (db.<ref>.supabase.co) and its
// pooler (*.pooler.supabase.com) with Supabase Root 2021 CA, which no system
// trusts, so sslmode=verify-full against the system's authorities fails on
// every Supabase host. Trust adds that root, next to the system's, for hosts
// under supabase.co and supabase.com only (CONTRACT.md, Supabase's root
// certificate).
package supabaseca

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// rootPEM is Supabase Root 2021 CA as Supabase publishes it
// (https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt). It
// expires on 2031-04-26: replace it, and the pinned fingerprint in the
// test, when Supabase publishes its successor.
//
//go:embed prod-ca-2021.crt
var rootPEM []byte

// root is rootPEM parsed. The file is fixed at build time and a test pins
// its fingerprint, so a parse failure is a broken build.
var root = mustParse(rootPEM)

func mustParse(b []byte) *x509.Certificate {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		panic("supabaseca: the embedded root is not a PEM certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("supabaseca: the embedded root does not parse: " + err.Error())
	}
	return c
}

// Root is Supabase Root 2021 CA.
func Root() *x509.Certificate { return root }

// domains are the registrable domains whose hosts Supabase's root is trusted
// for.
var domains = []string{"supabase.co", "supabase.com"}

// Covers reports whether host is a name under supabase.co or supabase.com:
// compared in lowercase, without a trailing dot, on a label boundary, so
// evilsupabase.co and supabase.co.example.com are not covered.
func Covers(host string) bool {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, d := range domains {
		if strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// Trust makes every TLS config in cfg that verifies the host name
// (sslmode=verify-full) for a host Covers trust ca as well as the system's
// authorities. Each host is matched on its own, so a multi-host connection
// string trusts ca only for its Supabase hosts. A config that already has
// roots (sslrootcert in the string, PGSSLROOTCERT, a service file or
// ~/.postgresql/root.crt) keeps them: the person's choice wins. The host
// name check stays on; verify-ca, require and weaker modes are left as pgx
// built them. Production passes Root; tests pass a test CA.
func Trust(cfg *pgconn.Config, ca *x509.Certificate) {
	var pool *x509.CertPool
	set := func(host string, t *tls.Config) {
		if t == nil || t.InsecureSkipVerify || t.RootCAs != nil || !Covers(host) {
			return
		}
		if pool == nil {
			pool = withSystem(ca)
		}
		t.RootCAs = pool
	}
	set(cfg.Host, cfg.TLSConfig)
	for _, fb := range cfg.Fallbacks {
		set(fb.Host, fb.TLSConfig)
	}
}

// withSystem is the system's authorities and ca. Without a system pool (an
// error loading it) it is ca alone, which is all a Supabase host needs.
func withSystem(ca *x509.Certificate) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	pool.AddCert(ca)
	return pool
}
