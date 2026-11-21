// Package supabaseca is Supabase's root certificates and the hosts Basalt
// trusts them for. Supabase signs its databases (db.<ref>.supabase.co) and
// its pooler (*.pooler.supabase.com) under a root named Supabase Root 2021
// CA, which no system trusts, so sslmode=verify-full against the system's
// authorities fails on every Supabase host. Trust adds Supabase's roots,
// next to the system's, for hosts
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

// Supabase publishes two self-signed roots, both named Supabase Root 2021
// CA, with different keys:
//   - prod-ca-2021.crt, valid 2021-04-28 to 2031-04-26
//     (https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt);
//   - prod-ca-2025.crt, issued September 2025, valid 2025-09-03 to
//     2035-09-01, the one Supabase's own CLI ships
//     (github.com/supabase/cli, supabase-ca-templates/prod-ca-2025.ts).
//
// Both are trusted, so a host signed under either verifies. Replace a file,
// and its pinned fingerprint in the test, when Supabase publishes its
// successor.
var (
	//go:embed prod-ca-2021.crt
	root2021PEM []byte
	//go:embed prod-ca-2025.crt
	root2025PEM []byte
)

// roots are the embedded roots parsed. The files are fixed at build time and
// a test pins their fingerprints, so a parse failure is a broken build.
var roots = []*x509.Certificate{mustParse(root2021PEM), mustParse(root2025PEM)}

func mustParse(b []byte) *x509.Certificate {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE" {
		panic("supabaseca: an embedded root is not a PEM certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic("supabaseca: an embedded root does not parse: " + err.Error())
	}
	return c
}

// Roots are Supabase's roots, the 2021 one first. The slice is a copy.
func Roots() []*x509.Certificate { return append([]*x509.Certificate(nil), roots...) }

// domains are the registrable domains whose hosts Supabase's roots are trusted
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
// (sslmode=verify-full) for a host Covers trust cas as well as the system's
// authorities. Each host is matched on its own, so a multi-host connection
// string trusts cas only for its Supabase hosts. A config that already has
// roots (sslrootcert in the string, PGSSLROOTCERT, a service file or
// ~/.postgresql/root.crt) keeps them: the person's choice wins. The host
// name check stays on; verify-ca, require and weaker modes are left as pgx
// built them. Production passes Roots; tests pass test CAs.
func Trust(cfg *pgconn.Config, cas ...*x509.Certificate) {
	var pool *x509.CertPool
	set := func(host string, t *tls.Config) {
		if t == nil || t.InsecureSkipVerify || t.RootCAs != nil || !Covers(host) {
			return
		}
		if pool == nil {
			pool = withSystem(cas)
		}
		t.RootCAs = pool
	}
	set(cfg.Host, cfg.TLSConfig)
	for _, fb := range cfg.Fallbacks {
		set(fb.Host, fb.TLSConfig)
	}
}

// withSystem is the system's authorities and cas. Without a system pool (an
// error loading it) it is cas alone, which is all a Supabase host needs.
func withSystem(cas []*x509.Certificate) *x509.CertPool {
	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	for _, ca := range cas {
		pool.AddCert(ca)
	}
	return pool
}
