// Package providerca is the root certificates of database providers whose
// certificates chain to roots no system trusts, and the hosts Basalt trusts
// each provider's roots for. Supabase signs its databases
// (db.<ref>.supabase.co) and its pooler (*.pooler.supabase.com) under
// Supabase Root 2021 CA; Amazon RDS and Aurora sign theirs under a root per
// region from AWS's global bundle. Without those roots sslmode=verify-full
// against the system's authorities fails on every such host.
//
// Trust adds a provider's roots, next to the system's, for that provider's
// hosts only: a Supabase root never verifies an RDS host, an RDS root never
// verifies a Supabase host, and every other host keeps the system's
// authorities (CONTRACT.md, Provider root certificates).
//
// Each embedded file is the provider's published file byte for byte, pinned
// by SHA-256 in the table and again in the tests. make check-provider-roots
// downloads each published file and compares it; it needs the network and
// is not part of CI.
package providerca

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5/pgconn"
)

// Provider names: the keys of Override and the argument of Roots.
const (
	Supabase = "supabase"
	RDS      = "rds"
)

// A provider is a name, the registrable domains whose hosts its roots are
// trusted for, and the embedded files that hold those roots.
type provider struct {
	name    string
	domains []string
	files   []rootsFile
	roots   func() []*x509.Certificate
	pool    func() *x509.CertPool
}

// A rootsFile is one embedded file of roots and where the provider
// publishes it, so make check-provider-roots can compare the two.
type rootsFile struct {
	path   string // the embedded file, in this directory
	pem    []byte // embedded byte for byte as published
	url    string // where the provider publishes it
	inCode bool   // url serves source code holding the PEM, not the PEM file itself
	sha256 string // of the embedded file; the tests pin it again
}

// supabaseRoot2021PEM is Supabase Root 2021 CA, valid 2021-04-28 to
// 2031-04-26. Supabase publishes it as prod-ca-2021.crt.
//
//go:embed supabase-root-2021.crt
var supabaseRoot2021PEM []byte

// supabaseRoot2025PEM is Supabase's second root: the same name with a new
// key, valid 2025-09-03 to 2035-09-01. The download URL does not serve it;
// Supabase's CLI ships it as a TypeScript module that exports the PEM.
//
//go:embed supabase-root-2025.crt
var supabaseRoot2025PEM []byte

// rdsBundlePEM is AWS's global bundle for RDS and Aurora: one root per
// region and key type (114 on 21 November 2026). AWS adds a root when it
// opens a region, so make check-provider-roots compares it with the
// published file. It holds no root for the China or GovCloud regions, which
// AWS publishes separately: hosts there are matched and get this bundle,
// which cannot verify them, so they need the person's own sslrootcert.
//
//go:embed rds-global-bundle.pem
var rdsBundlePEM []byte

var providers = []provider{
	newProvider(Supabase, []string{"supabase.co", "supabase.com"},
		rootsFile{
			path:   "supabase-root-2021.crt",
			pem:    supabaseRoot2021PEM,
			url:    "https://supabase-downloads.s3-ap-southeast-1.amazonaws.com/prod/ssl/prod-ca-2021.crt",
			sha256: "700723581420dd1ac98fd7e9ac529f0ef210eadcaf87fc868a3ad7d114c2f3b7",
		},
		rootsFile{
			path:   "supabase-root-2025.crt",
			pem:    supabaseRoot2025PEM,
			url:    "https://raw.githubusercontent.com/supabase/cli/develop/apps/cli/src/command-internal/supabase-ca-templates/prod-ca-2025.ts",
			inCode: true,
			sha256: "5865d2b26f6128e5795a13ae58b6543599bdb82d808f7f62e3c9a8d7e8527970",
		},
	),
	newProvider(RDS, []string{"rds.amazonaws.com", "rds.amazonaws.com.cn"},
		rootsFile{
			path:   "rds-global-bundle.pem",
			pem:    rdsBundlePEM,
			url:    "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem",
			sha256: "90a6f1a7978a1b1b096dca6c57511ca48d3b8cf052f8e704baf358f34ea2f21b",
		},
	),
}

// newProvider parses the provider's files and builds its pool, each once and
// only when first needed, so a command that never connects to a provider's
// host parses nothing.
func newProvider(name string, domains []string, files ...rootsFile) provider {
	roots := sync.OnceValue(func() []*x509.Certificate {
		out := make([]*x509.Certificate, 0, len(files))
		for _, f := range files {
			out = append(out, mustParse(f.path, f.pem)...)
		}
		return out
	})
	return provider{
		name:    name,
		domains: domains,
		files:   files,
		roots:   roots,
		pool:    sync.OnceValue(func() *x509.CertPool { return withSystem(roots()) }),
	}
}

// mustParse is every certificate in an embedded file. The files are fixed at
// build time and the tests pin them, so a file with no certificate, a block
// that is not a certificate, one that does not parse, or bytes after the
// last block is a broken build.
func mustParse(path string, b []byte) []*x509.Certificate {
	var out []*x509.Certificate
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			panic("providerca: " + path + " holds a " + block.Type + " block")
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic("providerca: a certificate in " + path + " does not parse: " + err.Error())
		}
		out = append(out, c)
	}
	if len(out) == 0 || strings.TrimSpace(string(rest)) != "" {
		panic("providerca: " + path + " is not a file of PEM certificates")
	}
	return out
}

// Roots are the named provider's embedded roots, in file order, or nil for
// a name that is no provider. The slice is a copy.
func Roots(name string) []*x509.Certificate {
	for _, p := range providers {
		if p.name == name {
			return append([]*x509.Certificate(nil), p.roots()...)
		}
	}
	return nil
}

// For is the name of the provider whose domains hold host, or false: compared
// in lowercase, without a trailing dot, on a label boundary, so
// evilsupabase.co, supabase.co.example.com and the bare domain itself are no
// provider's.
func For(host string) (string, bool) {
	p, ok := providerFor(host)
	return p.name, ok
}

func providerFor(host string) (provider, bool) {
	h := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, p := range providers {
		for _, d := range p.domains {
			if strings.HasSuffix(h, "."+d) {
				return p, true
			}
		}
	}
	return provider{}, false
}

// Override replaces a provider's roots, by provider name, in Trust. Tests
// set test CAs to stand in for a provider's roots; a provider not named
// keeps its embedded roots. Production passes nil.
type Override map[string][]*x509.Certificate

// Trust makes every TLS config in cfg that verifies the host name
// (sslmode=verify-full) for a provider's host trust that provider's roots
// as well as the system's authorities. Each host is matched on its own, so
// a multi-host connection string trusts each provider's roots only for that
// provider's hosts, and no extra roots for other hosts. A config that
// already has roots (sslrootcert in the string, PGSSLROOTCERT, a service
// file or ~/.postgresql/root.crt) keeps them: the person's choice wins. The
// host name check stays on; verify-ca, require and weaker modes are left as
// pgx built them.
func Trust(cfg *pgconn.Config, override Override) {
	pools := map[string]*x509.CertPool{}
	set := func(host string, t *tls.Config) {
		if t == nil || t.InsecureSkipVerify || t.RootCAs != nil {
			return
		}
		p, ok := providerFor(host)
		if !ok {
			return
		}
		pool, ok := pools[p.name]
		if !ok {
			if cas, over := override[p.name]; over {
				pool = withSystem(cas)
			} else {
				pool = p.pool()
			}
			pools[p.name] = pool
		}
		t.RootCAs = pool
	}
	set(cfg.Host, cfg.TLSConfig)
	for _, fb := range cfg.Fallbacks {
		set(fb.Host, fb.TLSConfig)
	}
}

// withSystem is the system's authorities and cas. Without a system pool (an
// error loading it) it is cas alone, which is all a provider's host needs.
// The pool is shared by every config Trust sets and never changed after.
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
