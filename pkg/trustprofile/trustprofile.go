// Package trustprofile is the trust profiles that say which root
// certificates verify a database's certificate, beyond the system's
// authorities: one JSON file per provider or host, with the PEM files of its
// roots beside it. A profile names the hosts it applies to (match), the
// files of its roots, each pinned by the SHA-256 of its bytes, and
// optionally where the provider publishes each file (source).
//
// The built-in profiles (Supabase and Amazon RDS) are embedded from the
// profiles directory; the engine adds the operator's own from trust.d next
// to its config. A matching profile's roots are added to the system's
// authorities for its hosts only, and only for connections that verify the
// host name (sslmode=verify-full). Each profile has its own pool, so one
// profile's roots never verify another profile's hosts (CONTRACT.md, Trust
// profiles).
package trustprofile

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Origin is where a profile comes from.
type Origin string

// The origins of a profile.
const (
	// BuiltIn profiles are embedded in the binary.
	BuiltIn Origin = "BUILT_IN"
	// Operator profiles are files in trust.d next to the engine's config.
	Operator Origin = "OPERATOR"
)

// Verify values of a profile. VerifyFull checks the chain and the host
// name. VerifyCA, accepted only on a profile whose matches are all exact
// hosts (a pin), checks that the chain ends at one of the profile's own
// roots, not the system's, and does not check the name: for a server whose
// certificate does not name the host (an IP-only certificate).
const (
	VerifyFull = "full"
	VerifyCA   = "ca"
)

// exactPrefix starts a match entry that is one exact host.
const exactPrefix = "="

// Limits on what a profile holds.
const (
	// MaxProfileBytes bounds a profile's JSON file.
	MaxProfileBytes = 64 << 10
	// MaxRootFileBytes bounds one roots file; AWS's RDS bundle is about
	// 175 KB.
	MaxRootFileBytes = 1 << 20
	// maxRoots bounds the roots files of one profile.
	maxRoots = 16
	// maxMatches bounds the match entries of one profile.
	maxMatches = 32
	// maxHostLen is the longest DNS name (RFC 1035).
	maxHostLen = 253
	// maxLabelLen is the longest DNS label.
	maxLabelLen = 63
)

// Spec is a profile's JSON file.
type Spec struct {
	Name  string     `json:"name"`
	Match []string   `json:"match,omitempty"`
	Roots []RootSpec `json:"roots,omitempty"`
	// Source is where the provider publishes each roots file, in the order
	// of Roots, for make check-provider-roots.
	Source []string `json:"source,omitempty"`
	// Verify is "full" (the default) or "ca" (exact hosts only).
	Verify string `json:"verify,omitempty"`
	// Disabled, on an operator profile, turns off the built-in profile of
	// the same name.
	Disabled bool `json:"disabled,omitempty"`
}

// RootSpec is one roots file of a profile: its name next to the profile and
// the SHA-256 of its bytes.
type RootSpec struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Profile is a profile whose files were read and checked.
type Profile struct {
	Spec
	Origin Origin
	// Files are the profile's roots files, in the order of Spec.Roots.
	Files []RootFile
	pool  func() *x509.CertPool
	// own is the profile's roots alone, for VerifyCA.
	own func() *x509.CertPool
}

// RootFile is one roots file, read and checked: its bytes match the pinned
// SHA-256 and hold only CA certificates.
type RootFile struct {
	Name string
	// SHA256 is the lowercase hex SHA-256 of PEM.
	SHA256 string
	// Source is where the provider publishes it, or "".
	Source string
	PEM    []byte
	Certs  []*x509.Certificate
}

// Certificates are every root of the profile, in file order.
func (p *Profile) Certificates() []*x509.Certificate {
	var out []*x509.Certificate
	for _, f := range p.Files {
		out = append(out, f.Certs...)
	}
	return out
}

// Pool is the system's authorities and the profile's roots, built once.
func (p *Profile) Pool() *x509.CertPool { return p.pool() }

// OwnPool is the profile's roots alone, built once: what VerifyCA checks
// a chain against.
func (p *Profile) OwnPool() *x509.CertPool { return p.own() }

// VerifiesCA reports whether p checks the chain against its own roots
// without the host name (VerifyCA on an exact-host profile).
func (p *Profile) VerifiesCA() bool { return p.Verify == VerifyCA && p.Exact() }

// Exact reports whether every match entry of p is one exact host.
func (p *Profile) Exact() bool { return exactOnly(p.Match) }

// Parse reads a profile's JSON and, through read, the roots files it names,
// and checks them: a valid name, at least one valid match entry and one
// roots file (unless disabled), each file's SHA-256 as pinned, and only CA
// certificates in them. A disabled profile is only an operator's and names
// nothing else. An operator profile's suffix entries must not be a public
// suffix on their own (CheckOperatorMatch). Any failure refuses the whole
// profile.
func Parse(raw []byte, origin Origin, read func(name string) ([]byte, error)) (*Profile, error) {
	if len(raw) > MaxProfileBytes {
		return nil, fmt.Errorf("the profile is over %d bytes", MaxProfileBytes)
	}
	var s Spec
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("the profile is not valid JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("the profile holds more than one JSON value")
	}
	if !ValidName(s.Name) {
		return nil, fmt.Errorf("name %q is not a profile name (lowercase letters, digits and dashes, up to 63)", s.Name)
	}
	if s.Disabled {
		return parseDisabled(s, origin)
	}
	match, err := checkMatches(s.Match, origin)
	if err != nil {
		return nil, err
	}
	s.Match = match
	if err := checkVerify(s); err != nil {
		return nil, err
	}
	files, err := readRoots(s, read, exactOnly(s.Match))
	if err != nil {
		return nil, err
	}
	if err := checkNotPublic(s, origin, files); err != nil {
		return nil, err
	}
	p := &Profile{Spec: s, Origin: origin, Files: files}
	p.pool = sync.OnceValue(func() *x509.CertPool { return withSystem(p.Certificates()) })
	p.own = sync.OnceValue(func() *x509.CertPool {
		pool := x509.NewCertPool()
		for _, c := range p.Certificates() {
			pool.AddCert(c)
		}
		return pool
	})
	return p, nil
}

func parseDisabled(s Spec, origin Origin) (*Profile, error) {
	if origin != Operator {
		return nil, errors.New("only an operator profile can be disabled")
	}
	if len(s.Match) > 0 || len(s.Roots) > 0 || len(s.Source) > 0 || s.Verify != "" {
		return nil, errors.New("a disabled profile names only its name and disabled")
	}
	none := func() *x509.CertPool { return nil }
	return &Profile{Spec: s, Origin: origin, pool: none, own: none}, nil
}

func checkMatches(entries []string, origin Origin) ([]string, error) {
	if len(entries) == 0 {
		return nil, errors.New("match is empty")
	}
	if len(entries) > maxMatches {
		return nil, fmt.Errorf("match has more than %d entries", maxMatches)
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		m, err := NormalizeMatch(e)
		if err != nil {
			return nil, err
		}
		if origin == Operator {
			if err := CheckOperatorMatch(m); err != nil {
				return nil, err
			}
		}
		if slices.Contains(out, m) {
			return nil, fmt.Errorf("match entry %q is listed twice", m)
		}
		out = append(out, m)
	}
	return out, nil
}

func checkVerify(s Spec) error {
	switch s.Verify {
	case "", VerifyFull:
		return nil
	case VerifyCA:
		for _, m := range s.Match {
			if !strings.HasPrefix(m, exactPrefix) {
				return fmt.Errorf("verify %q is allowed only when every match entry is an exact host (=host); %q is a suffix", VerifyCA, m)
			}
		}
		return nil
	}
	return fmt.Errorf("verify %q is not %q or %q", s.Verify, VerifyFull, VerifyCA)
}

// exactOnly reports whether every match entry is an exact host.
func exactOnly(match []string) bool {
	for _, m := range match {
		if !strings.HasPrefix(m, exactPrefix) {
			return false
		}
	}
	return len(match) > 0
}

// readRoots reads and checks the roots files. A profile for exact hosts
// only (a pin) may hold a certificate that is not a CA: the server's own
// certificate, when it sends no other, pinned for that host alone.
func readRoots(s Spec, read func(string) ([]byte, error), exact bool) ([]RootFile, error) {
	if len(s.Roots) == 0 {
		return nil, errors.New("roots is empty")
	}
	if len(s.Roots) > maxRoots {
		return nil, fmt.Errorf("roots has more than %d files", maxRoots)
	}
	if len(s.Source) > 0 && len(s.Source) != len(s.Roots) {
		return nil, fmt.Errorf("source has %d entries for %d roots files; give one per file, in order, or none", len(s.Source), len(s.Roots))
	}
	files := make([]RootFile, 0, len(s.Roots))
	seen := map[string]bool{}
	for i, r := range s.Roots {
		f, err := readRoot(r, read, exact)
		if err != nil {
			return nil, err
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("roots file %s is listed twice", f.Name)
		}
		seen[f.Name] = true
		if len(s.Source) > 0 {
			if err := checkSource(s.Source[i]); err != nil {
				return nil, err
			}
			f.Source = s.Source[i]
		}
		files = append(files, f)
	}
	return files, nil
}

func readRoot(r RootSpec, read func(string) ([]byte, error), exact bool) (RootFile, error) {
	if !ValidFileName(r.File) {
		return RootFile{}, fmt.Errorf("roots file %q is not a plain file name next to the profile", r.File)
	}
	want, err := NormalizeSHA256(r.SHA256)
	if err != nil {
		return RootFile{}, fmt.Errorf("roots file %s: %w", r.File, err)
	}
	b, err := read(r.File)
	if err != nil {
		return RootFile{}, fmt.Errorf("roots file %s: %w", r.File, err)
	}
	if len(b) > MaxRootFileBytes {
		return RootFile{}, fmt.Errorf("roots file %s is over %d bytes", r.File, MaxRootFileBytes)
	}
	if got := FileSHA256(b); got != want {
		return RootFile{}, fmt.Errorf("roots file %s has SHA-256 %s, the profile pins %s", r.File, got, want)
	}
	parse := ParseCAs
	if exact {
		parse = ParseCerts
	}
	certs, err := parse(b)
	if err != nil {
		return RootFile{}, fmt.Errorf("roots file %s: %w", r.File, err)
	}
	return RootFile{Name: r.File, SHA256: want, PEM: b, Certs: certs}, nil
}

func checkSource(s string) error {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("source %q is not an https URL", s)
	}
	return nil
}

// ParseCAs is every certificate in a PEM file, each a CA (basicConstraints
// CA:true): a file with no certificate, a block that is not a certificate,
// one that does not parse, one that is not a CA, or bytes after the last
// block is refused.
func ParseCAs(b []byte) ([]*x509.Certificate, error) {
	certs, err := ParseCerts(b)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if !c.BasicConstraintsValid || !c.IsCA {
			return nil, fmt.Errorf("%s (SHA-256 %s) is not a certificate authority (basicConstraints CA:true)", c.Subject, Fingerprint(c))
		}
	}
	return certs, nil
}

// ParseCerts is every certificate in a PEM file, CA or not, refused as
// ParseCAs refuses a file.
func ParseCerts(b []byte) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := b
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("it holds a %s block, not only certificates", block.Type)
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("a certificate does not parse: %w", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("it is not a file of PEM certificates")
	}
	return out, nil
}

// FileSHA256 is the lowercase hex SHA-256 of b.
func FileSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Fingerprint is the SHA-256 of a certificate's DER, uppercase hex in
// colon-separated pairs, as providers and browsers show it.
func Fingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(sum[:]))
	pairs := make([]string, 0, len(sum))
	for i := 0; i < len(h); i += 2 {
		pairs = append(pairs, h[i:i+2])
	}
	return strings.Join(pairs, ":")
}

// NormalizeSHA256 is a SHA-256 in hex, any case, with or without colons,
// as lowercase hex without them.
func NormalizeSHA256(s string) (string, error) {
	h := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", ""))
	if b, err := hex.DecodeString(h); err != nil || len(b) != sha256.Size {
		return "", fmt.Errorf("sha256 %q is not a SHA-256 in hex", s)
	}
	return h, nil
}

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ValidName reports whether s is a profile name: lowercase letters, digits
// and dashes, starting with a letter or digit, up to 63 characters.
func ValidName(s string) bool { return nameRe.MatchString(s) }

var fileRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// ValidFileName reports whether s is a plain file name a profile may name:
// no directory, not hidden, letters, digits, dots, dashes and underscores.
func ValidFileName(s string) bool { return fileRe.MatchString(s) && !strings.HasSuffix(s, ".json") }

var labelRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// NormalizeMatch is a match entry in lowercase without a trailing dot, or
// why it is not one: a DNS suffix (db.example.com matches its hosts below
// it), or =host, one exact host name or IP address.
func NormalizeMatch(entry string) (string, error) {
	m := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(entry)), ".")
	exact := strings.HasPrefix(m, exactPrefix)
	name := strings.TrimPrefix(m, exactPrefix)
	if exact && net.ParseIP(name) != nil {
		return exactPrefix + net.ParseIP(name).String(), nil
	}
	if err := checkDNSName(name); err != nil {
		return "", fmt.Errorf("match entry %q: %w", entry, err)
	}
	if !exact && allNumeric(name) {
		return "", fmt.Errorf("match entry %q is an address; an address can only be an exact host (=%s)", entry, name)
	}
	return m, nil
}

func checkDNSName(name string) error {
	if name == "" || len(name) > maxHostLen {
		return errors.New("not a host name")
	}
	for l := range strings.SplitSeq(name, ".") {
		if len(l) > maxLabelLen || !labelRe.MatchString(l) {
			return fmt.Errorf("label %q is not a DNS label (no wildcards; letters, digits and dashes)", l)
		}
	}
	return nil
}

func allNumeric(name string) bool {
	return strings.Trim(name, "0123456789.") == ""
}

// NormalizeHost is a host as profiles compare it: lowercase, without a
// trailing dot.
func NormalizeHost(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// matchLen is how long the entry of p that matches host is, 0 for none: an
// exact entry matches the host itself, a suffix entry a host below it on a
// label boundary (x.supabase.co, not evilsupabase.co or supabase.co).
func (p *Profile) matchLen(host string, exact bool) int {
	best := 0
	for _, m := range p.Match {
		switch {
		case exact && strings.HasPrefix(m, exactPrefix):
			if strings.TrimPrefix(m, exactPrefix) == host {
				return len(m)
			}
		case !exact && !strings.HasPrefix(m, exactPrefix):
			if strings.HasSuffix(host, "."+m) && len(m) > best {
				best = len(m)
			}
		}
	}
	return best
}

// withSystem is the system's authorities and cas. Without a system pool (an
// error loading it) it is cas alone. The pool is never changed after.
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

// pinPrefix starts the name of a pin's profile.
const pinPrefix = "pin-"

// PinName is the name of the pin profile for host: pin- and the host's
// letters and digits, the rest as dashes, up to the longest name. Two hosts
// can give one name; the pin's match says which host it is for.
func PinName(host string) string {
	return pinPrefix + nameOf(NormalizeHost(host), maxLabelLen-len(pinPrefix))
}

func nameOf(host string, limit int) string {
	var b strings.Builder
	for _, r := range host {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	name := strings.Trim(b.String(), "-")
	if len(name) > limit {
		name = strings.TrimRight(name[:limit], "-")
	}
	if name == "" {
		return "database"
	}
	return name
}

// DERSHA256 is the lowercase hex SHA-256 of a certificate's DER: the
// fingerprint pins, --trust-root and the ledger compare.
func DERSHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// providerNames are the providers of the built-in profiles as a person names
// them.
var providerNames = map[string]string{"aws-rds": "Amazon RDS", "supabase": "Supabase"}

// ProviderName is the provider a built-in profile is for, as the confirm
// step names it ("Amazon RDS"); another profile's own name.
func ProviderName(profile string) string {
	if n, ok := providerNames[profile]; ok {
		return n
	}
	return profile
}
