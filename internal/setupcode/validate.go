package setupcode

import (
	"encoding/base64"
	"regexp"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/basaltdbhq/basaltdb/internal/channel"
)

// Limits from setup-code.schema.json and CONTRACT.md.
const (
	// Lifetime is how long a code is valid after it is made (CO-13).
	Lifetime = 10 * time.Minute
	// CollectWindow is how long the engine polls CollectAddress after the
	// code was made: the code's life plus the connect service's 30-minute
	// hold (CONTRACT.md, The engine and a connect-only code).
	CollectWindow = Lifetime + 30*time.Minute
	// maxRoleLen is Postgres's NAMEDATALEN - 1.
	maxRoleLen = 63
	// maxTables is the most tables in one list.
	maxTables = 64
	// maxStatementTimeoutMs is one day.
	maxStatementTimeoutMs = 86400000
	maxPort               = 65535
	maxHostLen            = 253
	maxDatabaseLen        = 63
	// uuidTimeHex is the hex digits of a UUIDv7's 48-bit time.
	uuidTimeHex = 12
)

// Patterns from setup-code.schema.json.
var (
	setupIDPattern     = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	prefixPattern      = regexp.MustCompile(`^[a-z][a-z0-9_]{0,19}$`)
	hostPattern        = regexp.MustCompile(`^[A-Za-z0-9.:_-]+$`)
	supabaseRefPattern = regexp.MustCompile(`^[a-z0-9]{20}$`)
	buildPattern       = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$`)
	tablePattern       = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}\.[a-z_][a-z0-9_]{0,62}$`)
	systemTablePattern = regexp.MustCompile(`^(pg_[a-z0-9_]*|information_schema|basalt_meta)\.`)
	agentNamePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]{0,54}$`)
	expiresAtPattern   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	trustPinPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Validate checks p against setup-code.schema.json and the rules the
// schema cannot state (guard.from <= guard.to, < for UPGRADE; at least one
// table; no table in both lists; the role at most 63 bytes; expiresAt no
// later than the setupId's time plus 10 minutes). Failing one is INVALID.
// None of these depend on the clock.
func (p Payload) Validate() error {
	checks := []func() error{p.validateHeader, p.validateTarget, p.validateGuard, p.validateAgent, p.validateExpiry, p.validateEngine, p.validateConnectOnly, p.validateTrustPin}
	for _, c := range checks {
		if err := c(); err != nil {
			return err
		}
	}
	return nil
}

// ValidBuild reports whether v is a version a setup code can carry (the
// payload's build: major.minor.patch, with an optional pre-release).
func ValidBuild(v string) bool { return buildPattern.MatchString(v) }

func invalid(detail string) error { return refuse(RefusalInvalid, detail) }

func (p Payload) validateHeader() error {
	switch {
	case p.Format != Format:
		return refuse(RefusalUnsupportedFormat, "")
	case !setupIDPattern.MatchString(p.SetupID):
		return invalid("setupId is not a UUIDv7")
	case !prefixPattern.MatchString(p.Prefix):
		return invalid("prefix is not a valid role prefix")
	case !buildPattern.MatchString(p.Build):
		return invalid("build is not a version")
	}
	switch p.Kind {
	case KindInstall, KindAgent, KindUpgrade:
		return nil
	}
	return invalid("kind is unknown")
}

func (p Payload) validateTarget() error {
	if p.Target == nil {
		return nil // a connect-only code: validateConnectOnly
	}
	t := *p.Target
	switch {
	case len(t.Host) > maxHostLen || !hostPattern.MatchString(t.Host):
		return invalid("target.host is not a host name")
	case t.Port < 1 || t.Port > maxPort:
		return invalid("target.port is out of range")
	case t.Database == "" || utf8.RuneCountInString(t.Database) > maxDatabaseLen:
		return invalid("target.database is empty or too long")
	case !displayable(t.Database):
		return invalid("target.database has a control or formatting character")
	case t.SupabaseRef != "" && !supabaseRefPattern.MatchString(t.SupabaseRef):
		return invalid("target.supabaseRef is not a project ref")
	}
	return nil
}

// displayable reports whether s is safe to show the person: no control
// characters (C0, DEL, C1) and no format characters (bidi overrides and
// isolates, zero-width characters), which could make a summary line read
// differently from what it says. target.database is the only free-form
// string in a code; every other string field has an ASCII pattern.
func displayable(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}

func (p Payload) validateGuard() error {
	g := p.Guard
	switch {
	case g.From < 0 || g.To < 1:
		return invalid("guard versions are out of range")
	case g.From > g.To:
		return invalid("guard.from is after guard.to")
	case p.Kind == KindUpgrade && g.From == g.To:
		return invalid("an upgrade needs guard.from before guard.to")
	}
	return nil
}

func (p Payload) validateAgent() error {
	a := p.Agent
	switch {
	case p.Kind == KindUpgrade && a != nil:
		return invalid("an upgrade has no agent part")
	case p.Kind == KindUpgrade:
		return nil
	case a == nil:
		return invalid("agent is missing")
	case p.Kind == KindInstall && a.Verifier == "":
		return invalid("an install needs the agent's verifier")
	case a.Verifier != "" && !ValidVerifier(a.Verifier):
		return invalid("agent.verifier is not a SCRAM-SHA-256 verifier with 4096 iterations")
	case !agentNamePattern.MatchString(a.Name):
		return invalid("agent.name is not a valid agent name")
	case len(p.Role()) > maxRoleLen:
		return invalid("the agent's role name is longer than 63 bytes")
	case a.StatementTimeoutMs < 1 || a.StatementTimeoutMs > maxStatementTimeoutMs:
		return invalid("agent.statementTimeoutMs is out of range")
	case a.AllTables != nil:
		return validateAllTables(a)
	case a.Write == nil || a.Read == nil:
		return invalid("agent.write and agent.read are required")
	case len(a.Write)+len(a.Read) == 0:
		return invalid("the agent has no tables")
	}
	if err := validateTables("agent.write", a.Write); err != nil {
		return err
	}
	if err := validateTables("agent.read", a.Read); err != nil {
		return err
	}
	write := make(map[string]bool, len(a.Write))
	for _, t := range a.Write {
		write[t] = true
	}
	for _, t := range a.Read {
		if write[t] {
			return invalid("a table is in both agent.write and agent.read")
		}
	}
	return nil
}

// validateAllTables checks agent.allTables: in place of write and read, and
// schema public only (Supabase's auth and storage are never included).
func validateAllTables(a *Agent) error {
	switch {
	case a.Write != nil || a.Read != nil:
		return invalid("agent.allTables is given with agent.write or agent.read")
	case len(a.AllTables.Schemas) != 1 || a.AllTables.Schemas[0] != publicSchema:
		return invalid("agent.allTables.schemas may only be [\"public\"]")
	}
	return nil
}

// validateConnectOnly checks a code without target: it carries engine (its
// engine collects the database's address with that key), and it is an
// INSTALL or a recovery AGENT code with a verifier. UPGRADE codes and other
// AGENT codes keep target: their engine already has an address.
func (p Payload) validateConnectOnly() error {
	if !p.ConnectOnly() {
		return nil
	}
	switch {
	case p.Engine == nil:
		return invalid("a code without target needs engine")
	case p.Kind == KindUpgrade:
		return invalid("an upgrade needs target")
	case p.Kind == KindAgent && p.Agent.Verifier == "":
		return invalid("an agent change without target needs agent.verifier")
	}
	return nil
}

// validateTrustPin checks trustPin: 64 lowercase hex digits, in a code with
// target of kind AGENT or UPGRADE only (setup-code.schema.json gives the
// INSTALL kind no trustPin).
func (p Payload) validateTrustPin() error {
	switch {
	case p.TrustPin == "":
		return nil
	case p.ConnectOnly():
		return invalid("trustPin is only in a code with target")
	case p.Kind == KindInstall:
		return invalid("an install carries no trustPin")
	case !trustPinPattern.MatchString(p.TrustPin):
		return invalid("trustPin is not a SHA-256 in lowercase hex")
	}
	return nil
}

func validateTables(field string, tables []string) error {
	if len(tables) > maxTables {
		return invalid(field + " has more than 64 tables")
	}
	seen := make(map[string]bool, len(tables))
	for _, t := range tables {
		switch {
		case !tablePattern.MatchString(t):
			return invalid(field + " has a table that is not schema.table of plain identifiers")
		case systemTablePattern.MatchString(t):
			return invalid(field + " has a table in a system schema or basalt_meta")
		case seen[t]:
			return invalid(field + " lists a table twice")
		}
		seen[t] = true
	}
	return nil
}

func (p Payload) validateExpiry() error {
	if !expiresAtPattern.MatchString(p.ExpiresAt) {
		return invalid("expiresAt is not an RFC 3339 UTC time in whole seconds")
	}
	expires, err := p.ExpiresTime()
	if err != nil {
		return err
	}
	created, err := p.CreatedAt()
	if err != nil {
		return err
	}
	if expires.After(created.Add(Lifetime)) {
		return invalid("expiresAt is more than 10 minutes after the code was made")
	}
	return nil
}

// validateEngine checks the engine part: a P-256 SPKI with an
// uncompressed point on the curve. Every guard version records engine keys.
func (p Payload) validateEngine() error {
	if p.Engine == nil {
		return nil
	}
	if _, err := p.Engine.Key(); err != nil {
		return invalid("engine.publicKey is not a P-256 public key")
	}
	return nil
}

// Key is the engine key's SPKI DER, checked as an engine key.
func (e Engine) Key() ([]byte, error) {
	der, err := base64.RawURLEncoding.Strict().DecodeString(e.PublicKey)
	if err != nil {
		return nil, err
	}
	if _, err := channel.ParseEngineKey(der); err != nil {
		return nil, err
	}
	return der, nil
}
