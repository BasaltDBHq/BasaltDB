package setupcode

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/core/supabase"
)

// Address is a collected database address: never a password.
type Address struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Database    string `json:"database"`
	SupabaseRef string `json:"supabaseRef,omitempty"`
}

// The shape limits of a collected address (CONTRACT.md, The engine and a
// connect-only code, Checking the address itself). The host's and port's
// limits (maxHostLen, maxPort) and the Supabase ref's shape
// (supabaseRefPattern) are the same as a setup code's target.
var (
	hostShape     = regexp.MustCompile(`^[A-Za-z0-9.-]{1,253}$`)
	databaseShape = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,63}$`)
)

// ErrAddressInvalid is an address the engine refuses: its shape, or a host
// that resolves to an address outside global unicast (problem
// ADDRESS_INVALID). Its text names nothing of the address, which whoever
// ran the setup chose.
var ErrAddressInvalid = errors.New("the address the connect service handed over was refused")

// Check refuses an address whose host, port, database or Supabase ref is
// not of the contract's shape, before anything of it is shown or used.
func (a Address) Check() error {
	switch {
	case !hostShape.MatchString(a.Host) || len(a.Host) > maxHostLen || strings.HasPrefix(a.Host, "-") || strings.Contains(a.Host, ".."),
		a.Port < 1 || a.Port > maxPort,
		!databaseShape.MatchString(a.Database),
		a.SupabaseRef != "" && !supabaseRefPattern.MatchString(a.SupabaseRef):
		return ErrAddressInvalid
	}
	if err := a.checkRef(); err != nil {
		return err
	}
	return a.checkAsDatabaseURL()
}

// checkAsDatabaseURL applies the rules of basalt init --remote's
// --database-url (step 1) to the connection string the agent would log in
// with at a: the database that string names, as init reads it, must be
// exactly a, Supabase ref included. So the engine accepts no address that
// would read as another database.
func (a Address) checkAsDatabaseURL() error {
	u := &url.URL{
		Scheme: "postgres", User: url.User(LoginUser(a, "basalt")),
		Host: net.JoinHostPort(a.Host, strconv.Itoa(a.Port)), Path: "/" + a.Database,
	}
	t, err := TargetOf(u)
	if err != nil || t.Host != a.Host || t.Port != a.Port || t.Database != a.Database || t.SupabaseRef != a.SupabaseRef {
		return ErrAddressInvalid
	}
	return nil
}

// Canonical is a as a reach report names it: the host and the Supabase ref
// in lowercase (CONTRACT.md, Connect, The reach check). The port and the
// database are as given.
func (a Address) Canonical() Address {
	a.Host, a.SupabaseRef = strings.ToLower(a.Host), strings.ToLower(a.SupabaseRef)
	return a
}

// Key names a's canonical form without holding it: the probe cache keeps
// this, never the address.
func (a Address) Key() string {
	c := a.Canonical()
	sum := sha256.Sum256([]byte(c.Host + "\n" + strconv.Itoa(c.Port) + "\n" + c.Database + "\n" + c.SupabaseRef))
	return hex.EncodeToString(sum[:])
}

// checkRef ties a Supabase ref to the host, since Name shows the ref in
// place of the host and the person confirms what Name says: the project's
// own host db.<ref>.supabase.co, or Supabase's pooler, where the agent logs
// in as <role>.<ref> and the pooler routes the login to that project.
func (a Address) checkRef() error {
	if a.SupabaseRef == "" {
		return nil
	}
	host := strings.ToLower(a.Host)
	if host == "db."+a.SupabaseRef+supabaseDirect || supabase.PoolerHost(host) {
		return nil
	}
	return ErrAddressInvalid
}

// supabaseDirect is the host suffix of a Supabase project's own database.
const supabaseDirect = ".supabase.co"

// Name is the database as the agent names it to the person: "Supabase
// project <ref>, database <db>" or "<host>:<port>, database <db>".
func (a Address) Name() string {
	if a.SupabaseRef != "" {
		return "Supabase project " + a.SupabaseRef + ", database " + a.Database
	}
	return net.JoinHostPort(a.Host, strconv.Itoa(a.Port)) + ", database " + a.Database
}

// String names the database, as Name.
func (a Address) String() string { return a.Name() }

// LoginUser is the user the agent's role logs in as at a: <role>.<ref>
// through Supabase's pooler, the role otherwise.
func LoginUser(a Address, role string) string {
	if a.SupabaseRef != "" && supabase.PoolerHost(a.Host) {
		return role + "." + a.SupabaseRef
	}
	return role
}
