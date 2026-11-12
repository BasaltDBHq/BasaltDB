package setupcode

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Connection strings (CONTRACT.md, basalt init --remote).
const (
	// supabasePlaceholder is the password placeholder Supabase shows in the
	// connection string it offers: a person may paste that line as is. It
	// is no password.
	supabasePlaceholder = ":[YOUR-PASSWORD]@"
	supabasePoolerHost  = ".pooler.supabase.com"
	supabaseDirectHost  = ".supabase.co"
	supabaseDirectStart = "db."
	defaultPort         = 5432
	passwordParam       = "password"
)

// ErrHasPassword is a connection string with a password, which basalt init
// --remote refuses before anything else. The message is the contract's and
// never holds the connection string.
var ErrHasPassword = errors.New("This connection string contains a password. basalt init --remote does not need it " + //nolint:staticcheck // the contract's sentence, shown as is
	"and it must not be shared with an agent: change your database password now.")

// HasPassword reports whether conn carries a password: in the user part of
// a URL, as a password parameter of a URL, or as a password keyword of a
// key=value string. Supabase's [YOUR-PASSWORD] placeholder is not one.
func HasPassword(conn string) bool {
	conn = dropPlaceholder(conn)
	if passwordKeyword.MatchString(conn) {
		return true
	}
	u, err := url.Parse(conn)
	if err != nil {
		// Not a URL Go can parse: a user:secret@ part may still be in it.
		_, rest, ok := strings.Cut(conn, "://")
		at := strings.LastIndexByte(rest, '@')
		return ok && at > 0 && strings.Contains(rest[:at], ":")
	}
	if pw, ok := u.User.Password(); ok && pw != "" {
		return true
	}
	for k := range u.Query() {
		if strings.EqualFold(strings.TrimSpace(k), passwordParam) {
			return true
		}
	}
	return false
}

// passwordKeyword is a password keyword with its =, in any case and with
// any spaces around the = (libpq's key = value form allows them).
var passwordKeyword = regexp.MustCompile(`(?i)` + passwordParam + `\s*=`)

// dropPlaceholder removes Supabase's password placeholder.
func dropPlaceholder(conn string) string {
	return strings.Replace(conn, supabasePlaceholder, "@", 1)
}

// ParseConnURL parses a postgres:// connection string without a password
// (Supabase's placeholder dropped) and returns it with its target: host,
// port and database, and the Supabase project ref when the user
// (postgres.<ref> through the pooler) or the host (db.<ref>.supabase.co)
// names one. Errors never quote the string.
func ParseConnURL(conn string) (*url.URL, Target, error) {
	if HasPassword(conn) {
		return nil, Target{}, ErrHasPassword
	}
	u, err := url.Parse(dropPlaceholder(conn))
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, Target{}, errors.New("the connection string must be a postgres:// URL")
	}
	t, err := TargetOf(u)
	if err != nil {
		return nil, Target{}, err
	}
	return u, t, nil
}

// targetParams are connection parameters that would name another server or
// database than the URL's host, port and path: pgx reads them in place of
// those, so the target in the setup code and the agent's real connection
// could differ. TargetOf refuses them.
var targetParams = []string{"host", "hostaddr", "port", "dbname"}

// TargetParamError is a connection string TargetOf refuses for its Param
// parameter (one of targetParams).
type TargetParamError struct {
	Param string
}

func (e *TargetParamError) Error() string {
	return fmt.Sprintf("the connection string has a %s= parameter; put the host, port and database in the URL itself (postgres://user@host:port/database) and remove %s= from its parameters", e.Param, e.Param)
}

// TargetOf is the database u names: host, port, database and the Supabase
// project ref (see ParseConnURL). It does not look at u's password. A
// host, hostaddr, port or dbname parameter is refused: the target is
// read from the URL's host, port and path only.
func TargetOf(u *url.URL) (Target, error) {
	for k := range u.Query() {
		for _, p := range targetParams {
			if strings.EqualFold(strings.TrimSpace(k), p) {
				return Target{}, &TargetParamError{Param: p}
			}
		}
	}
	host := u.Hostname()
	if host == "" || strings.Contains(u.Host, ",") {
		return Target{}, errors.New("the connection string must name one database host")
	}
	port := defaultPort
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > maxPort {
			return Target{}, errors.New("the connection string's port is not valid")
		}
		port = n
	}
	db := strings.TrimPrefix(u.Path, "/")
	if db == "" || strings.Contains(db, "/") {
		return Target{}, errors.New("the connection string must name the database (postgres://user@host:port/database)")
	}
	t := Target{Host: host, Port: port, Database: db, SupabaseRef: supabaseRef(u.User.Username(), host)}
	if err := (Payload{Target: t}).validateTarget(); err != nil {
		return Target{}, fmt.Errorf("the connection string: %s", InvalidDetail(err))
	}
	return t, nil
}

// supabaseRef is the Supabase project ref the user or the host names, or
// "" when neither does.
func supabaseRef(user, host string) string {
	ref := ""
	host = strings.ToLower(host)
	switch {
	case strings.HasSuffix(host, supabasePoolerHost):
		_, ref, _ = strings.Cut(user, ".")
	case strings.HasPrefix(host, supabaseDirectStart) && strings.HasSuffix(host, supabaseDirectHost):
		ref = strings.TrimSuffix(strings.TrimPrefix(host, supabaseDirectStart), supabaseDirectHost)
	}
	if !supabaseRefPattern.MatchString(ref) {
		return ""
	}
	return ref
}

// NewSetupID returns a UUIDv7 of now (RFC 9562: 48-bit Unix milliseconds,
// then random bits) and the code's expiry: that time plus 24 hours,
// truncated to the second, in the payload's format. random is crypto/rand
// outside tests.
func NewSetupID(now time.Time, random io.Reader) (id, expiresAt string, err error) {
	if random == nil {
		random = rand.Reader
	}
	var u uuid.UUID
	if _, err := io.ReadFull(random, u[:]); err != nil {
		return "", "", fmt.Errorf("random setup id: %w", err)
	}
	ms := now.UnixMilli()
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(ms))
	// RFC 9562: 48 bits of time, then version 7 in the high nibble of byte
	// 6 and the variant 10 in the high bits of byte 8.
	const (
		timeBytes                             = 6
		versionByte, versionMask, versionBits = 6, 0x0f, 0x70
		variantByte, variantMask, variantBits = 8, 0x3f, 0x80
	)
	copy(u[:timeBytes], ts[len(ts)-timeBytes:])
	u[versionByte] = u[versionByte]&versionMask | versionBits
	u[variantByte] = u[variantByte]&variantMask | variantBits
	expires := time.UnixMilli(ms).UTC().Add(Lifetime).Truncate(time.Second)
	return u.String(), expires.Format(time.RFC3339), nil
}

// InvalidDetail is what is wrong in an INVALID refusal, or err's text.
func InvalidDetail(err error) string {
	var e *Error
	if errors.As(err, &e) && e.Detail != "" {
		return e.Detail
	}
	return err.Error()
}
