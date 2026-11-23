package setupcode

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/core/supabase"

	"github.com/google/uuid"
)

// Connection strings (CONTRACT.md, basalt init --remote).
const (
	supabaseDirectHost  = ".supabase.co"
	supabaseDirectStart = "db."
	defaultPort         = 5432
)

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
	if err := (Payload{Target: &t}).validateTarget(); err != nil {
		return Target{}, fmt.Errorf("the connection string: %s", InvalidDetail(err))
	}
	return t, nil
}

// ConnTarget is the database a parsed connection (pgx's config: host,
// port, database and user) connects to, with the Supabase project ref when
// its user or host names one. A Unix socket directory is its host.
func ConnTarget(host string, port int, database, user string) Target {
	return Target{Host: host, Port: port, Database: database, SupabaseRef: supabaseRef(user, host)}
}

// supabaseRef is the Supabase project ref the user or the host names, or
// "" when neither does.
func supabaseRef(user, host string) string {
	ref := ""
	host = strings.ToLower(host)
	switch {
	case supabase.PoolerHost(host):
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
// then random bits) and the code's expiry: that time plus 10 minutes,
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
