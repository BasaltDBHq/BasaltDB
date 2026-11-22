package pgdial

import (
	"errors"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// foreignKeys are the only parameters root takes from a credential file
// another user wrote (CheckForeignDSN). pgx reads files for the caller from
// others (passfile, service, servicefile, sslkey, sslcert, sslrootcert,
// sslcrl), so root, connecting with a string the engine's user wrote, would
// read root-only files for that user, or block on a FIFO it names.
var foreignKeys = map[string]bool{
	"sslmode":              true,
	"sslnegotiation":       true,
	"sslsni":               true,
	"channel_binding":      true,
	"require_auth":         true,
	"target_session_attrs": true,
	"connect_timeout":      true,
	"application_name":     true,
	"min_protocol_version": true,
	"max_protocol_version": true,
	execModeKey:            true,
}

// foreignURLKeys are the URL parts pgx reads as keys besides the
// parameters: who logs in, where, and the database.
var foreignURLKeys = []string{"user", "password", "host", "port", "dbname"}

// ErrForeignDSN is the refusal of a connection string root does not take
// from another user's file. It never echoes the string, which holds a
// password; callers add who wrote the file and what to do.
var ErrForeignDSN = errors.New("only a postgres:// or postgresql:// URL with a password, no # or ;, and only the parameters " +
	strings.Join(sortedForeignKeys(), ", "))

// ConnectionKey reports whether key is one of the connection string
// parameters a Basalt connection takes from a string someone gave:
// how to reach and trust the server, never a file to read (passfile,
// service, servicefile, sslkey, sslcert, sslrootcert, sslcrl) or who
// logs in. The match is exact: libpq's keys are lower case.
func ConnectionKey(key string) bool { return foreignKeys[key] }

// ConnectionKeys is the sorted list ConnectionKey accepts.
func ConnectionKeys() []string { return sortedForeignKeys() }

func sortedForeignKeys() []string {
	keys := make([]string, 0, len(foreignKeys))
	for k := range foreignKeys {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// CheckForeignDSN accepts, from a credential file root did not write (basalt
// init --remote and basalt engine run as root, reading a file the owner of
// agents/ wrote), only what pgx reads no file for: a URL with an exact
// lower-case postgres:// or postgresql:// prefix (pgx parses any other
// string as keyword/value), no '#' or ';' (where Go's and pgx's URL parsers
// disagree), a password (without one pgx falls back to root's ~/.pgpass),
// and only foreignKeys. pgx's own parser is the authority, with
// ConnStringAllowedKeys refusing any other key before it touches the file
// system; it must then agree with Go's parse on the host, port, database
// and password, which is what the callers read. Anything else is
// ErrForeignDSN.
func CheckForeignDSN(dsn string) error {
	if (!strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://")) ||
		strings.ContainsAny(dsn, "#;") || strings.ContainsFunc(dsn, func(r rune) bool { return r <= ' ' || r == 0x7f }) {
		return ErrForeignDSN
	}
	u, err := url.Parse(dsn)
	if err != nil {
		return ErrForeignDSN
	}
	pw, ok := u.User.Password()
	if !ok || pw == "" {
		return ErrForeignDSN
	}
	for k := range u.Query() {
		if !foreignKeys[k] {
			return ErrForeignDSN
		}
	}
	allowed := append(sortedForeignKeys(), foreignURLKeys...)
	cfg, err := pgconn.ParseConfigWithOptions(dsn, pgconn.ParseConfigOptions{ConnStringAllowedKeys: allowed})
	if err != nil {
		return ErrForeignDSN
	}
	port := uint16(defaultPort)
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return ErrForeignDSN
		}
		port = uint16(n)
	}
	if cfg.Password != pw || cfg.Host != u.Hostname() || cfg.Port != port ||
		cfg.Database != strings.TrimPrefix(u.Path, "/") {
		return ErrForeignDSN
	}
	for _, fb := range cfg.Fallbacks {
		// sslmode=prefer tries TLS then plain, to the same host and port.
		if fb.Host != cfg.Host || fb.Port != cfg.Port {
			return ErrForeignDSN
		}
	}
	return nil
}

// defaultPort is the port a URL without one connects to.
const defaultPort = 5432
