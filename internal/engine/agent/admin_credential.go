package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

// ReasonAdminCredential is INVALID_ARGUMENT for a tool call whose arguments
// hold a Postgres connection URL with a password (CONTRACT.md, Agents and
// the admin credential).
const ReasonAdminCredential = "ADMIN_CREDENTIAL" //nolint:gosec // an error reason, not a credential

const (
	adminCredentialMessage = "an argument holds a database connection string with a password; basalt did not use or keep it. " +
		"An agent never asks for, accepts or passes the admin connection string or password."
	adminCredentialAsk = "Tell the person that a database connection string with a password was in your call and that basalt did not keep it, " +
		"and ask them to change that database password now. Do not repeat or use the string."
	adminCredentialRevise = "Then call again without the connection string. To set up, run basalt init (basalt init --remote where the person cannot reach this computer) and show the person the link it prints."
	adminCredentialPerson = "A database connection string with a password was sent through your agent. Basalt refused the call and kept no copy. Change that database password now."
)

// postgresPassword matches a postgres:// or postgresql:// URL (scheme in any
// case) with a password: in its user part (user:secret@host), or as a
// password parameter. A URL without a password does not match.
//
// postgresPasswordInString is the same match for one decoded string or key,
// where a quote cannot end the value: the user part and the password value
// may hold quotes. The raw JSON text keeps the stricter form, because there a
// quote can end one string and start the next.
// postgresPassword matches the raw request text; it stops at a quote, so
// it cannot run from one JSON string into the next.
var postgresPassword = regexp.MustCompile(`(?i)postgres(?:ql)?://(?:[^\s"'/?#@:]*:\S+@|[^\s"'?#]*\?(?:[^\s"'#]*&)?password=[^&\s"'#]+)`)

// postgresPasswordInString matches one string: a URL of the postgres
// scheme family (postgres, postgresql, jdbc:postgresql, postgresql+<driver>)
// with a password in its user part or as a password parameter. A password
// may hold a quote or a slash, or, without a slash, a space.
var postgresPasswordInString = regexp.MustCompile(`(?i)postgres(?:ql)?(?:\+[a-z0-9_]+)?://` +
	`(?:[^\s/?#@:]*:(?:\S+|[^/@'"\r\n]{1,256})@|[^\s?#]*\?(?:[^\s#]*&)?password\s*=[^&\s#]+)`)

// keyValuePair is one libpq key=value pair: a single-quoted value may hold
// spaces and backslash escapes.
const keyValuePair = `([a-z_]+)\s*=\s*(?:'(?:[^'\\]|\\.)*'|[^\s']+)`

// keyValueRun is a run of key=value pairs that only whitespace separates,
// as libpq reads a key/value connection string. SQL puts a word or a comma
// between its comparisons, so `SET password = $1 WHERE user = $2` is two
// runs, not one.
var (
	keyValueRun  = regexp.MustCompile(`\b` + keyValuePair + `(?:\s+` + keyValuePair + `)*`)
	keyValueKeys = regexp.MustCompile(keyValuePair)
)

func holdsAdminCredential(raw json.RawMessage) bool {
	if postgresPassword.Match(raw) {
		return true
	}
	if !json.Valid(raw) {
		return holdsCredentialString(string(raw))
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if s, ok := tok.(string); ok && holdsCredentialString(s) {
			return true
		}
	}
}

// holdsCredentialString: s, as given or normalised, holds a connection
// string with a password.
func holdsCredentialString(s string) bool {
	if postgresPasswordInString.MatchString(s) {
		return true
	}
	n := normalise(s)
	return postgresPasswordInString.MatchString(n) || keyValuePassword(n)
}

// keyValuePassword: lower-case s holds a libpq key/value connection string
// with a password key next to a host, hostaddr, user or dbname key.
func keyValuePassword(s string) bool {
	for _, run := range keyValueRun.FindAllString(s, -1) {
		password, target := false, false
		for _, m := range keyValueKeys.FindAllStringSubmatch(run, -1) {
			switch m[1] {
			case "password":
				password = true
			case "host", "hostaddr", "user", "dbname":
				target = true
			}
		}
		if password && target {
			return true
		}
	}
	return false
}

// normalise undoes the encodings an agent's call may carry a connection
// string in, until nothing changes: JSON escapes (\uXXXX, \/, \\, \")
// left in a string that is itself JSON text, percent-encoding, and
// invisible format characters (a zero-width space in the scheme). Then it
// lower-cases. Each round only shortens s, so the loop ends.
func normalise(s string) string {
	for range 8 {
		next := percentDecode(jsonUnescape(s))
		if next == s {
			break
		}
		s = next
	}
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	return strings.ToLower(s)
}

// jsonUnescape decodes one level of JSON string escapes; anything else is
// kept as it is.
func jsonUnescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		switch c := s[i+1]; c {
		case '\\', '/', '"':
			b.WriteByte(c)
			i++
		case 'u':
			if i+6 <= len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil {
					b.WriteRune(rune(v))
					i += 5
					continue
				}
			}
			b.WriteByte(s[i])
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// percentDecode decodes every %XX; a % without two hex digits is kept.
func percentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
			v, _ := strconv.ParseUint(s[i+1:i+3], 16, 8)
			b.WriteByte(byte(v))
			i += 2
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

func adminCredentialError() error {
	return &ArgumentError{Reason: ReasonAdminCredential, Message: adminCredentialMessage}
}

// adminCredentialToolError is the refusal as a tool error with its steps,
// for the tools that answer without the service (the engine-down tools).
func adminCredentialToolError(tool string) *mcp.ToolError {
	te := &mcp.ToolError{Code: CodeInvalidArgument, Reason: ReasonAdminCredential, Message: adminCredentialMessage, PersonMessage: adminCredentialPerson}
	b := NewSteps()
	invalidArgumentSteps(b, te, failure{tool: tool})
	te.NextSteps, _ = b.Build() // fixed steps: they cannot fail
	return te
}

// refuseAdminCredential runs call, after refusing a call that holds one.
func refuseAdminCredential(tool string, call func(context.Context, json.RawMessage) (any, error)) func(context.Context, json.RawMessage) (any, error) {
	return func(ctx context.Context, raw json.RawMessage) (any, error) {
		if holdsAdminCredential(raw) {
			return nil, adminCredentialToolError(tool)
		}
		return call(ctx, raw)
	}
}
