package agent

import (
	"bytes"
	"encoding/json"
	"regexp"
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
	adminCredentialRevise = "Then call again without the connection string. To set up a database, run basalt init --remote and give the person the setup code it prints."
	adminCredentialPerson = "A database connection string with a password was sent through your agent. Basalt refused the call and kept no copy. Change that database password now."
)

// postgresPassword matches a postgres:// or postgresql:// URL (scheme in any
// case) with a password: in its user part (user:secret@host), or as a
// password parameter. A URL without a password does not match.
var postgresPassword = regexp.MustCompile(`(?i)postgres(?:ql)?://(?:[^\s"'/?#@:]*:[^\s"']+@|[^\s"'?#]*\?(?:[^\s"'#]*&)?password=[^&\s"'#]+)`)

// holdsAdminCredential reports whether a tool call's raw arguments hold such
// a URL: in the raw text, or in any string or key once the JSON escapes are
// decoded.
func holdsAdminCredential(raw json.RawMessage) bool {
	if postgresPassword.Match(raw) {
		return true
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	for {
		tok, err := dec.Token()
		if err != nil {
			return false
		}
		if s, ok := tok.(string); ok && postgresPassword.MatchString(s) {
			return true
		}
	}
}

// adminCredentialError is the refusal of a call that holds one. It carries
// no part of the value.
func adminCredentialError() error {
	return &ArgumentError{Reason: ReasonAdminCredential, Message: adminCredentialMessage}
}
