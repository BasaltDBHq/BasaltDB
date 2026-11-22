package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"

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
var postgresPasswordInString = regexp.MustCompile(`(?i)postgres(?:ql)?://(?:[^\s/?#@:]*:\S+@|[^\s?#]*\?(?:[^\s#]*&)?password=[^&\s#]+)`)

var postgresPassword = regexp.MustCompile(`(?i)postgres(?:ql)?://(?:[^\s"'/?#@:]*:\S+@|[^\s"'?#]*\?(?:[^\s"'#]*&)?password=[^&\s"'#]+)`)

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
		if s, ok := tok.(string); ok && postgresPasswordInString.MatchString(s) {
			return true
		}
	}
}

// adminCredentialError is the refusal of a call that holds one. It carries
// no part of the value.
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
