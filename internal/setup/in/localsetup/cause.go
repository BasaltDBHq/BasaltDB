package localsetup

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// maxCauseMessage bounds a cause's message in the log.
const maxCauseMessage = 500

// secretForms are the shapes a secret takes in an error's text: a
// connection URL, a password parameter or literal, and a generated agent
// password (hex, as guard.NewPassword makes it).
var secretForms = []*regexp.Regexp{
	regexp.MustCompile(`(?i)postgres(ql)?://\S+`),
	regexp.MustCompile(`(?i)password\s*=\s*\S+`),
	regexp.MustCompile(`(?i)password\s+'[^']*'`),
	regexp.MustCompile(`(?i)\b[0-9a-f]{32,}\b`),
}

const redacted = "[redacted]"

// describeError is the message and detail of the database error in err,
// false when it carries none (Backend.DatabaseError).
type describeError func(err error) (message, detail string, ok bool)

// causeOf is err's cause at step: the Postgres SQLSTATE and the server's
// own message (never its hint or query position, and its detail only for
// the guard's own BS… codes: another detail can quote the statement) when
// the database refused it, else the error's text; the
// message redacted. describe nil reads no message: the SQLSTATE and the
// error's text then.
func causeOf(step string, err error, describe describeError) *Cause {
	c := &Cause{Step: setup.FailedStep(step, err)}
	if err == nil {
		return c
	}
	var message, detail string
	var ok bool
	if describe != nil {
		message, detail, ok = describe(err)
	}
	switch {
	case ok:
		c.SQLState, c.Message = setup.SQLStateOf(err), message
		if strings.HasPrefix(c.SQLState, "BS") && detail != "" {
			// The guard's own refusals (BS…) put the reason in the detail,
			// written by basalt_meta's SQL, never a quoted statement.
			c.Message += ": " + detail
		}
	case describe == nil:
		c.SQLState, c.Message = setup.SQLStateOf(err), err.Error()
	default:
		c.Message = err.Error()
	}
	c.Message = redact(c.Message)
	return c
}

// redact removes every secret form from s, and each of secrets (a
// password the caller knows) wherever it appears, then bounds it.
func redact(s string, secrets ...string) string {
	for _, secret := range secrets {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, redacted)
		}
	}
	for _, re := range secretForms {
		s = re.ReplaceAllString(s, redacted)
	}
	if len(s) > maxCauseMessage {
		s = strings.ToValidUTF8(s[:maxCauseMessage], "") + "…"
	}
	return s
}

// scrub removes from err's cause the admin password of adminURL and the
// password it gives, wherever they appear: a password that has none of
// the shapes redact knows still never reaches the log.
func scrub(err error, adminURL string) error {
	var r *RefusalError
	if !errors.As(err, &r) || r.Cause == nil {
		return err
	}
	var secrets []string
	if u, perr := url.Parse(adminURL); perr == nil && u.User != nil {
		if pw, ok := u.User.Password(); ok {
			secrets = append(secrets, pw, url.QueryEscape(pw), url.PathEscape(pw))
		}
	}
	if adminURL != "" {
		secrets = append(secrets, adminURL)
	}
	if len(secrets) == 0 {
		return err
	}
	r.Cause.Step = redact(r.Cause.Step, secrets...)
	r.Cause.Message = redact(r.Cause.Message, secrets...)
	return err
}
