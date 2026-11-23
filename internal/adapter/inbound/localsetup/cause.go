package localsetup

import (
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
)

// maxCauseMessage bounds a cause's message in the log.
const maxCauseMessage = 500

// initStep is the prefix guard.ApplyScript puts on a statement's error.
var initStep = regexp.MustCompile(`^init step (\d+): `)

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

// causeOf is err's cause at step: the Postgres SQLSTATE and the server's
// own message (never its hint or query position, and its detail only for
// the guard's own BS… codes: another detail can quote the statement) when
// the database refused it, else the error's text; the
// message redacted.
func causeOf(step string, err error) *Cause {
	c := &Cause{Step: step}
	if err == nil {
		return c
	}
	if m := initStep.FindStringSubmatch(err.Error()); m != nil {
		c.Step = step + ", statement " + m[1]
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		c.SQLState, c.Message = pg.Code, pg.Message
		if strings.HasPrefix(pg.Code, "BS") && pg.Detail != "" {
			// The guard's own refusals (BS…) put the reason in the detail,
			// written by basalt_meta's SQL, never a quoted statement.
			c.Message += ": " + pg.Detail
		}
	} else {
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
