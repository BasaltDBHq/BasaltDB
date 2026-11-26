// Package logredact keeps link secrets out of the engine's logs. A short
// link carries its secret in its fragment (<page>#s=<secret>, links.WithSecret),
// a hash link its request hash (<page>#h=<h>, links.HashLink), and a page
// socket's URL its Vault token (/v1/links/<token>). The types that hold a
// key or a token redact themselves (channel.LinkToken, channel.PSK and the
// link values that carry them), but a URL is a plain string, logged as is or
// inside an error's text. Every slog handler the engine builds comes from
// here (NewTextHandler), and its ReplaceAttr scrubs those
// forms from every string, error and other value before it is written.
package logredact

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
)

// Redacted replaces a scrubbed secret.
const Redacted = "[redacted]"

// secretForms are the link secrets a log line may carry inside a URL: the
// #s= and #h= fragments, also percent-encoded (a link inside another URL's
// query), and the token in a page socket's path. Each match keeps its
// prefix and loses its value, base64url text.
var secretForms = regexp.MustCompile(`(#|%23)([sh])(=|%3[dD])[A-Za-z0-9_-]*|(/v1/links/)[A-Za-z0-9_-]+`)

// Scrub is s with every link secret replaced by Redacted.
func Scrub(s string) string {
	return secretForms.ReplaceAllString(s, "$1$2$3$4"+Redacted)
}

// ReplaceAttr scrubs a's value: a string, an error's text, or any other
// value's %+v text (what the text handler prints). Another value also counts
// as carrying a secret when its JSON (what the JSON handler prints, which
// follows pointers %+v shows as addresses) does. A value that carries no
// secret is left as it was; one that does becomes its scrubbed %+v text.
func ReplaceAttr(_ []string, a slog.Attr) slog.Attr {
	var s string
	switch a.Value.Kind() {
	case slog.KindString:
		s = a.Value.String()
	case slog.KindAny:
		if err, ok := a.Value.Any().(error); ok {
			s = err.Error()
		} else {
			s = fmt.Sprintf("%+v", a.Value.Any())
			if j, err := json.Marshal(a.Value.Any()); err == nil && Scrub(string(j)) != string(j) {
				a.Value = slog.StringValue(Scrub(s))
				return a
			}
		}
	default:
		return a
	}
	if r := Scrub(s); r != s {
		a.Value = slog.StringValue(r)
	}
	return a
}

// options is o with ReplaceAttr run after o's own.
func options(o *slog.HandlerOptions) *slog.HandlerOptions {
	var out slog.HandlerOptions
	if o != nil {
		out = *o
	}
	own := out.ReplaceAttr
	out.ReplaceAttr = func(groups []string, a slog.Attr) slog.Attr {
		if own != nil {
			a = own(groups, a)
		}
		return ReplaceAttr(groups, a)
	}
	return &out
}

// NewTextHandler is slog.NewTextHandler with ReplaceAttr.
func NewTextHandler(w io.Writer, o *slog.HandlerOptions) *slog.TextHandler {
	return slog.NewTextHandler(w, options(o))
}
