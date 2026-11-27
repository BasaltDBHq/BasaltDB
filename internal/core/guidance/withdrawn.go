package guidance

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxWithdrawReasonShown is how much of the agent's withdraw reason a person
// message quotes, in characters, so the whole stays within
// MaxPersonMessageLength.
const maxWithdrawReasonShown = 400

// WithdrawnMessage is what a page and a tool result tell the person about a
// held write, revert or plugin approval the agent withdrew (CONTRACT.md,
// Approvals, Withdrawn requests): the agent's reason, quoted as the guard
// stored it, and that nothing changed. A reason that is empty or holds a
// character RefusedInText refuses is left out, never shown: the guard
// checks only its length, as for an intent.
func WithdrawnMessage(reason string) string {
	reason = strings.TrimRight(strings.TrimSpace(reason), ".")
	if reason == "" || strings.IndexFunc(reason, RefusedInText) >= 0 {
		return "The agent withdrew this request. Nothing changed."
	}
	if utf8.RuneCountInString(reason) > maxWithdrawReasonShown {
		reason = string([]rune(reason)[:maxWithdrawReasonShown]) + "..."
	}
	return fmt.Sprintf("The agent withdrew this request: %s. Nothing changed.", reason)
}

// RefusedInText reports a rune a short text that a person reads may not
// hold: a control character (C0, DEL, C1) other than a newline or a tab, or
// a bidirectional mark, embedding, override or isolate, which could make the
// text read otherwise.
func RefusedInText(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return false
	case unicode.IsControl(r):
		return true
	case r == '\u061c' || r == '\u200e' || r == '\u200f':
		return true
	case r >= '\u202a' && r <= '\u202e':
		return true
	}
	return r >= '\u2066' && r <= '\u2069'
}
