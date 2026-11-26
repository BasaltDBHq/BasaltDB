package passkey

import "unicode/utf8"

// labelEllipsis ends a label FitLabel cut.
const labelEllipsis = "…"

// FitLabel returns s when it is at most MaxLabelLen bytes, and otherwise
// cuts it on a rune boundary and ends it with "…" so the result is at most
// MaxLabelLen bytes. The names are only what the person reads in their
// password manager; the passkey's identity is its user id. s is UTF-8.
func FitLabel(s string) string {
	if len(s) <= MaxLabelLen {
		return s
	}
	cut := MaxLabelLen - len(labelEllipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + labelEllipsis
}
