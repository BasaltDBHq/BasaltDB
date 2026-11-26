// Package sqlident quotes SQL identifiers. It is the one function that
// always quotes a name for the SQL the engine builds; a test in the
// architecture kit refuses any other quote-doubling helper.
package sqlident

import "strings"

// Quote returns parts as one quoted, dot-joined identifier: each part in
// double quotes with a double quote doubled and a NUL dropped, so
// Quote("a", `b"c`) is "a"."b""c". The output is the same, byte for byte,
// as pgx.Identifier(parts).Sanitize().
func Quote(parts ...string) string {
	quoted := make([]string, len(parts))
	for i, p := range parts {
		p = strings.ReplaceAll(p, "\x00", "")
		quoted[i] = `"` + strings.ReplaceAll(p, `"`, `""`) + `"`
	}
	return strings.Join(quoted, ".")
}
