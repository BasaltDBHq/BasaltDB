package textrule_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/textrule"
)

func TestCheckAcceptsTheRulesLayout(t *testing.T) {
	t.Parallel()
	for _, text := range []string{
		`{}`,
		`{"op": "UPDATE", "key": {"id": 7}, "old": {"id": 7, "status": "open"}, "set": {"status": "merged"}, "shape": "RECORD", "store": {"kind": "POSTGRES", "verb": "UPDATE"}, "cascaded": false, "resource": "public.leads"}`,
		`{"\n": 2, "A": 1}`,
		`{"a": [], "b": [1, -2, 1.50, 0, 1e5, 2.5E-3, true, false, null], "c": "tab\there \"q\" back\\slash \u0001 \b\f\r é 日本 🚀 /"}`,
		`{"x": {}}`,
		`{"deep": ` + strings.Repeat("[", 200) + strings.Repeat("]", 200) + `}`,
	} {
		require.NoError(t, textrule.Check(text), text)
	}
}

func TestCheckRefusesAnyOtherLayout(t *testing.T) {
	t.Parallel()
	for name, text := range map[string]string{
		"not an object":            `[1]`,
		"keys out of order":        `{"set": 1, "op": 2}`,
		"same length out of order": `{"b": 1, "a": 2}`,
		"a repeated key":           `{"a": 1, "a": 2}`,
		"nested keys out of order": `{"a": {"bb": 1, "c": 2}}`,
		"no space after a colon":   `{"a":1}`,
		"no space after a comma":   `{"a": 1,"b": 2}`,
		"a space inside braces":    `{ "a": 1}`,
		"a space inside brackets":  `{"a": [ 1]}`,
		"an uppercase literal":     `{"a": TRUE}`,
		"an escaped slash":         `{"a": "\/"}`,
		"a unicode escape":         `{"a": "\u00e9"}`,
		"uppercase hex":            `{"a": "\u001F"}`,
		"a long escape for tab":    `{"a": "\u0009"}`,
		"a raw control character":  "{\"a\": \"\x01\"}",
		"a leading zero":           `{"a": 01}`,
		"a bare point":             `{"a": 1.}`,
		"a plus sign":              `{"a": +1}`,
		"data after the end":       `{"a": 1} `,
		"not UTF-8":                "{\"a\": \"\xff\"}",
		"an unterminated string":   `{"a": "x}`,
	} {
		require.ErrorIs(t, textrule.Check(text), textrule.ErrBroken, name)
	}
}

func TestPlainInteger(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]bool{"0": true, "27": true, "-0": false, "-1": false, "01": false, "1.0": false, "1e2": false, "": false} {
		require.Equal(t, want, textrule.PlainInteger([]byte(raw)), raw)
	}
}
