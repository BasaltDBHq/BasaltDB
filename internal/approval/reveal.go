package approval

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/google/uuid"
)

// The reveal of rows hidden from the agent (CONTRACT.md, Approvals, Rows
// hidden from the agent; owner decision HR-1).
const (
	revealPrefix  = "basalt-reveal.1"
	revealKeyInfo = "basalt-reveal-key.1"
	// KindRevert is the kind a revert's reveal proof names; the revert
	// binding's kind is the same word.
	KindRevert = "REVERT"
	// RevealSecretLen is the length of the page's reveal secret.
	RevealSecretLen = 16
	// RevealKeyLen is the length of the key derived from it; Postgres
	// refuses any other.
	RevealKeyLen = 32
	// RevealNonceLen is the length of an item's reveal nonce.
	RevealNonceLen = 16
	// revealRowValues is how many values a revealed row holds: key, then
	// old or now, then set.
	revealRowValues = 3
)

// RevealKey derives the key the engine passes Postgres for a reveal from the
// page's reveal secret: HKDF-SHA-256 with an empty salt and info
// "basalt-reveal-key.1". The secret itself never reaches Postgres.
func RevealKey(secret []byte) ([]byte, error) {
	if len(secret) != RevealSecretLen {
		return nil, invalid("reveal secret is %d bytes, want %d", len(secret), RevealSecretLen)
	}
	return hkdf.Key(sha256.New, secret, nil, revealKeyInfo, RevealKeyLen)
}

// RevealChallenge is the WebAuthn challenge of a reveal proof:
// sha256(utf8("basalt-reveal.1\n" + kind + "\n" + id + "\n" +
// base64url(nonce) + "\n" + hex(sha256(revealKey)) + "\n" + rowsHash)), with
// rowsHash the binding's (a large plan's too, never its sampleHash).
func RevealChallenge(kind string, id uuid.UUID, nonce, revealKey []byte, rowsHash string) ([]byte, error) {
	if kind != KindApprove && kind != KindRevert {
		return nil, invalid("reveal kind %q", kind)
	}
	if len(nonce) != RevealNonceLen {
		return nil, invalid("reveal nonce is %d bytes, want %d", len(nonce), RevealNonceLen)
	}
	if len(revealKey) != RevealKeyLen {
		return nil, invalid("reveal key is %d bytes, want %d", len(revealKey), RevealKeyLen)
	}
	if !isHashHex(rowsHash) {
		return nil, invalid("rowsHash is not a lowercase sha256 hex digest")
	}
	keyHash := sha256.Sum256(revealKey)
	msg := strings.Join([]string{
		revealPrefix, kind, id.String(), base64.RawURLEncoding.EncodeToString(nonce),
		hex.EncodeToString(keyHash[:]), rowsHash,
	}, "\n")
	sum := sha256.Sum256([]byte(msg))
	return sum[:], nil
}

func isHashHex(s string) bool {
	if len(s) != sha256.Size*2 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// RevealAnswer is the answer of POST …/reveal (reveal-response.schema.json).
type RevealAnswer struct {
	Rows []RevealedRow `json:"rows"`
}

// RevealedRow is the values of one redacted line. Row is the exact text of
// jsonb_build_array(key, old|now, set) that the line's rowHash hashes,
// with every SECRET column null and named in SecretColumns.
type RevealedRow struct {
	Line          int      `json:"line"`
	Row           string   `json:"row"`
	SecretColumns []string `json:"secretColumns,omitempty"`
}

// redactedLine is what a reveal reads of a redacted approval or revert line.
type redactedLine struct {
	Redacted bool   `json:"redacted"`
	RowHash  string `json:"rowHash"`
}

// CheckRevealAnswer checks an answer against the request's lines: each row
// answers a redacted line, in line order, at most once, and passes
// CheckRevealedRow. It returns, per row, whether its values were checked
// against the line's rowHash (false for a row with SECRET columns).
func CheckRevealAnswer(lines []string, a RevealAnswer) ([]bool, error) {
	checked := make([]bool, 0, len(a.Rows))
	last := -1
	for _, r := range a.Rows {
		if r.Line <= last || r.Line >= len(lines) {
			return nil, invalid("revealed line %d is out of order or out of range", r.Line)
		}
		last = r.Line
		ok, err := CheckRevealedRow(lines[r.Line], r)
		if err != nil {
			return nil, err
		}
		checked = append(checked, ok)
	}
	return checked, nil
}

// CheckRevealedRow checks a revealed row against the redacted line it
// answers. A row without SECRET columns must hash to the line's rowHash:
// then it is checked (true), and its values are the ones bound into what
// the person signs. A row with SECRET columns cannot be: every named column
// must appear in the row and be null wherever it does, and the row is
// unverified (false), never shown as checked.
func CheckRevealedRow(line string, r RevealedRow) (bool, error) {
	var l redactedLine
	if err := json.Unmarshal([]byte(line), &l); err != nil {
		return false, invalid("revealed line: %v", err)
	}
	if !l.Redacted || !isHashHex(l.RowHash) {
		return false, invalid("revealed line is not a redacted line")
	}
	values, err := revealedValues(r.Row)
	if err != nil {
		return false, err
	}
	if len(r.SecretColumns) == 0 {
		sum := sha256.Sum256([]byte(r.Row))
		if hex.EncodeToString(sum[:]) != l.RowHash {
			return false, invalid("revealed row does not hash to its line's rowHash")
		}
		return true, nil
	}
	return false, checkSecretColumns(values, r.SecretColumns)
}

// revealedValues parses a row: three values, each an object or null.
func revealedValues(row string) ([]map[string]json.RawMessage, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(row), &raw); err != nil {
		return nil, invalid("revealed row: %v", err)
	}
	if len(raw) != revealRowValues {
		return nil, invalid("revealed row has %d values, want %d", len(raw), revealRowValues)
	}
	values := make([]map[string]json.RawMessage, 0, revealRowValues)
	for _, v := range raw {
		if bytes.Equal(v, []byte("null")) {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(v, &obj); err != nil {
			return nil, invalid("revealed row value is not an object or null")
		}
		values = append(values, obj)
	}
	return values, nil
}

// checkSecretColumns: each named column is named once, appears in the row,
// and is null wherever it appears.
func checkSecretColumns(values []map[string]json.RawMessage, cols []string) error {
	seen := make(map[string]bool, len(cols))
	for _, col := range cols {
		if col == "" || seen[col] {
			return invalid("secret column %q is empty or named twice", col)
		}
		seen[col] = true
		found := false
		for _, obj := range values {
			v, ok := obj[col]
			if !ok {
				continue
			}
			if !bytes.Equal(v, []byte("null")) {
				return invalid("secret column %q has a value", col)
			}
			found = true
		}
		if !found {
			return invalid("secret column %q is not in the row", col)
		}
	}
	return nil
}
