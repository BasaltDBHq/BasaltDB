package approval

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// The reveal of rows hidden from the agent (CONTRACT.md, Approvals, Rows
// hidden from the agent; owner decision HR-1).
const (
	revealKeyInfo = "basalt-reveal-key.1"
	// KindRevert is the kind a revert's reveal proof names; the revert
	// binding's kind is the same word.
	KindRevert = "REVERT"
	// RevealSecretLen is the length of the page's reveal secret.
	RevealSecretLen = 16
	// RevealKeyLen is the length of the key derived from it; Postgres
	// refuses any other.
	RevealKeyLen = 32
	// revealRowValues is how many values a revealed row holds: key, then
	// old or now, then set.
	revealRowValues = 3
)

// RevealKey derives the key the engine passes Postgres for a reveal from the
// page's reveal secret: HKDF-SHA-256 with an empty salt and info
// "basalt-reveal-key.1". The secret itself never reaches Postgres.
func RevealKey(secret []byte) ([]byte, error) {
	if len(secret) != RevealSecretLen {
		return nil, Invalid("reveal secret is %d bytes, want %d", len(secret), RevealSecretLen)
	}
	return hkdf.Key(sha256.New, secret, nil, revealKeyInfo, RevealKeyLen)
}

func IsHashHex(s string) bool {
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

// redactedRowHash is the rowHash of a redacted approval or revert line, its
// keys read exactly as written (encoding/json would also match "RowHash" or
// "REDACTED"), as the pages read them.
func redactedRowHash(line string) (string, error) {
	var keys map[string]json.RawMessage
	if err := json.Unmarshal([]byte(line), &keys); err != nil {
		return "", Invalid("revealed line: %v", err)
	}
	var hash string
	if !bytes.Equal(keys["redacted"], []byte("true")) || json.Unmarshal(keys["rowHash"], &hash) != nil || !IsHashHex(hash) {
		return "", Invalid("revealed line is not a redacted line")
	}
	return hash, nil
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
			return nil, Invalid("revealed line %d is out of order or out of range", r.Line)
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
	rowHash, err := redactedRowHash(line)
	if err != nil {
		return false, err
	}
	values, err := revealedValues(r.Row)
	if err != nil {
		return false, err
	}
	if r.SecretColumns != nil && len(r.SecretColumns) == 0 {
		return false, Invalid("secretColumns is empty: name the SECRET columns, or leave it out")
	}
	if r.SecretColumns == nil {
		sum := sha256.Sum256([]byte(r.Row))
		if hex.EncodeToString(sum[:]) != rowHash {
			return false, Invalid("revealed row does not hash to its line's rowHash")
		}
		return true, nil
	}
	return false, checkSecretColumns(values, r.SecretColumns)
}

// revealedValues parses a row: three values, each an object or null.
func revealedValues(row string) ([]map[string]json.RawMessage, error) {
	var raw []json.RawMessage
	if err := json.Unmarshal([]byte(row), &raw); err != nil {
		return nil, Invalid("revealed row: %v", err)
	}
	if len(raw) != revealRowValues {
		return nil, Invalid("revealed row has %d values, want %d", len(raw), revealRowValues)
	}
	values := make([]map[string]json.RawMessage, 0, revealRowValues)
	for _, v := range raw {
		if bytes.Equal(v, []byte("null")) {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(v, &obj); err != nil {
			return nil, Invalid("revealed row value is not an object or null")
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
			return Invalid("secret column %q is empty or named twice", col)
		}
		seen[col] = true
		found := false
		for _, obj := range values {
			v, ok := obj[col]
			if !ok {
				continue
			}
			if !bytes.Equal(v, []byte("null")) {
				return Invalid("secret column %q has a value", col)
			}
			found = true
		}
		if !found {
			return Invalid("secret column %q is not in the row", col)
		}
	}
	return nil
}
