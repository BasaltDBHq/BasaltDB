package pagination

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type cursorKey struct {
	ID   string `json:"id,omitempty"`
	Seq  int64  `json:"seq,omitempty"`
	Name string `json:"name,omitempty"`
}

// EncodeIDCursor builds an opaque cursor from a row id (change, approval, run).
func EncodeIDCursor(id string) string {
	return encodeCursor(cursorKey{ID: id})
}

// DecodeIDCursor returns the id from an opaque cursor.
func DecodeIDCursor(cursor string) (string, error) {
	k, err := decodeCursor(cursor)
	if err != nil {
		return "", err
	}
	if k.ID == "" {
		return "", fmt.Errorf("invalid cursor: missing id")
	}
	return k.ID, nil
}

// EncodeNameCursor builds a cursor for name-ordered lists (revert lines, by line hash).
func EncodeNameCursor(name string) string {
	return encodeCursor(cursorKey{Name: name})
}

// DecodeNameCursor returns the name from a cursor.
func DecodeNameCursor(cursor string) (string, error) {
	k, err := decodeCursor(cursor)
	if err != nil {
		return "", err
	}
	if k.Name == "" {
		return "", fmt.Errorf("invalid cursor: missing name")
	}
	return k.Name, nil
}

// EncodeSeqCursor builds a cursor for seq-ordered lists.
func EncodeSeqCursor(seq int64) string {
	return encodeCursor(cursorKey{Seq: seq})
}

// DecodeSeqCursor returns the change seq from a cursor.
func DecodeSeqCursor(cursor string) (int64, error) {
	k, err := decodeCursor(cursor)
	if err != nil {
		return 0, err
	}
	if k.Seq <= 0 {
		return 0, fmt.Errorf("invalid cursor: missing seq")
	}
	return k.Seq, nil
}

func encodeCursor(k cursorKey) string {
	b, err := json.Marshal(k)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(cursor string) (cursorKey, error) {
	if cursor == "" {
		return cursorKey{}, fmt.Errorf("empty cursor")
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return cursorKey{}, fmt.Errorf("invalid cursor encoding")
	}
	var k cursorKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return cursorKey{}, fmt.Errorf("invalid cursor payload")
	}
	return k, nil
}
