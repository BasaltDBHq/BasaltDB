package pagination

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrStaleCursor is a list cursor the engine cannot read: not one it
// returned, or one from another list. Every decoder here wraps it, so a
// caller tells a stale cursor apart with errors.Is, never by its text.
var ErrStaleCursor = errors.New("invalid cursor")

// StaleCursor is an ErrStaleCursor with its own message, for a list whose
// cursor has its own shape.
func StaleCursor(message string) error {
	return staleCursorError(message)
}

type staleCursorError string

func (e staleCursorError) Error() string { return string(e) }

func (staleCursorError) Unwrap() error { return ErrStaleCursor }

type cursorKey struct {
	ID   string `json:"id,omitempty"`
	Seq  int64  `json:"seq,omitempty"`
	Name string `json:"name,omitempty"`
	// At is a time as Unix microseconds, with Kind and ID the key of a list
	// ordered by time.
	At   int64  `json:"at,omitempty"`
	Kind string `json:"kind,omitempty"`
}

// EncodeIDCursor builds an opaque cursor from a row id (change, approval, run).
func EncodeIDCursor(id string) string {
	return encodeCursor(cursorKey{ID: id})
}

// DecodeIDCursor returns the id from an opaque cursor. An id that is not
// a UUID is a stale cursor, refused before it reaches a query.
func DecodeIDCursor(cursor string) (uuid.UUID, error) {
	k, err := decodeCursor(cursor)
	if err != nil {
		return uuid.Nil, err
	}
	if k.ID == "" {
		return uuid.Nil, fmt.Errorf("%w: missing id", ErrStaleCursor)
	}
	id, err := uuid.Parse(k.ID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: %w", ErrStaleCursor, err)
	}
	return id, nil
}

// EncodeNameCursor builds a cursor for name-ordered lists (revert lines, by line hash).
// EncodeTimeCursor is the cursor of a list ordered by (at, kind, id): the
// item the next page continues after.
func EncodeTimeCursor(at time.Time, kind string, id uuid.UUID) string {
	return encodeCursor(cursorKey{At: at.UnixMicro(), Kind: kind, ID: id.String()})
}

// DecodeTimeCursor is the key EncodeTimeCursor wrote.
func DecodeTimeCursor(cursor string) (at time.Time, kind string, id uuid.UUID, err error) {
	k, err := decodeCursor(cursor)
	if err != nil {
		return time.Time{}, "", uuid.Nil, err
	}
	if k.At == 0 || k.Kind == "" || k.ID == "" {
		return time.Time{}, "", uuid.Nil, fmt.Errorf("%w: missing time key", ErrStaleCursor)
	}
	id, err = uuid.Parse(k.ID)
	if err != nil {
		return time.Time{}, "", uuid.Nil, fmt.Errorf("%w: %w", ErrStaleCursor, err)
	}
	return time.UnixMicro(k.At).UTC(), k.Kind, id, nil
}

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
		return "", fmt.Errorf("%w: missing name", ErrStaleCursor)
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
		return 0, fmt.Errorf("%w: missing seq", ErrStaleCursor)
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
		return cursorKey{}, fmt.Errorf("%w encoding", ErrStaleCursor)
	}
	var k cursorKey
	if err := json.Unmarshal(raw, &k); err != nil {
		return cursorKey{}, fmt.Errorf("%w payload", ErrStaleCursor)
	}
	return k, nil
}
