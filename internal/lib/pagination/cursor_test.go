package pagination_test

import (
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

func rawCursor(json string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(json))
}

// Every cursor the engine cannot read is ErrStaleCursor, whatever the list.
func TestDecodeRefusesAStaleCursor(t *testing.T) {
	t.Parallel()
	bad := map[string]string{
		"not base64":  "%%%",
		"not json":    rawCursor("x"),
		"no key":      rawCursor("{}"),
		"id not uuid": rawCursor(`{"id":"x"}`),
	}
	for name, c := range bad {
		if _, err := pagination.DecodeIDCursor(c); !errors.Is(err, pagination.ErrStaleCursor) {
			t.Errorf("id cursor %s: got %v, want ErrStaleCursor", name, err)
		}
		if name == "id not uuid" {
			continue
		}
		if _, err := pagination.DecodeSeqCursor(c); !errors.Is(err, pagination.ErrStaleCursor) {
			t.Errorf("seq cursor %s: got %v, want ErrStaleCursor", name, err)
		}
		if _, err := pagination.DecodeNameCursor(c); !errors.Is(err, pagination.ErrStaleCursor) {
			t.Errorf("name cursor %s: got %v, want ErrStaleCursor", name, err)
		}
	}
	if err := pagination.StaleCursor("not one of mine"); !errors.Is(err, pagination.ErrStaleCursor) || err.Error() != "not one of mine" {
		t.Errorf("StaleCursor: got %v", err)
	}
}

func TestIDCursorRoundTrip(t *testing.T) {
	t.Parallel()
	id := uuid.Must(uuid.NewV7())
	got, err := pagination.DecodeIDCursor(pagination.EncodeIDCursor(id.String()))
	if err != nil || got != id {
		t.Fatalf("got %v, %v; want %v", got, err, id)
	}
}

func TestTimeCursorRoundTrip(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 27, 9, 30, 0, 123456000, time.UTC)
	id := uuid.Must(uuid.NewV7())
	gotAt, kind, gotID, err := pagination.DecodeTimeCursor(pagination.EncodeTimeCursor(at, "REVERT", id))
	if err != nil || !at.Equal(gotAt) || kind != "REVERT" || gotID != id {
		t.Fatalf("got %v %q %v %v", gotAt, kind, gotID, err)
	}
}

func TestDecodeTimeCursorRefusesWhatIsNotOne(t *testing.T) {
	t.Parallel()
	for _, c := range []string{
		"%%%", rawCursor(`{}`), pagination.EncodeIDCursor(uuid.Must(uuid.NewV7()).String()),
		rawCursor(`{"at":1,"kind":"RUN","id":"x"}`),
	} {
		if _, _, _, err := pagination.DecodeTimeCursor(c); !errors.Is(err, pagination.ErrStaleCursor) {
			t.Errorf("%q: got %v, want a stale cursor", c, err)
		}
	}
}
