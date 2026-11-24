package links

import (
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/channel"
)

// A long headline is shortened in the line, never the id or the engine.
func TestReceiptLineFitsAndKeepsTheIDs(t *testing.T) {
	t.Parallel()
	p := channel.Receipt{ItemID: uuid.Must(uuid.NewV7()).String(), Headline: strings.Repeat("Update 3 rows in public.orders + ", 20) + "end."}
	line := receiptLine("Approved", "approval", p, "R68W FYxA cGgI jMEN")
	require.LessOrEqual(t, len([]rune(line)), maxReceiptLine)
	require.True(t, strings.HasSuffix(line, "... (approval "+p.ItemID+"), receipt from engine R68W FYxA cGgI jMEN."), line)
	short := receiptLine("Approved", "approval", channel.Receipt{ItemID: p.ItemID, Headline: "Delete 1 row in public.customers + 30 cascaded rows."}, "R68W FYxA cGgI jMEN")
	require.Equal(t, "Approved: Delete 1 row in public·customers + 30 cascaded rows (approval "+p.ItemID+"), receipt from engine R68W FYxA cGgI jMEN.", short)
}

// With no engine key a receipt is not made: the answer says so, with the line
// the person is shown.
func TestSignReceiptWithoutAKeyNamesTheMissingReceipt(t *testing.T) {
	t.Parallel()
	s := New(Core{}, &Deps{}, nil, nil)
	got, err := s.SignReceipt(channel.Receipt{}, "Approved", "approval")
	require.NoError(t, err)
	require.Equal(t, Receipt{Missing: NoReceiptKeyError, Line: noReceiptKeyErrorLine}, got)
}
