package handoffmcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/handoff"
)

// The validator prints the args type's name in the error text that confirm_database
// returns, so the name is part of the tool's output.
func TestConfirmDatabaseArgumentErrorsNameConfirmArgs(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty", `{}`, []string{"Key: 'confirmArgs.Database' Error:Field validation for 'Database' failed on the 'required' tag"}},
		{"bad answer", `{"setupId":"x","answer":"maybe"}`, []string{
			"Key: 'confirmArgs.SetupID' Error:Field validation for 'SetupID' failed on the 'uuid' tag",
			"Key: 'confirmArgs.Database' Error:Field validation for 'Database' failed on the 'required' tag",
			"Key: 'confirmArgs.Answer' Error:Field validation for 'Answer' failed on the 'oneof' tag",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := handlers{svc: notWaiting{}}.confirmDatabase(context.Background(), json.RawMessage(tc.raw))
			require.Error(t, err)
			for _, w := range tc.want {
				require.Contains(t, err.Error(), w)
			}
		})
	}
}

// notWaiting is a served agent's confirmer: no database waits.
type notWaiting struct{}

func (notWaiting) ConfirmDatabase(context.Context, string, setupcode.Address, bool) (handoff.ConfirmResult, error) {
	return handoff.ConfirmResult{}, handoff.ErrNotWaiting
}

// A valid call on an agent where nothing waits is INVALID_ARGUMENT naming
// what to do.
func TestConfirmDatabaseWithNothingWaiting(t *testing.T) {
	raw := `{"setupId":"0190a2b3-4c5d-7e6f-8a9b-0c1d2e3f4a5b","database":{"host":"db.example.com","port":5432,"database":"postgres"},"answer":"YES"}`
	_, err := handlers{svc: notWaiting{}}.confirmDatabase(context.Background(), json.RawMessage(raw))
	var ae *guidance.ArgumentError
	require.ErrorAs(t, err, &ae)
	require.Equal(t, handoff.ErrNotWaiting.Error(), ae.Message)
}
