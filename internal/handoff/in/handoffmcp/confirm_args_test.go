package handoffmcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
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
			_, err := confirmDatabase(context.Background(), json.RawMessage(tc.raw))
			require.Error(t, err)
			for _, w := range tc.want {
				require.Contains(t, err.Error(), w)
			}
		})
	}
}
