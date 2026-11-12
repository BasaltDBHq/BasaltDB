package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// callParams decodes params as the write tool does (UseNumber).
func callParams(t *testing.T, text string) []any {
	t.Helper()
	v, ok := decodeExact([]byte(text))
	require.True(t, ok)
	if v == nil {
		return nil
	}
	params, ok := v.([]any)
	require.True(t, ok)
	return params
}

func TestSameParamsComparesNumbersExactly(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, held, call string
		same             bool
	}{
		{"past 2^53", `[9007199254740993]`, `[9007199254740993]`, true},
		{"past 2^53, rounded", `[9007199254740993]`, `[9007199254740992]`, false},
		{"rounded the other way", `[9007199254740992]`, `[9007199254740993]`, false},
		{"beyond float64", `[1e400]`, `[1e400]`, true},
		{"beyond float64, a neighbor", `[1e400]`, `[1e399]`, false},
		{"jsonb respells 1e400", "[1" + strings.Repeat("0", 400) + "]", `[1e400]`, true},
		{"jsonb respells 1e2", `[100]`, `[1e2]`, true},
		{"trailing zeros", `[1.50]`, `[1.5]`, true},
		{"negative zero", `[0]`, `[-0.0]`, true},
		{"sign", `[1]`, `[-1]`, false},
		{"small", `[1e-400]`, `[0]`, false},
		{"nested", `[{"a": [12345678901234567891]}]`, `[{"a": [12345678901234567891]}]`, true},
		{"nested, rounded", `[{"a": [12345678901234567891]}]`, `[{"a": [12345678901234567890]}]`, false},
		{"number is not a string", `["1"]`, `[1]`, false},
		{"strings", `["a", true, null]`, `["a", true, null]`, true},
		{"huge exponents compare by text", `[1e99999999999999999999]`, `[1e99999999999999999999]`, true},
		{"huge exponents differ", `[1e99999999999999999999]`, `[1e99999999999999999998]`, false},
	} {
		require.Equal(t, tc.same, sameParams(json.RawMessage(tc.held), callParams(t, tc.call)), tc.name)
	}
	require.True(t, sameParams(nil, nil), "no params held, none given")
	require.False(t, sameParams(nil, callParams(t, `[1]`)))
	require.False(t, sameParams(json.RawMessage(`[1]`), nil))
}
