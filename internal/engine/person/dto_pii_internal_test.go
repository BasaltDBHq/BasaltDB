package person

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
)

func TestHealthCarriesThePIISummary(t *testing.T) {
	t.Parallel()
	at := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	h := ledger.Health{PII: &ledger.PIIHealth{
		Classified: 3, Unclassified: 1, UnclassifiedNames: []string{"public.t.c"},
		Review: 0, Dictionary: &ledger.DictionaryHealth{Values: 9, LastScanAt: &at},
	}}
	raw, err := json.Marshal(healthFromDomain(h))
	require.NoError(t, err)
	require.Contains(t, string(raw), `"pii":{"classified":3,"unclassified":1,"unclassifiedNames":["public.t.c"],"review":0,"reviewNames":[],"dictionary":{"values":9,"lastScanAt":"2026-11-12T08:00:00Z"}}`)
	var back healthDTO
	require.NoError(t, json.Unmarshal(raw, &back))
	got := back.toDomain()
	require.Equal(t, 3, got.PII.Classified)
	require.Equal(t, []string{"public.t.c"}, got.PII.UnclassifiedNames)
	require.Equal(t, uint64(9), got.PII.Dictionary.Values)

	raw, err = json.Marshal(healthFromDomain(ledger.Health{}))
	require.NoError(t, err)
	require.NotContains(t, string(raw), `"pii"`, "absent before guard version 15")
	var none healthDTO
	require.NoError(t, json.Unmarshal(raw, &none))
	require.Nil(t, none.toDomain().PII)
}
