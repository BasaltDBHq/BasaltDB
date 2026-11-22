package pii_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/pii"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name   string
		typ    pii.EntityType
		value  string
		region string
		want   string
	}{
		{"email lower case and trimmed", pii.EntityEmail, "  Alice.Tamm@Gmail.COM\n", "", "alice.tamm@gmail.com"},
		{"email NFD becomes NFC", pii.EntityEmail, "jose\u0301@example.com", "", "josé@example.com"},
		{"email non-ASCII lower case", pii.EntityEmail, "ÄNNE@example.com", "", "änne@example.com"},
		{"phone with +cc", pii.EntityPhone, "+44 7700 900123", "", "+447700900123"},
		{"phone with +cc ignores the region", pii.EntityPhone, "+44 (0)7700-900123", "ID", "+447700900123"},
		{"phone local format with a region", pii.EntityPhone, "0812-3456-7890", "ID", "+6281234567890"},
		{"phone region is case-insensitive", pii.EntityPhone, "0812 3456 7890", "id", "+6281234567890"},
		{"phone local without a region keeps the digits", pii.EntityPhone, "0812-3456-7890", "", "081234567890"},
		{"phone unparseable keeps + and digits", pii.EntityPhone, "+1", "", "+1"},
		{"phone with an unknown region keeps the digits", pii.EntityPhone, "0812 3456 7890", "ZZ", "081234567890"},
		{"phone full-width digits", pii.EntityPhone, "+４４ ７７００ ９００１２３", "", "+447700900123"},
		{"name case folding and whitespace", pii.EntityPersonName, "  Alice\t\tTAMM\n", "", "alice tamm"},
		{"name punctuation is a separator", pii.EntityPersonName, "Mari-Liis   Kask", "", "mari liis kask"},
		{"name NFD equals NFC", pii.EntityPersonName, "Jose\u0301 Pe\u0301rez", "", "josé pérez"},
		{"name sharp s folds", pii.EntityPersonName, "Straße", "", "strasse"},
		{"name Greek final sigma folds", pii.EntityPersonName, "ΟΔΥΣΣΕΥΣ", "", "οδυσσευσ"},
		{"name dotted capital I keeps its mark", pii.EntityPersonName, "İstanbul", "", "i\u0307stanbul"},
		{"name full-width is plain", pii.EntityPersonName, "\uff21\uff4c\uff45\uff58 \uff2a\uff4f\uff4e\uff45\uff53", "", "alex jones"},
		{"name ligature is decomposed", pii.EntityPersonName, "\ufb01ona", "", "fiona"},
		{"email full-width is plain", pii.EntityEmail, "\uff41\uff4c\uff49\uff43\uff45@example.com", "", "alice@example.com"},
		{"email IDN domain", pii.EntityEmail, "Alice@Ex\u00c4mple.ee", "", "alice@ex\u00e4mple.ee"},
		{"name Cherokee folds to upper case", pii.EntityPersonName, "\uabb9 \u13e9", "", "\u13e9 \u13e9"},
		{"name format char between marks keeps canonical order", pii.EntityPersonName, "\u07e4\u0740\u0600\u05a4", "", "\u07e4\u05a4\u0740"},
		{"name zero-width chars are ignored", pii.EntityPersonName, "Ali\u200bce Ta\u200dmm", "", "alice tamm"},
		{"address", pii.EntityAddress, "Pärnu mnt 99,\nTallinn", "", "pärnu mnt 99 tallinn"},
		{"other", pii.EntityOther, "DE89 3704-0044", "", "de89 3704 0044"},
		{"empty", pii.EntityPersonName, "", "", ""},
		{"only separators", pii.EntityAddress, " ,.- ", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, pii.Normalize(c.typ, c.value, c.region))
		})
	}
}

func TestNormalizeIsIdempotent(t *testing.T) {
	inputs := []string{"Jose\u0301 Pe\u0301rez", "İstanbul", "Straße", "+44 7700 900123", "A@B.example", "ΟΔΥΣΣΕΥΣ"}
	for _, typ := range pii.TokenTypes() {
		for _, in := range inputs {
			once := pii.Normalize(typ, in, "GB")
			require.Equal(t, once, pii.Normalize(typ, once, "GB"), "%s %q", typ, in)
		}
	}
}

func TestGenericFormMatchesNameNormalization(t *testing.T) {
	require.Equal(t, pii.Normalize(pii.EntityPersonName, "Jose\u0301  PÉREZ", ""), pii.GenericForm("José Pérez"))
}
