package pgpii_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/piistore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgpii"
)

func TestKindOf(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]piistore.Kind{
		"text": piistore.KindText, "character varying": piistore.KindText, "extensions.citext": piistore.KindText, "jsonb": piistore.KindText,
		"text[]": piistore.KindText, "integer[]": piistore.KindOther, "bigint": piistore.KindInt, "numeric": piistore.KindNumeric,
		"timestamp with time zone": piistore.KindDate, "boolean": piistore.KindBool, "uuid": piistore.KindOther, "bytea": piistore.KindOther,
	} {
		require.Equal(t, want, pgpii.KindOf(in), in)
	}
}
