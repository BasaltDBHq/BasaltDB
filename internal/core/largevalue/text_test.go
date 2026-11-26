package largevalue_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/largevalue"
)

type sharedVector struct {
	Name   string          `json:"name"`
	Value  json.RawMessage `json:"value"`
	Text   string          `json:"text"`
	Bytes  int64           `json:"bytes"`
	SHA256 string          `json:"sha256"`
	Field  string          `json:"field"`
	Cost   int64           `json:"cost"`
}

// jsonbText is the value as Postgres prints it: a string quoted with the
// escapes it writes, an object as the vector's text.
func (v sharedVector) jsonbText(t *testing.T) []byte {
	var s string
	if json.Unmarshal(v.Value, &s) != nil {
		return []byte(v.Text)
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	require.NoError(t, enc.Encode(s))
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func loadSharedVectors(t *testing.T) []sharedVector {
	t.Helper()
	raw, err := os.ReadFile("../../../api/mcp/values/large-value.json")
	require.NoError(t, err)
	var f struct {
		Vectors []sharedVector `json:"vectors"`
	}
	require.NoError(t, json.Unmarshal(raw, &f))
	require.NotEmpty(t, f.Vectors)
	return f.Vectors
}

func TestCostAndTextMatchSharedVectors(t *testing.T) {
	for _, v := range loadSharedVectors(t) {
		t.Run(v.Name, func(t *testing.T) {
			jt := v.jsonbText(t)
			require.Equal(t, v.Cost, largevalue.Cost(jt, v.Field))
			text, err := largevalue.Text(jt)
			require.NoError(t, err)
			require.Equal(t, v.Text, text)
			require.EqualValues(t, v.Bytes, len(text))
			sum := sha256.Sum256([]byte(text))
			require.Equal(t, v.SHA256, hex.EncodeToString(sum[:]))
		})
	}
}

func TestSizeText(t *testing.T) {
	require.Equal(t, "1.5 KiB", largevalue.SizeText(1536))
	require.Equal(t, "1.0 MiB", largevalue.SizeText(1<<20))
	require.Equal(t, "2.0 MiB", largevalue.SizeText(2<<20))
	// Halves round up, as the pages' toFixed does.
	require.Equal(t, "1.3 MiB", largevalue.SizeText(1<<20+1<<18))
	require.Equal(t, "15.5 MiB", largevalue.SizeText(15<<20+1<<19))
}
