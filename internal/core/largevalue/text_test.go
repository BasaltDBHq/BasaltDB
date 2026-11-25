package largevalue_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
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

func TestSummaryNamesOnlyValuesOverTheCap(t *testing.T) {
	// The most plain bytes in a string of column v at the cap: the two quotes
	// cost 1+6 each, then 128 and the column's 1.
	const atCap = largevalue.ValueCap - 128 - 1 - 2*7
	small := []byte(`"` + strings.Repeat("a", 100) + `"`)
	require.Empty(t, largevalue.Summary(small, "v"))
	// Cost 1 MiB exactly is kept.
	edge := []byte(`"` + strings.Repeat("a", atCap) + `"`)
	require.EqualValues(t, largevalue.ValueCap, largevalue.Cost(edge, "v"))
	require.Empty(t, largevalue.Summary(edge, "v"))
	over := []byte(`"` + strings.Repeat("a", atCap+1) + `"`)
	text := strings.Repeat("a", atCap+1)
	sum := sha256.Sum256([]byte(text))
	require.Equal(t, "(1023.9 KiB, sha256 "+hex.EncodeToString(sum[:])+")", largevalue.Summary(over, "v"))
}

func TestMarksOfAnImage(t *testing.T) {
	big := strings.Repeat("<", largevalue.ValueCap/7+1)
	image := []byte(`{"id": 1, "body": "` + big + `"}`)
	marks, err := largevalue.ImageMarks(image)
	require.NoError(t, err)
	require.Len(t, marks, 1)
	require.Contains(t, marks["body"], "sha256 ")
	none, err := largevalue.ImageMarks([]byte(`null`))
	require.NoError(t, err)
	require.Empty(t, none)
}
