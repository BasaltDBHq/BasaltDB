package mcpcontract_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/contractdoc"
)

// Close-code range of the Vault channel (CONTRACT.md, Vault channel, Close
// codes): WebSocket's application-private range starts at 4000, and the
// channel keeps to its first hundred.
const (
	vaultCloseCodeMin = 4000
	vaultCloseCodeMax = 4099
)

// vaultCloseCode is one entry of api/mcp/vault/close-codes.json.
type vaultCloseCode struct {
	Code      int      `json:"code"`
	Name      string   `json:"name"`
	SentBy    []string `json:"sentBy"`
	When      string   `json:"when"`
	PageShows string   `json:"pageShows"`
}

// vaultCloseRow matches a row of the close-code table in CONTRACT.md:
// | 4000 | `PROTOCOL` | ...
var vaultCloseRow = regexp.MustCompile("(?m)^\\| (40[0-9]{2}) \\| `([A-Z_]+)` \\|")

// TestVaultSchemas checks the Vault channel schemas (CONTRACT.md, Vault
// channel) follow the wire rules.
func TestVaultSchemas(t *testing.T) {
	t.Parallel()
	checkPayloadSchemas(t, "vault", []string{
		"channel-key-file.schema.json",
		"close-codes.schema.json",
		"control-message.schema.json",
		"frame-message.schema.json",
		"handshake-payload.schema.json",
		"receipt.schema.json",
		"vectors.schema.json",
	})
}

// TestVaultCloseCodes checks the close-code registry is well formed, matches
// the table in CONTRACT.md row for row, and holds every close code a vector
// may expect.
func TestVaultCloseCodes(t *testing.T) {
	t.Parallel()
	codes := loadVaultCloseCodes(t)

	byName := make(map[string]int, len(codes))
	seen := make(map[int]bool, len(codes))
	for _, c := range codes {
		require.Regexp(t, screamingCase, c.Name)
		require.GreaterOrEqual(t, c.Code, vaultCloseCodeMin, c.Name)
		require.LessOrEqual(t, c.Code, vaultCloseCodeMax, c.Name)
		require.False(t, seen[c.Code], "close code %d listed twice", c.Code)
		_, dup := byName[c.Name]
		require.False(t, dup, "close code name %s listed twice", c.Name)
		require.NotEmpty(t, c.SentBy, c.Name)
		require.NotEmpty(t, c.When, c.Name)
		require.Contains(t, []string{"LINK_GONE", "ENGINE_OFFLINE", "BROKEN", "TRY_LATER"}, c.PageShows, c.Name)
		seen[c.Code] = true
		byName[c.Name] = c.Code
	}

	contract, err := contractdoc.Read()
	require.NoError(t, err)
	rows := vaultCloseRow.FindAllStringSubmatch(string(contract), -1)
	inContract := make(map[string]int, len(rows))
	for _, r := range rows {
		n, err := strconv.Atoi(r[1])
		require.NoError(t, err)
		inContract[r[2]] = n
	}
	require.Equal(t, byName, inContract, "CONTRACT.md's close-code table and close-codes.json differ")

	for _, name := range vaultVectorExpectations(t) {
		if name == "ACCEPT" || name == "REFUSE" {
			continue
		}
		_, ok := byName[name]
		require.True(t, ok, "vectors.schema.json expects %s, which is not a close code", name)
	}
}

// TestVaultControlErrorsInContract checks every control ERROR code is named
// in CONTRACT.md.
func TestVaultControlErrorsInContract(t *testing.T) {
	t.Parallel()
	contract, err := contractdoc.Read()
	require.NoError(t, err)
	raw, err := os.ReadFile(filepath.Join("vault", "control-message.schema.json"))
	require.NoError(t, err)
	var schema struct {
		Defs struct {
			Error struct {
				Properties struct {
					Code struct {
						Enum []string `json:"enum"`
					} `json:"code"`
				} `json:"properties"`
			} `json:"error"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema))
	codes := schema.Defs.Error.Properties.Code.Enum
	require.NotEmpty(t, codes)
	for _, c := range codes {
		require.True(t, strings.Contains(string(contract), "`"+c+"`"), "control error %s is not in CONTRACT.md", c)
	}
}

func loadVaultCloseCodes(t *testing.T) []vaultCloseCode {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("vault", "close-codes.json"))
	require.NoError(t, err)
	var reg struct {
		Codes []vaultCloseCode `json:"codes"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	require.NoError(t, dec.Decode(&reg))
	require.NotEmpty(t, reg.Codes)
	return reg.Codes
}

func vaultVectorExpectations(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("vault", "vectors.schema.json"))
	require.NoError(t, err)
	var schema struct {
		Defs struct {
			Expect struct {
				Enum []string `json:"enum"`
			} `json:"expect"`
		} `json:"$defs"`
	}
	require.NoError(t, json.Unmarshal(raw, &schema))
	require.NotEmpty(t, schema.Defs.Expect.Enum)
	return schema.Defs.Expect.Enum
}
