package plugincontract_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/contractdoc"
)

// The person socket's limits the plugin methods live within.
const (
	personRequestBytes = 256 << 10
	maxPartBytes       = 64 << 10
	maxUploadBytes     = 256 << 20
)

// personSchema is approval/person.schema.json, read as data for the values
// the test ties to the contract.
type personSchema struct {
	Defs struct {
		Request struct {
			Properties struct {
				Method struct {
					Enum []string `json:"enum"`
				} `json:"method"`
			} `json:"properties"`
		} `json:"request"`
		PartParams struct {
			Properties struct {
				Offset struct {
					Maximum int `json:"maximum"`
				} `json:"offset"`
				Data struct {
					MaxLength int `json:"maxLength"`
				} `json:"data"`
			} `json:"properties"`
		} `json:"partParams"`
		UploadBeginResult struct {
			Properties struct {
				MaxPartBytes struct {
					Const int `json:"const"`
				} `json:"maxPartBytes"`
				MaxUploadBytes struct {
					Const int `json:"const"`
				} `json:"maxUploadBytes"`
			} `json:"properties"`
		} `json:"uploadBeginResult"`
		Error struct {
			Properties struct {
				Error struct {
					Properties struct {
						Reason struct {
							Enum []string `json:"enum"`
						} `json:"reason"`
					} `json:"properties"`
				} `json:"error"`
			} `json:"properties"`
		} `json:"error"`
	} `json:"$defs"`
}

// personTableRow is a row of the person socket's method table.
var personTableRow = regexp.MustCompile("(?m)^\\| `(PLUGIN_[A-Z_]+)` \\| `\\{[^|]*\\(no `agent`\\) \\|")

// TestPluginServiceMethods checks the person socket's plugin methods
// (CONTRACT.md, Plugin approval in service mode) against their schema: every
// method has its row in the person socket's table and a valid request
// example; the part and upload limits in the schema are the contract's and a
// largest part fits one request line; every refusal reason is in the
// contract; and a binding an engine-kept local entry opens is a level 3 page.
func TestPluginServiceMethods(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("approval", "person.schema.json"))
	require.NoError(t, err)
	var ps personSchema
	require.NoError(t, json.Unmarshal(raw, &ps))
	contractRaw, err := contractdoc.Read()
	require.NoError(t, err)
	contract := string(contractRaw)
	start := strings.Index(contract, "### Plugin approval in service mode")
	require.Positive(t, start, "CONTRACT.md has no Plugin approval in service mode section")
	end := strings.Index(contract[start:], "\n### Transports")
	require.Positive(t, end)
	section := contract[start : start+end]

	methods := ps.Defs.Request.Properties.Method.Enum
	found := personTableRow.FindAllStringSubmatch(contract, -1)
	rows := make([]string, 0, len(found))
	for _, m := range found {
		rows = append(rows, m[1])
	}
	require.ElementsMatch(t, methods, rows, "the person socket's table lists exactly the schema's plugin methods")
	for _, m := range methods {
		require.Contains(t, section, "`"+m+"`", "the section names %s", m)
	}

	examples, err := filepath.Glob(filepath.Join("testdata", "valid-person-request-*.json"))
	require.NoError(t, err)
	covered := map[string]bool{}
	for _, f := range examples {
		b, err := os.ReadFile(f)
		require.NoError(t, err)
		var req struct {
			Method string `json:"method"`
		}
		require.NoError(t, json.Unmarshal(b, &req))
		covered[req.Method] = true
	}
	for _, m := range methods {
		require.True(t, covered[m], "no valid-person-request example for %s", m)
	}

	require.Equal(t, maxPartBytes, ps.Defs.UploadBeginResult.Properties.MaxPartBytes.Const)
	require.Equal(t, maxUploadBytes, ps.Defs.UploadBeginResult.Properties.MaxUploadBytes.Const)
	require.Equal(t, maxUploadBytes-1, ps.Defs.PartParams.Properties.Offset.Maximum)
	require.Equal(t, base64.RawURLEncoding.EncodedLen(maxPartBytes), ps.Defs.PartParams.Properties.Data.MaxLength)
	for _, n := range []string{"65,536", "268,435,456", "1,073,741,824", "At most 16 entries", "1 MiB", "4 KiB", "1,024", "15 minutes"} {
		require.Contains(t, section, n)
	}

	compiler := newCompiler(t)
	request, err := compiler.Compile(schemaBase + "approval/person.schema.json#/$defs/request")
	require.NoError(t, err)
	part := func(n int) []byte {
		b, err := json.Marshal(map[string]any{"method": "PLUGIN_UPLOAD_PART", "params": map[string]any{
			"uploadId": "0193b2c4-5d6e-7f80-9a1b-2c3d4e5f6a70", "path": "bin/local-ner",
			"offset": maxUploadBytes - 1, "data": base64.RawURLEncoding.EncodeToString(make([]byte, n)),
		}})
		require.NoError(t, err)
		return b
	}
	validate := func(b []byte) error {
		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(b))
		require.NoError(t, err)
		return request.Validate(inst)
	}
	largest := part(maxPartBytes)
	require.NoError(t, validate(largest))
	require.Less(t, len(largest)+1, personRequestBytes, "a largest part and its newline fit one request line")
	require.Error(t, validate(part(maxPartBytes+1)))

	for _, r := range ps.Defs.Error.Properties.Error.Properties.Reason.Enum {
		require.Contains(t, section, "`"+r+"`", "the section names the refusal reason %s", r)
	}

	// The engine opens an engine-kept local entry's approval with files NONE
	// and network NOT_ENFORCED, so an unknown publisher is the level 3 page.
	b, err := os.ReadFile(filepath.Join("testdata", "valid-person-result-open.json"))
	require.NoError(t, err)
	type openedApproval struct {
		BindingText  string `json:"bindingText"`
		SettingsText string `json:"settingsText"`
	}
	var opened struct {
		Approvals []openedApproval `json:"approvals"`
	}
	require.NoError(t, json.Unmarshal(b, &opened))
	binding, err := compiler.Compile(schemaBase + "approval/binding.schema.json")
	require.NoError(t, err)
	texts := slices.DeleteFunc(opened.Approvals, func(a openedApproval) bool { return a.BindingText == "" })
	require.NotEmpty(t, texts)
	for _, a := range texts {
		requireJSONBText(t, a.BindingText, "the open result's binding")
		inst, err := jsonschema.UnmarshalJSON(strings.NewReader(a.BindingText))
		require.NoError(t, err)
		require.NoError(t, binding.Validate(inst))
		var ab approvalBinding
		require.NoError(t, json.Unmarshal([]byte(a.BindingText), &ab))
		require.Equal(t, &approvalIsolation{Files: "NONE", Network: "NOT_ENFORCED"}, ab.Isolation)
		require.Equal(t, 3, pageLevel(ab))
		require.Equal(t, fmt.Sprintf("%x", sha256.Sum256([]byte(a.SettingsText))), ab.SettingsSHA256)
	}
	require.Contains(t, section, `{"files": "NONE", "network": "NOT_ENFORCED"}`)
	require.Contains(t, section, sentSameAccess, "the known publisher's plain line, word for word")
}
