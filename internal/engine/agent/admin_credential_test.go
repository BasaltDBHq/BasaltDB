package agent

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/mcp"
)

func TestHoldsAdminCredential(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"in a query":        `{"sql":"SELECT * FROM dblink('postgres://admin:s3cret@db.example.com:5432/app', 'select 1') t(x int)"}`,
		"postgresql scheme": `{"sql":"x","params":["postgresql://postgres:pw@h/db"]}`,
		"upper case":        `{"intent":"POSTGRES://u:p@h/db"}`,
		"nested":            `{"a":{"b":[{"c":"postgres://u:p@h/db"}]}}`,
		"in a key":          `{"postgres://u:p@h/db":1}`,
		"escaped colon":     `{"sql":"postgres\u003a//u:p@h/db"}`,
		"escaped slash":     `{"sql":"postgres:\/\/u:p@h/db"}`,
		"escaped at":        `{"sql":"postgres://u:p\u0040h/db"}`,
		"doubled quote":     `{"sql":"SELECT dblink('postgres://admin:ab''cd@db/app','select 1')"}`,
		"quote":             `{"sql":"postgres://u:a'b@h/db"}`,
		"json quote":        `{"sql":"postgres://u:a\"b@h/db"}`,
		"escaped scheme":    `{"sql":"\u0070ostgres://u:p@h/db"}`,
		"password param":    `{"sql":"postgres://u@h/db?sslmode=require&password=hunter2"}`,
		"empty user":        `{"sql":"postgres://:p@h/db"}`,
		"not json":          `postgres://u:p@h/db`,
		"slash in password": `{"sql":"postgres://u:pa/ss@h/db"}`,
	} {
		require.True(t, holdsAdminCredential(json.RawMessage(raw)), name)
	}
	for name, raw := range map[string]string{
		"no password":           `{"sql":"SELECT dblink_connect('postgres://u@h/db')"}`,
		"host and port":         `{"sql":"postgres://h:5432/db"}`,
		"no password parameter": `{"sql":"postgres://u@h/db?sslmode=require"}`,
		"plain sql":             `{"sql":"SELECT 1","params":["a:b@c"]}`,
		"other scheme":          `{"sql":"mysql://u:p@h/db"}`,
		"empty":                 `{}`,
	} {
		require.False(t, holdsAdminCredential(json.RawMessage(raw)), name)
	}
}

// Every tool refuses such a call before it admits it, reads the database or
// writes the ledger (the service's store is nil, so any use panics), and
// neither the answer nor the log carries the value.
func TestEveryToolRefusesAnAdminURLInItsArguments(t *testing.T) {
	t.Parallel()
	const secret = "s3cretpassw0rd"
	d := deps()
	d.Store = parts{}
	var logs bytes.Buffer
	d.Log = slog.New(slog.NewTextHandler(&logs, nil))
	d.Now = func() time.Time { return statusNow }
	tools := Tools(NewService(d))
	srv := mcp.NewServer(mcp.Info{Name: "basalt"}, tools...)
	url := "postgres://admin:" + secret + "@db.example.com:5432/app"
	entry, ok := catalogOf(t).ErrorEntry(CodeInvalidArgument, ReasonAdminCredential, "")
	require.True(t, ok)

	for _, tool := range tools {
		for name, args := range map[string]map[string]any{
			"value": {"sql": "SELECT dblink('" + url + "', 'select 1')", "intent": url, "params": []any{url}},
			"key":   {url: true},
		} {
			body, isError := serveCall(t, srv, tool.Name, args)
			require.True(t, isError, tool.Name+" "+name)
			require.Equal(t, CodeInvalidArgument, body["code"], tool.Name)
			require.Equal(t, ReasonAdminCredential, body["reason"], tool.Name)
			require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), steps(t, body), tool.Name)
			require.Contains(t, body["personMessage"], "Change that database password", tool.Name)
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			require.NotContains(t, string(raw), secret, tool.Name)
			require.NotContains(t, string(raw), "db.example.com", tool.Name)
		}
	}
	// The engine-down tools (basalt mcp, engine not answering) refuse too.
	down := EngineDown{Name: "bot", Log: d.Log, Now: d.Now}
	downTools := down.Tools()
	downSrv := mcp.NewServer(mcp.Info{Name: "basalt"}, downTools...)
	for _, tool := range downTools {
		for _, args := range []map[string]any{{"sql": url}, {url: true}} {
			body, isError := serveCall(t, downSrv, tool.Name, args)
			require.True(t, isError, tool.Name)
			require.Equal(t, ReasonAdminCredential, body["reason"], tool.Name)
			require.Equal(t, mcpcontract.Resolve(entry.Steps, mcpcontract.OperatedByPerson), steps(t, body), tool.Name)
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			require.NotContains(t, string(raw), secret, tool.Name)
		}
	}
	require.NotContains(t, logs.String(), secret)
	require.NotContains(t, logs.String(), "db.example.com")
}
