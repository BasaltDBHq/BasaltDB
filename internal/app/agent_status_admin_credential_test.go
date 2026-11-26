package app

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
)

// Every tool refuses such a call before it admits it, reads the database or
// writes the ledger (the service's store is nil, so any use panics), and
// neither the answer nor the log carries the value.
// Every spelling of an admin connection string is refused by every tool,
// in the SQL, the intent and a parameter, before the store (which panics on
// any use here) is reached: nothing reaches Postgres or the ledger, and
// neither the result nor the log holds the password.
func TestEveryToolRefusesEverySpellingOfAnAdminString(t *testing.T) {
	t.Parallel()
	const secret = "QApwB2zz"
	jsonText := func(dsn string) string {
		b, err := json.Marshal(map[string]string{"dsn": dsn}) // Go's default encoder: & is \u0026
		require.NoError(t, err)
		return string(b)
	}
	spellings := map[string]string{
		"json text, user param":     jsonText("postgresql://db.example.com/app?user=u&password='" + secret + "'"),
		"json text, sslmode first":  jsonText("postgresql://db.example.com/app?sslmode=require&PASSWORD=" + secret),
		"json text, jdbc":           jsonText("jdbc:postgresql://db.example.com:5432/app?user=u&password=" + secret),
		"space in password":         "postgres://admin:pa ss" + secret + "@db.example.com/app",
		"percent-encoded parameter": "postgres://u@db.example.com/app?sslmode=require&pass%77ord=" + secret,
		"double percent-encoded":    "postgres://u@db.example.com/app?pass%2577ord=" + secret,
		"percent-encoded scheme":    "%70ostgresql%3A%2F%2Fadmin:" + secret + "@db.example.com/app",
		"driver in the scheme":      "postgresql+psycopg2://admin:" + secret + "@db.example.com/app",
		"key value":                 "host=db.example.com user=postgres password=" + secret + " dbname=app",
		"key value, quoted space":   "dbname=app password='a " + secret + "' host=db.example.com",
		"key value in dblink":       "SELECT * FROM dblink('host=db.example.com user=postgres password=" + secret + "', 'select 1') AS t(x int)",
		"zero-width in the scheme":  "post\u200bgres://admin:" + secret + "@db.example.com/app",
	}
	require.Contains(t, spellings["json text, user param"], `\u0026`)
	d := deps()
	useStore(&d, parts{})
	var logs bytes.Buffer
	d.Core.Log = slog.New(slog.NewTextHandler(&logs, nil))
	d.Core.Now = func() time.Time { return statusNow }
	tools := AgentTools(NewService(d))
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, tools...)
	for _, tool := range tools {
		for name, v := range spellings {
			for _, args := range []map[string]any{{"sql": v}, {"intent": v}, {"params": []any{v}}} {
				body, isError := serveCall(t, srv, tool.Name, args)
				require.True(t, isError, tool.Name+" "+name)
				require.Equal(t, guidance.ReasonAdminCredential, body["reason"], tool.Name+" "+name)
				raw, err := json.Marshal(body)
				require.NoError(t, err)
				require.NotContains(t, string(raw), secret, tool.Name+" "+name)
				require.NotContains(t, string(raw), "db.example.com", tool.Name+" "+name)
			}
		}
	}
	require.NotContains(t, logs.String(), secret)
}

func TestEveryToolRefusesAnAdminURLInItsArguments(t *testing.T) {
	t.Parallel()
	const secret = "s3cretpassw0rd"
	d := deps()
	useStore(&d, parts{})
	var logs bytes.Buffer
	d.Core.Log = slog.New(slog.NewTextHandler(&logs, nil))
	d.Core.Now = func() time.Time { return statusNow }
	tools := AgentTools(NewService(d))
	srv := mcpserver.NewServer(mcpserver.Info{Name: "basalt"}, tools...)
	url := "postgres://admin:" + secret + "@db.example.com:5432/app"
	entry, ok := stepcatalogtest.CatalogOf(t).ErrorEntry(guidance.CodeInvalidArgument, guidance.ReasonAdminCredential, "")
	require.True(t, ok)

	for _, tool := range tools {
		for name, args := range map[string]map[string]any{
			"value": {"sql": "SELECT dblink('" + url + "', 'select 1')", "intent": url, "params": []any{url}},
			"key":   {url: true},
		} {
			body, isError := serveCall(t, srv, tool.Name, args)
			require.True(t, isError, tool.Name+" "+name)
			require.Equal(t, guidance.CodeInvalidArgument, body["code"], tool.Name)
			require.Equal(t, guidance.ReasonAdminCredential, body["reason"], tool.Name)
			require.Equal(t, stepcatalogtest.Resolve(entry.Steps, mcpcontract.OperatedByPerson), steps(t, body), tool.Name)
			require.Contains(t, body["personMessage"], "Change that database password", tool.Name)
			raw, err := json.Marshal(body)
			require.NoError(t, err)
			require.NotContains(t, string(raw), secret, tool.Name)
			require.NotContains(t, string(raw), "db.example.com", tool.Name)
		}
	}
	require.NotContains(t, logs.String(), secret)
	require.NotContains(t, logs.String(), "db.example.com")
}
