package mcpserver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHoldsAdminCredential(t *testing.T) {
	t.Parallel()
	for name, raw := range map[string]string{
		"in a query":                  `{"sql":"SELECT * FROM dblink('postgres://admin:s3cret@db.example.com:5432/app', 'select 1') t(x int)"}`,
		"postgresql scheme":           `{"sql":"x","params":["postgresql://postgres:pw@h/db"]}`,
		"upper case":                  `{"intent":"POSTGRES://u:p@h/db"}`,
		"nested":                      `{"a":{"b":[{"c":"postgres://u:p@h/db"}]}}`,
		"in a key":                    `{"postgres://u:p@h/db":1}`,
		"escaped colon":               `{"sql":"postgres\u003a//u:p@h/db"}`,
		"escaped slash":               `{"sql":"postgres:\/\/u:p@h/db"}`,
		"escaped at":                  `{"sql":"postgres://u:p\u0040h/db"}`,
		"doubled quote":               `{"sql":"SELECT dblink('postgres://admin:ab''cd@db/app','select 1')"}`,
		"quote":                       `{"sql":"postgres://u:a'b@h/db"}`,
		"apostrophe in user":          `{"sql":"postgres://o'brien:QApwA1@db.example.com/app"}`,
		"quote starts password param": `{"sql":"postgresql://db.example.com/app?user=u&password='QApwB2'"}`,
		"json quote":                  `{"sql":"postgres://u:a\"b@h/db"}`,
		"json quote in user":          `{"sql":"postgres://o\"brien:p@h/db"}`,
		"escaped scheme":              `{"sql":"\u0070ostgres://u:p@h/db"}`,
		"password param":              `{"sql":"postgres://u@h/db?sslmode=require&password=hunter2"}`,
		"empty user":                  `{"sql":"postgres://:p@h/db"}`,
		"not json":                    `postgres://u:p@h/db`,
		"slash in password":           `{"sql":"postgres://u:pa/ss@h/db"}`,
		"json text param":             `{"params":["{\"dsn\":\"postgresql://db.example.com/app?user=u\\u0026password='QApwB2'\"}"]}`,
		"space in password":           `{"sql":"postgres://u:pa ss@h/db"}`,
		"percent-encoded parameter":   `{"sql":"postgres://u@h/db?pass%77ord=p"}`,
		"percent-encoded scheme":      `{"sql":"%70ostgres%3A%2F%2Fu:p@h/db"}`,
		"driver in the scheme":        `{"sql":"postgresql+psycopg2://u:p@h/db"}`,
		"jdbc":                        `{"sql":"jdbc:postgresql://h/db?user=u&password=p"}`,
		"key value":                   `{"sql":"SELECT dblink('host=h user=u password=p', 'select 1')"}`,
		"key value, password first":   `{"intent":"password = 'a b' dbname=app"}`,
		"zero-width in the scheme":    `{"sql":"post\u200bgres://u:p@h/db"}`,
		"not json, key value":         `host=h password=p`,
	} {
		require.True(t, HoldsAdminCredential(json.RawMessage(raw)), name)
	}
	for name, raw := range map[string]string{
		"no password":           `{"sql":"SELECT dblink_connect('postgres://u@h/db')"}`,
		"host and port":         `{"sql":"postgres://h:5432/db"}`,
		"no password parameter": `{"sql":"postgres://u@h/db?sslmode=require"}`,
		"plain sql":             `{"sql":"SELECT 1","params":["a:b@c"]}`,
		"other scheme":          `{"sql":"mysql://u:p@h/db"}`,
		"the word password":     `{"intent":"reset the password for user bob"}`,
		"sql set and where":     `{"sql":"UPDATE users SET password = $1 WHERE user = $2"}`,
		"sql and":               `{"sql":"SELECT 1 FROM t WHERE \"user\"='a' AND password='b'"}`,
		"sql comma":             `{"sql":"UPDATE accounts SET password='x', host='h'"}`,
		"password key alone":    `{"intent":"password=reset"}`,
		"url then an email":     `{"sql":"SELECT 'postgres://h:5432/db', email FROM t WHERE email LIKE '%@x.com'"}`,
		"a percent sign":        `{"intent":"100% of the password column"}`,
		"json with a password":  `{"params":["{\"user\":\"u\",\"password\":\"p\"}"]}`,
		"empty":                 `{}`,
	} {
		require.False(t, HoldsAdminCredential(json.RawMessage(raw)), name)
	}
}
