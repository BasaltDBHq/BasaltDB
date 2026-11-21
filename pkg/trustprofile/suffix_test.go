package trustprofile_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
)

// An operator suffix that is itself a public suffix (ICANN or private entry
// of Go's list) is refused; a domain below one, and an exact host, are not.
func TestCheckOperatorMatch(t *testing.T) {
	t.Parallel()
	for _, m := range []string{
		"com", "internal", "co.uk", "com.au", "amazonaws.com", "amazonaws.com.cn", "azure.com", "cloudapp.azure.com", "cloudapp.net", "windows.net", "rds.amazonaws.com", "rds.amazonaws.com.cn", "database.windows.net", "postgres.database.azure.com", "azurewebsites.net", "googleapis.com", "appspot.com",
		"github.io", "blogspot.com", "cloudfront.net",
		"s3.amazonaws.com", "elb.amazonaws.com", "compute-1.amazonaws.com",
	} {
		require.Error(t, trustprofile.CheckOperatorMatch(m), m)
	}
	for _, m := range []string{
		"example.com", "db.example.com", "=mydb.us-east-1.rds.amazonaws.com", "example.co.uk", "mine.github.io",
		"mydb.cloudfront.net", "=db.example.com", "=github.io", "=127.0.0.1",
	} {
		require.NoError(t, trustprofile.CheckOperatorMatch(m), "allowed: "+m)
	}
}
