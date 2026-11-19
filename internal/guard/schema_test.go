package guard

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

// The schema files load in name order, each without its header, and the
// versions run all of them, in order, each file once.
func TestSchemaFiles(t *testing.T) {
	t.Parallel()
	files, err := loadSchema(schemaFS)
	require.NoError(t, err)
	require.NotEmpty(t, files)
	all := ""
	for i, m := range migrations {
		require.Equal(t, i+1, m.version)
		all += m.sql
	}
	require.Equal(t, strings.Join(files, ""), all)
	require.Equal(t, versionPluginTrustRemoved, LatestVersion())
	require.True(t, migrations[versionPluginEvents-1].nonBreaking)
	require.True(t, migrations[versionPluginTrustRemoved-1].nonBreaking)
	require.False(t, migrations[versionInstallIDs-1].nonBreaking)
	for _, sql := range files {
		require.True(t, strings.HasPrefix(sql, "\n"), "the SQL starts after the header's blank line")
		require.NotContains(t, sql, strings.TrimSpace(recordInstallLine))
	}
	require.Contains(t, migrations[versionInstallIDs-1].sql, recordInstallRow)
	require.NotContains(t, migrations[versionGuard-1].sql, recordInstallRow, "version 1 keeps the oid row it shipped with")
	require.Contains(t, migrations[versionGuard-1].sql, recordInstallRowV1, "recordInstall(1) runs the statement version 1 has")
}

func TestSchemaFilesRefuseAMalformedDirectory(t *testing.T) {
	t.Parallel()
	file := func(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }
	good := "-- a header\n--\n-- on two lines\n\nSELECT 1;\n" + recordInstallLine
	for name, fsys := range map[string]fstest.MapFS{
		"no header":            {"schema/001_a.sql": file("\nSELECT 1;\n" + recordInstallLine)},
		"no blank line":        {"schema/001_a.sql": file("-- a header\nSELECT 1;\n" + recordInstallLine)},
		"header not a comment": {"schema/001_a.sql": file("-- a header\nSELECT 1;\n\nSELECT 2;\n" + recordInstallLine)},
		"a gap":                {"schema/001_a.sql": file(good), "schema/003_b.sql": file("-- b\n\nSELECT 2;\n")},
		"not sql":              {"schema/001_a.txt": file(good)},
		"no install row":       {"schema/001_a.sql": file("-- a\n\nSELECT 1;\n")},
		"two install rows":     {"schema/001_a.sql": file(good), "schema/002_b.sql": file(good)},
	} {
		_, err := loadSchema(fsys)
		require.Error(t, err, name)
	}
	files, err := loadSchema(fstest.MapFS{"schema/001_a.sql": file(good)})
	require.NoError(t, err)
	require.Equal(t, []string{"\nSELECT 1;\n" + recordInstallRow}, files)
}
