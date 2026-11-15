package guard

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/require"
)

// The schema files load in name order, each without its header, and
// version 1 is all of them.
func TestSchemaFiles(t *testing.T) {
	t.Parallel()
	files, err := loadSchema(schemaFS)
	require.NoError(t, err)
	require.NotEmpty(t, files)
	require.Equal(t, strings.Join(files, ""), migrations[0].sql)
	for _, sql := range files {
		require.True(t, strings.HasPrefix(sql, "\n"), "the SQL starts after the header's blank line")
		require.NotContains(t, sql, strings.TrimSpace(recordInstallLine))
	}
	require.Contains(t, migrations[0].sql, recordInstallRow)
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
