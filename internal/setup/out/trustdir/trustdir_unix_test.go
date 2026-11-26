//go:build unix

package trustdir_test

import (
	"crypto/x509"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/setup/out/trustdir"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile"
	"github.com/basaltdbhq/basaltdb/pkg/trustprofile/trustprofiletest"
)

// configPath is an engine.json path in a fresh directory reached without a
// symlink (macOS's temporary directory is under /var, a link).
func configPath(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, os.Chmod(dir, 0o700))
	return filepath.Join(dir, "engine.json")
}

func testCA(t *testing.T) (*x509.Certificate, []byte) {
	t.Helper()
	ca, _ := trustprofiletest.Chain(t, "db.internal.example.com")
	return ca, trustprofiletest.PEM(ca)
}

func names(ps []*trustprofile.Profile) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Name)
	}
	return out
}

func refusedFiles(rs []trustprofile.Refused) []string {
	out := make([]string, 0, len(rs))
	for _, r := range rs {
		out = append(out, filepath.Base(r.File))
	}
	return out
}

func TestNoTrustDirIsNothing(t *testing.T) {
	t.Parallel()
	ops, refused := trustdir.Load(configPath(t))
	require.Empty(t, ops)
	require.Empty(t, refused)
	set := trustdir.Set(configPath(t))
	require.Equal(t, "supabase", set.For("db.abcdefghijklmnopqrst.supabase.co").Name)
}

// addProfile writes an operator profile called name, its roots pem, for
// the hosts match names, into a 0700 trust.d, as an operator would.
func addProfile(t *testing.T, cfg, name string, match []string, pem []byte) {
	t.Helper()
	dir := trustdir.Path(cfg)
	require.NoError(t, os.MkdirAll(dir, 0o700))
	raw, err := json.Marshal(trustprofile.Spec{Name: name, Match: match, Roots: []trustprofile.RootSpec{{File: name + ".pem", SHA256: trustprofile.FileSHA256(pem)}}})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, name+".pem"), pem, 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(dir, trustprofile.FileName(name)), raw, 0o644))
}

// An operator profile in trust.d loads, and applies only inside its match.
func TestLoadOperatorProfile(t *testing.T) {
	t.Parallel()
	cfg := configPath(t)
	ca, pem := testCA(t)
	addProfile(t, cfg, "internal", []string{"Internal.Example.com."}, pem)

	ops, refused := trustdir.Load(cfg)
	require.Empty(t, refused)
	require.Equal(t, []string{"internal"}, names(ops))
	require.Equal(t, []string{"internal.example.com"}, ops[0].Match)
	require.True(t, ops[0].Certificates()[0].Equal(ca))
	set := trustdir.Set(cfg)
	require.Equal(t, "internal", set.For("db.internal.example.com").Name)
	require.Nil(t, set.For("db.example.com"), "never outside its match")
}

// An operator profile that disables a built-in turns it off.
func TestLoadDisabledBuiltIn(t *testing.T) {
	t.Parallel()
	cfg := configPath(t)
	require.NoError(t, os.MkdirAll(trustdir.Path(cfg), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(trustdir.Path(cfg), trustprofile.FileName("aws-rds")), []byte(`{"name":"aws-rds","disabled":true}`), 0o644))
	require.Nil(t, trustdir.Set(cfg).For("mydb.c9akciq32xyz.eu-central-1.rds.amazonaws.com"))
}

// A file that breaks a rule is refused and named; the good ones load, and
// a refused file never takes a built-in's place.
func TestLoadRefuses(t *testing.T) {
	t.Parallel()
	cfg := configPath(t)
	_, pem := testCA(t)
	addProfile(t, cfg, "good", []string{"good.example.com"}, pem)
	dir := trustdir.Path(cfg)
	write := func(name string, b []byte, mode os.FileMode) {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), b, mode))
		require.NoError(t, os.Chmod(filepath.Join(dir, name), mode))
	}
	profile := func(name, pemFile, sum string) []byte {
		b, err := json.Marshal(trustprofile.Spec{Name: name, Match: []string{name + ".example.com"}, Roots: []trustprofile.RootSpec{{File: pemFile, SHA256: sum}}})
		require.NoError(t, err)
		return b
	}
	sum := trustprofile.FileSHA256(pem)

	write("groupw.pem", pem, 0o644)
	write("groupw.json", profile("groupw", "groupw.pem", sum), 0o664)
	write("pemw.pem", pem, 0o666)
	write("pemw.json", profile("pemw", "pemw.pem", sum), 0o644)
	write("mismatch.pem", append(append([]byte{}, pem...), pem...), 0o644)
	write("mismatch.json", profile("mismatch", "mismatch.pem", sum), 0o644)
	write("misnamed.json", profile("other", "good.pem", sum), 0o644)
	write("supabase.json", []byte(`{"name":"supabase","match":["x.supabase.co"],"roots":[{"file":"gone.pem","sha256":"`+sum+`"}]}`), 0o644)
	elsewhere := filepath.Join(filepath.Dir(cfg), "elsewhere.json")
	require.NoError(t, os.WriteFile(elsewhere, profile("link", "good.pem", sum), 0o644))
	require.NoError(t, os.Symlink(elsewhere, filepath.Join(dir, "link.json")))
	outside := filepath.Join(filepath.Dir(cfg), "outside.pem")
	require.NoError(t, os.WriteFile(outside, pem, 0o644))
	require.NoError(t, os.Link(outside, filepath.Join(dir, "hard.pem")))
	write("hard.json", profile("hard", "hard.pem", sum), 0o644)
	write(".hidden.json", []byte("not json"), 0o644)
	write("notes.txt", []byte("ignored"), 0o644)

	ops, refused := trustdir.Load(cfg)
	for _, r := range refused {
		t.Log(r.File, ": ", r.Reason)
	}
	require.Equal(t, []string{"good"}, names(ops))
	require.ElementsMatch(t, []string{"groupw.json", "pemw.json", "mismatch.json", "misnamed.json", "supabase.json", "link.json", "hard.json"}, refusedFiles(refused))
	require.Nil(t, trustdir.Set(cfg).For("x.y.supabase.co"), "a refused file named after a built-in keeps it off")
	require.Equal(t, "aws-rds", trustdir.Set(cfg).For("db.x.eu-west-1.rds.amazonaws.com").Name)
}

// A trust.d writable by group or others is refused whole, and named.
func TestLoadRefusesAnOpenDirectory(t *testing.T) {
	t.Parallel()
	cfg := configPath(t)
	_, pem := testCA(t)
	addProfile(t, cfg, "good", []string{"good.example.com"}, pem)
	require.NoError(t, os.Chmod(trustdir.Path(cfg), 0o777))
	ops, refused := trustdir.Load(cfg)
	require.Empty(t, ops)
	require.Equal(t, []string{"trust.d"}, refusedFiles(refused))
	require.Contains(t, refused[0].Reason, "writable by group or others")
}

// A trust.d that is a symlink is refused.
func TestLoadRefusesASymlinkedDirectory(t *testing.T) {
	t.Parallel()
	cfg := configPath(t)
	target := filepath.Join(filepath.Dir(cfg), "real")
	require.NoError(t, os.Mkdir(target, 0o700))
	require.NoError(t, os.Symlink(target, trustdir.Path(cfg)))
	ops, refused := trustdir.Load(cfg)
	require.Empty(t, ops)
	require.Len(t, refused, 1)
	require.Contains(t, refused[0].Reason, "symlink")
}
