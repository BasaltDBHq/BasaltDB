package osservice_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/platform/osservice"
)

// fakeStat serves lstat from a map; a missing path does not exist.
func fakeStat(files map[string]osservice.FileStat) osservice.StatFunc {
	return func(path string) (osservice.FileStat, error) {
		st, ok := files[path]
		if !ok {
			return osservice.FileStat{}, os.ErrNotExist
		}
		return st, nil
	}
}

func rootDir(perm os.FileMode) osservice.FileStat { return osservice.FileStat{Mode: os.ModeDir | perm} }

func TestCheckBinary(t *testing.T) {
	t.Parallel()
	const person = 501
	protected := map[string]osservice.FileStat{
		"/":                         rootDir(0o755),
		"/usr":                      rootDir(0o755),
		"/usr/local":                rootDir(0o755),
		"/usr/local/libexec":        rootDir(0o755),
		"/usr/local/libexec/basalt": {Mode: 0o755},
	}
	with := func(path string, st osservice.FileStat) map[string]osservice.FileStat {
		out := map[string]osservice.FileStat{}
		for k, v := range protected {
			out[k] = v
		}
		out[path] = st
		return out
	}
	for _, tc := range []struct {
		name  string
		files map[string]osservice.FileStat
		want  string
	}{
		{name: "root-owned and protected", files: protected},
		{name: "root:admin group that cannot write", files: with("/usr/local/libexec", osservice.FileStat{Mode: os.ModeDir | 0o755})},
		{name: "root-owned symlink", files: with("/usr/local/libexec/basalt", osservice.FileStat{Mode: os.ModeSymlink | 0o777})},
		{
			name:  "binary owned by the person",
			files: with("/usr/local/libexec/basalt", osservice.FileStat{UID: person, Mode: 0o755}),
			want:  "/usr/local/libexec/basalt is owned by uid 501, not root",
		},
		{
			name:  "group-writable binary",
			files: with("/usr/local/libexec/basalt", osservice.FileStat{Mode: 0o775}),
			want:  "/usr/local/libexec/basalt is writable by group or others (mode 0775)",
		},
		{
			name:  "Homebrew directory owned by the person (Intel Mac)",
			files: with("/usr/local/libexec", osservice.FileStat{UID: person, Mode: os.ModeDir | 0o775}),
			want:  "/usr/local/libexec is owned by uid 501, not root",
		},
		{
			name:  "group-writable directory",
			files: with("/usr/local", rootDir(0o775)),
			want:  "/usr/local is writable by group or others (mode 0775)",
		},
		{
			name:  "world-writable sticky directory",
			files: with("/usr", rootDir(os.ModeSticky|0o777)),
			want:  "/usr is writable by group or others",
		},
		{
			name:  "person-owned symlink",
			files: with("/usr/local/libexec/basalt", osservice.FileStat{UID: person, Mode: os.ModeSymlink | 0o777}),
			want:  "owned by uid 501",
		},
		{
			name:  "not a regular file",
			files: with("/usr/local/libexec/basalt", rootDir(0o755)),
			want:  "is not a regular file",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := osservice.CheckBinary("/usr/local/libexec/basalt", fakeStat(tc.files))
			if tc.want == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.want)
			require.ErrorContains(t, err, "sudo install -o root -m 0755 /usr/local/libexec/basalt /usr/local/libexec/basalt")
		})
	}
}

func TestCheckBinaryMissingOrRelative(t *testing.T) {
	t.Parallel()
	require.ErrorIs(t, osservice.CheckBinary("/opt/basalt", fakeStat(nil)), os.ErrNotExist)
	require.ErrorContains(t, osservice.CheckBinary("basalt", fakeStat(nil)), "must be absolute")
}

// The install checks the binary before it plans a single step.
func TestInstallPlanRefusesUnprotectedBinary(t *testing.T) {
	t.Parallel()
	for _, spec := range []osservice.Spec{linuxSpec(), darwinSpec()} {
		sys := newFake()
		sys.binaryErr = os.ErrPermission
		steps, err := osservice.InstallPlan(t.Context(), sys, spec)
		require.ErrorIs(t, err, os.ErrPermission)
		require.Empty(t, steps)
		require.Empty(t, sys.ran)
	}
}
