package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine/privdrop"
)

// rootSystem is a privdrop.System started as root whose steps all succeed;
// it records the directories it was asked to make.
type rootSystem struct {
	dirs []privdrop.Dir
	err  error
}

func (s *rootSystem) Euid() uint32 { return 0 }
func (s *rootSystem) Lookup(name string) (privdrop.Account, error) {
	return privdrop.Account{Name: name, UID: 990, GID: 991, Groups: []uint32{991}}, nil
}
func (s *rootSystem) CheckBinary() error { return s.err }
func (s *rootSystem) Mkdir(d privdrop.Dir, _ string) error {
	s.dirs = append(s.dirs, d)
	return nil
}
func (s *rootSystem) Umask(int)                     {}
func (s *rootSystem) Setgroups([]uint32) error      { return nil }
func (s *rootSystem) Setgid(uint32) error           { return nil }
func (s *rootSystem) Setuid(uint32) error           { return nil }
func (s *rootSystem) NoNewPrivs() error             { return nil }
func (s *rootSystem) Verify(privdrop.Account) error { return nil }

func TestDropToUserMakesTheServiceDirectories(t *testing.T) {
	sys := &rootSystem{}
	var out bytes.Buffer
	require.NoError(t, dropToUser(sys, "basalt", &out))
	require.Contains(t, out.String(), "basalt engine: dropped root; running as basalt (uid 990, gid 991)")
	require.Len(t, sys.dirs, 2)
}

func TestEngineDirsAreTheUnitDirectories(t *testing.T) {
	require.Equal(t, []privdrop.Dir{
		{Path: "/run/basalt", Mode: 0o755},
		{Path: "/var/lib/basalt", Mode: 0o700},
	}, engineDirs("linux"))
	require.Equal(t, []privdrop.Dir{
		{Path: "/Library/Application Support/Basalt/run", Mode: 0o755},
		{Path: "/Library/Application Support/Basalt/state", Mode: 0o750},
	}, engineDirs("darwin"))
}

// A refused drop stops basalt engine before it reads the config: the
// config path given does not exist, and the error is the drop's.
func TestEngineUserRefusalComesBeforeTheConfig(t *testing.T) {
	var errOut bytes.Buffer
	code := runEngine(t.Context(), []string{"--user", "root", "--config", "/nonexistent/engine.json"}, stdio{in: bytes.NewReader(nil), out: &bytes.Buffer{}, err: &errOut})
	require.Equal(t, exitError, code)
	require.Contains(t, errOut.String(), "--user root is root (uid 0)")
	require.NotContains(t, errOut.String(), "/nonexistent")

	sys := &rootSystem{err: errors.New("binary is writable")}
	require.ErrorContains(t, dropToUser(sys, "basalt", os.Stderr), "binary is writable")
	require.Empty(t, sys.dirs, "nothing is made for an untrusted binary")
}
