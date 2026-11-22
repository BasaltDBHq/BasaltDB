package osservice

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"slices"
	"strconv"
)

// OSSystem runs install steps on this machine. Commands inherit stdout and
// stderr so a person sees what the service manager says.
type OSSystem struct {
	Stdout, Stderr io.Writer
}

// UserExists reports whether the OS user exists.
func (OSSystem) UserExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

// InGroup reports whether the OS user name is in group, as its primary or a
// supplementary group. A group that does not exist has no one in it.
func (OSSystem) InGroup(name, group string) (bool, error) {
	return InGroup(name, group)
}

// InGroup is OSSystem.InGroup, for the engine, which has no System. In a
// build without cgo, Linux group membership comes from /etc/group only, so a
// membership only a directory service (sssd, LDAP) knows is not seen, as for
// plugin.CheckAgentUsers.
func InGroup(name, group string) (bool, error) {
	g, err := user.LookupGroup(group)
	var unknown user.UnknownGroupError
	if errors.As(err, &unknown) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	u, err := user.Lookup(name)
	if err != nil {
		return false, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return false, err
	}
	return u.Gid == g.Gid || slices.Contains(gids, g.Gid), nil
}

// keepID tells chown to leave an id as it is; as an owner uid it is no user.
const keepID = -1

// LookupUID is the uid of the OS user name, or -1 when there is no such
// user (the install has not made it yet, so it owns nothing).
func LookupUID(name string) int {
	u, err := user.Lookup(name)
	if err != nil {
		return keepID
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil {
		return keepID
	}
	return uid
}

// Output runs a command and returns its stdout.
func (OSSystem) Output(ctx context.Context, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, args[0], args[1:]...).Output()
	return string(out), err
}

// Run runs a command.
func (s OSSystem) Run(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = s.Stdout, s.Stderr
	return cmd.Run()
}

// WriteFile writes a file with mode, also when it already exists with
// another mode.
func (OSSystem) Remove(path string) error {
	return os.Remove(path)
}

// Exists reports whether a file exists.
func (OSSystem) Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
