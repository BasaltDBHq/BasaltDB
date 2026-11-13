// Package privdrop runs the engine as its own OS user without a service
// manager: basalt engine --user NAME, started as root by a container
// entrypoint, makes the engine's directories, gives up root for good and only
// then reads the config and the credential (CONTRACT.md, CLI, basalt engine
// --user). Systemd and launchd do the same for an installed service; this is
// what a container without either does.
package privdrop

import (
	"errors"
	"fmt"
	"os"
	"slices"
)

// engineUmask is the systemd unit's UMask: what the engine creates is its
// OS user's alone unless it sets a mode itself (the sockets are 0666).
const engineUmask = 0o077

// Account is an OS user: its ids and its supplementary groups.
type Account struct {
	Name   string
	UID    uint32
	GID    uint32
	Groups []uint32
}

// Dir is a directory the engine's OS user owns, made with mode.
type Dir struct {
	Path string
	Mode os.FileMode
}

// System is what the drop needs from the machine. OS is the real one.
type System interface {
	// Euid is the process's effective user id.
	Euid() uint32
	// Lookup resolves an OS user name.
	Lookup(name string) (Account, error)
	// CheckBinary refuses this process's binary when anyone but root
	// could change it, the check basalt service install makes.
	CheckBinary() error
	// Mkdir makes dir (or takes over an existing one root or owner owns)
	// with its mode, owned by owner, without following a symlink.
	Mkdir(dir Dir, owner string) error
	// Umask sets the process's file mode creation mask.
	Umask(mask int)
	Setgroups(gids []uint32) error
	Setgid(gid uint32) error
	Setuid(uid uint32) error
	// NoNewPrivs sets no_new_privs on every thread, where the OS has it.
	NoNewPrivs() error
	// Verify checks every thread runs as a with nothing left to regain root.
	Verify(a Account) error
}

// Result is what Drop did.
type Result struct {
	Account Account
	// Dropped is true when the process started as root and gave it up;
	// false when it already ran as the account.
	Dropped bool
}

// ErrNotPermitted is a start as neither root nor the engine's user.
var ErrNotPermitted = errors.New("not permitted")

// Drop makes the process run as the OS user name before anything secret is
// opened. Started as root it checks the binary, makes dirs owned by name,
// then sets the supplementary groups, the group and the user, in that order,
// sets no_new_privs and verifies none of it can be undone. Started as name
// already it checks the binary, sets no_new_privs and verifies. Anything
// else, and the user root, is refused before any change.
func Drop(sys System, name string, dirs []Dir) (Result, error) {
	acct, err := sys.Lookup(name)
	if err != nil {
		return Result{}, fmt.Errorf("--user %s: %w", name, err)
	}
	euid := sys.Euid()
	dropping, err := decide(acct, euid)
	if err != nil {
		return Result{}, err
	}
	if err := sys.CheckBinary(); err != nil {
		return Result{}, err
	}
	sys.Umask(engineUmask)
	if dropping {
		for _, d := range dirs {
			if err := sys.Mkdir(d, acct.Name); err != nil {
				return Result{}, fmt.Errorf("make %s for %s: %w", d.Path, acct.Name, err)
			}
		}
		if err := sys.Setgroups(acct.Groups); err != nil {
			return Result{}, fmt.Errorf("set the supplementary groups of %s: %w", acct.Name, err)
		}
		if err := sys.Setgid(acct.GID); err != nil {
			return Result{}, fmt.Errorf("set group id %d: %w", acct.GID, err)
		}
		if err := sys.Setuid(acct.UID); err != nil {
			return Result{}, fmt.Errorf("set user id %d: %w", acct.UID, err)
		}
	}
	if err := sys.NoNewPrivs(); err != nil {
		return Result{}, fmt.Errorf("set no_new_privs: %w", err)
	}
	if err := sys.Verify(acct); err != nil {
		return Result{}, fmt.Errorf("the engine did not stay %s: %w", acct.Name, err)
	}
	return Result{Account: acct, Dropped: dropping}, nil
}

// decide says whether the process must drop to acct (it runs as root), or
// already runs as it, and refuses everything else.
func decide(acct Account, euid uint32) (dropping bool, err error) {
	switch {
	case acct.UID == 0:
		return false, fmt.Errorf("--user %s is root (uid 0); the engine runs as its own OS user, so the agent's credential is that user's alone", acct.Name)
	case acct.GID == 0:
		return false, fmt.Errorf("--user %s has the root group (gid 0) as its group; give the engine's OS user its own group, so it cannot change root's files", acct.Name)
	case slices.Contains(acct.Groups, 0):
		return false, fmt.Errorf("--user %s is a member of the root group (gid 0); remove it from that group, so the engine cannot change root's files", acct.Name)
	case euid == 0:
		return true, nil
	case euid == acct.UID:
		return false, nil
	}
	return false, fmt.Errorf("%w: basalt engine --user %s starts as root (a container entrypoint) or as %s itself, not as uid %d",
		ErrNotPermitted, acct.Name, acct.Name, euid)
}

// sameGroups reports whether got holds exactly the gids in want, in any
// order and ignoring repeats.
func sameGroups(got, want []uint32) bool {
	g, w := slices.Clone(got), slices.Clone(want)
	slices.Sort(g)
	slices.Sort(w)
	return slices.Equal(slices.Compact(g), slices.Compact(w))
}
