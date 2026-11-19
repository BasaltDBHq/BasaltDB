package main

import (
	"fmt"
	"io/fs"
	"os/user"
	"slices"
	"strconv"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/mcp"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// pathRuleRefusal is the UNSAFE_PATH refusal of a path the path rule
// refused (CONTRACT.md, Plugins, the path rule): it names the path and what
// is wrong with it, and says in words what would fix it. Trusting a key
// does not, and Basalt changes no directory it does not own, so it offers
// no command but the refused one, once the path is fixed.
func pathRuleRefusal(r *pluginRefusedError, ve *plugin.VerifyError, again string) error {
	f := ve.Path
	r.reason = reasonUnsafePath
	var what, fix string
	switch f.Kind {
	case plugin.PathWritable:
		what = fmt.Sprintf("%s can be written by %s (owner %s, group %s, mode %04o); only its owner may write it",
			ve.File, writers(f), userName(f.UID), groupName(f.GID), octalMode(f.Mode))
		fix = "If it is yours, remove others' write access; if not, ask whoever runs this machine"
	case plugin.PathSymlink:
		what = fmt.Sprintf("%s is a symbolic link owned by %s; only links root owns, above the plugin files, are followed",
			ve.File, userName(f.UID))
		fix = "Put the real file or directory there, or ask whoever runs this machine"
	default:
		what = fmt.Sprintf("%s is owned by %s; it must be owned by %s", ve.File, userName(f.UID), ownerNames(f.Owners))
		fix = "Use one that belongs to " + ownerNames(f.Owners) + ", or ask whoever runs this machine"
	}
	r.person = "Plugin refused: " + what + ". Trusting a key does not fix this, and Basalt does not change it. " + fix +
		". Then run again:\n  " + again
	r.steps = []mcp.NextStep{
		{Actor: mcp.ActorAgent, Action: mcp.ActionAskPerson, Text: "Show the person the personMessage: " + ve.File +
			" must be fixed on this machine. Do not change it yourself, and do not offer to trust a key."},
		{Actor: mcp.ActorPerson, Action: mcp.ActionRunCommand, Text: "Once " + ve.File + " is fixed, run the refused command again.", Command: again},
	}
	return r
}

// octalMode is m as ls shows it in octal: the permission bits, with the
// setuid, setgid and sticky bits.
func octalMode(m fs.FileMode) uint32 {
	o := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		o |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		o |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		o |= 0o1000
	}
	return o
}

// writers says who besides the owner can write a path of fault f.
func writers(f *plugin.PathFault) string {
	if f.Mode.Perm()&0o002 != 0 {
		return "every user"
	}
	return "members of group " + groupName(f.GID)
}

// userName is uid's user name, or "uid N" when it has none.
func userName(uid uint32) string {
	id := strconv.FormatUint(uint64(uid), 10)
	if u, err := user.LookupId(id); err == nil {
		return u.Username
	}
	return "uid " + id
}

// groupName is gid's group name, or "gid N" when it has none.
func groupName(gid uint32) string {
	id := strconv.FormatUint(uint64(gid), 10)
	if g, err := user.LookupGroupId(id); err == nil {
		return g.Name
	}
	return "gid " + id
}

// ownerNames names the users a path may be owned by, "root or alice".
func ownerNames(uids []uint32) string {
	names := make([]string, 0, len(uids))
	for _, u := range uids {
		if n := userName(u); !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return strings.Join(names, " or ")
}
