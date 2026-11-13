package privdrop

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// fakeSystem records the calls Drop makes, in order.
type fakeSystem struct {
	euid     uint32
	accounts map[string]Account
	calls    []string
	// fail makes the named call fail.
	fail string
}

func (f *fakeSystem) record(call string) error {
	f.calls = append(f.calls, call)
	name, _, _ := strings.Cut(call, " ")
	if name == f.fail {
		return errors.New(name + " failed")
	}
	return nil
}

func (f *fakeSystem) Euid() uint32 { return f.euid }

func (f *fakeSystem) Lookup(name string) (Account, error) {
	a, ok := f.accounts[name]
	if !ok {
		return Account{}, fmt.Errorf("user: unknown user %s", name)
	}
	return a, nil
}

func (f *fakeSystem) CheckBinary() error { return f.record("checkBinary") }

func (f *fakeSystem) Mkdir(d Dir, owner string) error {
	return f.record(fmt.Sprintf("mkdir %s %04o %s", d.Path, d.Mode, owner))
}
func (f *fakeSystem) Umask(mask int) { _ = f.record(fmt.Sprintf("umask %04o", mask)) }
func (f *fakeSystem) Setgroups(g []uint32) error {
	return f.record(fmt.Sprintf("setgroups %v", g))
}
func (f *fakeSystem) Setgid(g uint32) error  { return f.record(fmt.Sprintf("setgid %d", g)) }
func (f *fakeSystem) Setuid(u uint32) error  { return f.record(fmt.Sprintf("setuid %d", u)) }
func (f *fakeSystem) NoNewPrivs() error      { return f.record("noNewPrivs") }
func (f *fakeSystem) Verify(a Account) error { return f.record("verify " + a.Name) }

var (
	basalt = Account{Name: "basalt", UID: 990, GID: 990, Groups: []uint32{990, 4}}
	root   = Account{Name: "root", UID: 0, GID: 0, Groups: []uint32{0}}
	dirs   = []Dir{{Path: "/run/basalt", Mode: 0o755}, {Path: "/var/lib/basalt", Mode: 0o700}}
)

func newFake(euid uint32) *fakeSystem {
	return &fakeSystem{euid: euid, accounts: map[string]Account{
		"basalt": basalt, "root": root,
		"rootgroup":   {Name: "rootgroup", UID: 991, GID: 0, Groups: []uint32{0}},
		"wheelmember": {Name: "wheelmember", UID: 992, GID: 992, Groups: []uint32{992, 0}},
	}}
}

func TestDropAsRootRunsEveryStepInOrder(t *testing.T) {
	sys := newFake(0)
	res, err := Drop(sys, "basalt", dirs)
	require.NoError(t, err)
	require.True(t, res.Dropped)
	require.Equal(t, basalt, res.Account)
	require.Equal(t, []string{
		"checkBinary",
		"umask 0077",
		"mkdir /run/basalt 0755 basalt",
		"mkdir /var/lib/basalt 0700 basalt",
		"setgroups [990 4]",
		"setgid 990",
		"setuid 990",
		"noNewPrivs",
		"verify basalt",
	}, sys.calls)
}

func TestDropAsTheUserSkipsTheDrop(t *testing.T) {
	sys := newFake(990)
	res, err := Drop(sys, "basalt", dirs)
	require.NoError(t, err)
	require.False(t, res.Dropped)
	require.Equal(t, []string{"checkBinary", "umask 0077", "noNewPrivs", "verify basalt"}, sys.calls)
}

func TestDropRefusesBeforeAnyChange(t *testing.T) {
	cases := []struct {
		name, user string
		euid       uint32
		want       string
	}{
		{"another user", "basalt", 1000, "starts as root (a container entrypoint) or as basalt itself, not as uid 1000"},
		{"root target", "root", 0, "--user root is root (uid 0)"},
		{"root target as user", "root", 1000, "--user root is root (uid 0)"},
		{"unknown user", "nobody-here", 0, "--user nobody-here: user: unknown user"},
		{"root primary group", "rootgroup", 0, "--user rootgroup has the root group (gid 0) as its group"},
		{"root supplementary group", "wheelmember", 0, "--user wheelmember is a member of the root group (gid 0)"},
		{"root group as the user", "wheelmember", 992, "--user wheelmember is a member of the root group (gid 0)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sys := newFake(tc.euid)
			_, err := Drop(sys, tc.user, dirs)
			require.ErrorContains(t, err, tc.want)
			require.Empty(t, sys.calls, "nothing runs after a refusal")
		})
	}
	_, err := Drop(newFake(1000), "basalt", dirs)
	require.ErrorIs(t, err, ErrNotPermitted)
}

// A failing step stops the drop there: the ids are never set after a
// failed setgroups or setgid, and nothing claims success after verify fails.
func TestDropStopsAtTheFirstFailure(t *testing.T) {
	cases := []struct {
		fail, want string
		last       string
	}{
		{"checkBinary", "checkBinary failed", "checkBinary"},
		{"mkdir", "make /run/basalt for basalt: mkdir failed", "mkdir /run/basalt 0755 basalt"},
		{"setgroups", "set the supplementary groups of basalt", "setgroups [990 4]"},
		{"setgid", "set group id 990", "setgid 990"},
		{"setuid", "set user id 990", "setuid 990"},
		{"noNewPrivs", "set no_new_privs", "noNewPrivs"},
		{"verify", "the engine did not stay basalt", "verify basalt"},
	}
	for _, tc := range cases {
		t.Run(tc.fail, func(t *testing.T) {
			sys := newFake(0)
			sys.fail = tc.fail
			_, err := Drop(sys, "basalt", dirs)
			require.ErrorContains(t, err, tc.want)
			require.Equal(t, tc.last, sys.calls[len(sys.calls)-1])
		})
	}
}

func TestSameGroups(t *testing.T) {
	require.True(t, sameGroups([]uint32{4, 990}, []uint32{990, 4, 990}))
	require.True(t, sameGroups(nil, []uint32{}))
	require.False(t, sameGroups([]uint32{990}, []uint32{990, 4}))
	require.False(t, sameGroups([]uint32{990, 0}, []uint32{990}))
}

const droppedStatus = `Name:	basalt
Umask:	0077
State:	S (sleeping)
Uid:	990	990	990	990
Gid:	990	990	990	990
Groups:	4 990
NoNewPrivs:	1
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	000001ffffffffff
CapAmb:	0000000000000000
`

func TestThreadStatusCheck(t *testing.T) {
	st, err := parseStatus(droppedStatus)
	require.NoError(t, err)
	require.NoError(t, st.check(basalt))

	cases := []struct {
		name, from, to, want string
	}{
		{"saved uid root", "Uid:\t990\t990\t990\t990", "Uid:\t990\t990\t0\t990", "uids [990 990 0 990], want all 990"},
		{"fs gid root", "Gid:\t990\t990\t990\t990", "Gid:\t990\t990\t990\t0", "gids [990 990 990 0], want all 990"},
		{"root group kept", "Groups:\t4 990", "Groups:\t0 4 990", "groups [0 4 990], want [990 4]"},
		{"no groups", "Groups:\t4 990", "Groups:\t", "groups [], want [990 4]"},
		{"nnp unset", "NoNewPrivs:\t1", "NoNewPrivs:\t0", "no_new_privs is not set"},
		{"capability left", "CapEff:\t0000000000000000", "CapEff:\t0000000000000400", "capabilities left"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.Replace(droppedStatus, tc.from, tc.to, 1)
			require.NotEqual(t, droppedStatus, text)
			st, err := parseStatus(text)
			require.NoError(t, err)
			require.ErrorContains(t, st.check(basalt), tc.want)
		})
	}
}

func TestParseStatusWantsEveryField(t *testing.T) {
	for _, key := range []string{"Uid", "Gid", "Groups", "NoNewPrivs", "CapPrm", "CapEff", "CapAmb"} {
		t.Run(key, func(t *testing.T) {
			var kept []string
			for line := range strings.SplitSeq(droppedStatus, "\n") {
				if !strings.HasPrefix(line, key+":") {
					kept = append(kept, line)
				}
			}
			_, err := parseStatus(strings.Join(kept, "\n"))
			require.ErrorContains(t, err, "no "+key+" line")
		})
	}
	_, err := parseStatus(strings.Replace(droppedStatus, "Uid:\t990\t990\t990\t990", "Uid:\t990\t990", 1))
	require.ErrorContains(t, err, "Uid: want 4 ids")
}

func TestOSLookupCurrentUser(t *testing.T) {
	name := os.Getenv("USER")
	if name == "" {
		t.Skip("USER is not set")
	}
	a, err := OS{}.Lookup(name)
	if err != nil {
		t.Skipf("cannot look up %s: %v", name, err)
	}
	require.Equal(t, uint32(os.Getuid()), a.UID)
	require.Contains(t, a.Groups, a.GID)
}
