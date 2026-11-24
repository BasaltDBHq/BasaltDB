//go:build unix

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// A credential file owned by another user is refused. A process that is not
// root cannot make one it can still read with mode 0600, so the rule is
// tested on the owner and process ids directly.
func TestCredentialOwnerRefusesAnotherUser(t *testing.T) {
	const path = "/home/bot/.config/basalt/agents/bot.url"
	for _, tc := range []struct {
		name      string
		uid, euid int
		refused   bool
	}{
		{name: "own file", uid: 501, euid: 501},
		{name: "root's file", uid: 0, euid: 501},
		{name: "root reads its own", uid: 0, euid: 0},
		{name: "another user's file", uid: 4242, euid: 501, refused: true},
		{name: "root reads another user's", uid: 4242, euid: 0, refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkCredentialOwner(path, tc.uid, tc.euid)
			if !tc.refused {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, "credential file "+path+" is owned by uid 4242, not this process's user or root")
		})
	}
}
