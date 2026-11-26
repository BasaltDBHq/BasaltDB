//go:build unix

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/lib/ownerfile"
)

// ReadCredential accepts a file this process's effective user or root owns.
// A process that is not root cannot make another user's file it can still
// read with mode 0600, so the owners are checked on the rules (ownerfile's
// tests prove the rule itself) and the refusal's words on the error.
func TestCredentialOwnersAreThisUserOrRoot(t *testing.T) {
	require.ElementsMatch(t, []int{os.Geteuid(), 0}, credentialRules().Owners)

	const path = "/home/bot/.config/basalt/agents/bot.url"
	err := credentialFileErr(path, &ownerfile.RefusedError{Rule: ownerfile.Owner, UID: 4242})
	require.EqualError(t, err, "credential file "+path+" is owned by uid 4242, not this process's user or root")
}
