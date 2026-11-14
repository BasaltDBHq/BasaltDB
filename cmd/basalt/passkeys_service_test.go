//go:build linux || darwin

package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

// passkeyLedger is an agent whose engine answers LIST_PASSKEYS with keys.
type passkeyLedger struct {
	emptyLedger
	keys []ledger.Passkey
}

func (l passkeyLedger) ListPasskeys(context.Context) ([]ledger.Passkey, error) { return l.keys, nil }

// In service mode the person cannot read engine.json: basalt passkey list
// and check ask the engine over the person socket, as log, approve and
// revert do.
func TestServiceModePasskeyListAndCheckUseThePersonSocket(t *testing.T) {
	t.Parallel()
	a, err := passkeytest.New(passkey.Relying{RPID: "portal.basaltvault.app", Origin: links.Portal})
	require.NoError(t, err)
	key := ledger.Passkey{Credential: a.Credential(), Label: "laptop", CreatedAt: time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)}
	socket := personSocketFor(t, personUIDForTest, passkeyLedger{keys: []ledger.Passkey{key}})
	idText := passkey.Bytes(key.Credential.ID).String()

	r := serviceRun(t, socket, runPasskey, "list", "--agent", "bot")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, idText+"  laptop")
	require.NotContains(t, r.stderr, "engine.json")

	// check lists the passkeys over the socket and prints the check link;
	// no code is pasted here.
	r = serviceRun(t, socket, runPasskey, "check", "--agent", "bot", "--pages-url", links.Portal)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, links.Portal+"/passkeys/check#1.")
	require.Contains(t, r.stderr, "no check code given")
	require.NotContains(t, r.stderr, "engine.json")
}
