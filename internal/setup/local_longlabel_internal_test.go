package setup

import (
	"crypto/rand"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
)

// A long agent or database name still makes a passkey on the first try:
// the page's names are cut to fit, and the run accepts the passkey made
// with them.
func TestLongNamesMakeAPasskeyThatVerifies(t *testing.T) {
	t.Parallel()
	const origin = "http://localhost:8787"
	rp, err := passkey.Local(origin)
	require.NoError(t, err)
	key := make([]byte, keyLen)
	_, err = rand.Read(key)
	require.NoError(t, err)
	s := &LocalService{key: key, rp: rp, opts: LocalOptions{Now: time.Now}}

	for _, tc := range []struct{ agent, database string }{
		{"x_" + strings.Repeat("a", 53), "app"},
		{"bot", strings.Repeat("d", 63)},
		{"demo_bot", "app"},
	} {
		req := Request{Job: JobInstall, Agent: tc.agent, OSUser: "alice"}
		b := bound{database: tc.database, host: "db.example"}
		c, err := s.challenge(req, b)
		require.NoError(t, err)
		for _, name := range []struct{ got, full string }{
			{c.UserName, "BasaltDB · " + tc.agent},
			{c.DisplayName, "BasaltDB · " + tc.database},
		} {
			require.True(t, utf8.ValidString(name.got))
			require.LessOrEqual(t, len(name.got), passkey.MaxLabelLen)
			if len(name.full) <= passkey.MaxLabelLen {
				require.Equal(t, name.full, name.got, "a name that fits is unchanged")
			} else {
				require.True(t, strings.HasSuffix(name.got, "…"), name.got)
				require.True(t, strings.HasPrefix(name.full, strings.TrimSuffix(name.got, "…")), name.got)
			}
		}

		auth, err := passkeytest.New(rp)
		require.NoError(t, err)
		rr, err := passkey.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
		require.NoError(t, err, "the browser's request")
		resp, err := auth.Register(rr, nil)
		require.NoError(t, err)
		req.Challenge = &c
		req.Passkey = &Passkey{RegistrationResponse: resp, Label: "laptop"}
		_, err = s.verifyPasskey(req)
		require.NoError(t, err, "agent %q database %q", tc.agent, tc.database)
		require.NoError(t, s.checkBinding(req, b))
	}
}
