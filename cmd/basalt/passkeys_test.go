package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

// twoPasskeys runs init with the laptop passkey (registered through the
// page, so with its user handle) and adds a phone passkey as the admin.
func twoPasskeys(t *testing.T, d *guardtest.DB) (credFile string, laptop, phone *passkeytest.Authenticator) {
	t.Helper()
	var err error
	laptop, err = passkeytest.New(passkey.Production)
	require.NoError(t, err)
	phone, err = passkeytest.New(passkey.Production)
	require.NoError(t, err)
	credFile = initWithPasskey(t, d, laptop)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, phone.Credential(), "phone"))
	return credFile, laptop, phone
}

func id(p *passkeytest.Authenticator) string { return passkey.Bytes(p.ID).String() }

// linkRequest decodes the request of a passkeys page link on the hosted
// console (the test passkeys' origin).
func linkRequest(t *testing.T, link, page string, v any) {
	t.Helper()
	frag, ok := strings.CutPrefix(strings.TrimSpace(link), "https://console.basaltvault.app/passkeys/"+page+"#")
	require.True(t, ok, link)
	require.NoError(t, passkey.DecodeCode(passkey.ManageRequestPrefix, frag, v))
}

func TestPasskeyList(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	credFile, laptop, phone := twoPasskeys(t, d)

	r := cli(t, nil, "", "passkey", "list", "--credential-file", credFile)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stdout, id(laptop)+"  "+dbName(t, d))
	require.Contains(t, r.stdout, id(phone)+"  phone")
	require.Contains(t, r.stdout, "last used never")

	r = cli(t, nil, "", "passkey", "list", "--credential-file", credFile, "--json")
	require.Equal(t, exitOK, r.code, r.stderr)
	var out []map[string]any
	require.NoError(t, json.Unmarshal([]byte(r.stdout), &out))
	require.Len(t, out, 2)
	for _, k := range out {
		require.ElementsMatch(t, []string{"credentialId", "label", "rpId", "origin", "createdAt", "lastUsedAt"}, keysOf(k), "no key material")
		require.Nil(t, k["lastUsedAt"])
	}

	require.Equal(t, exitUsage, cli(t, nil, "", "passkey").code)
	require.Equal(t, exitUsage, cli(t, nil, "", "passkey", "rename").code)
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestPasskeyRemove(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	credFile, laptop, phone := twoPasskeys(t, d)
	admin := map[string]string{envAdminURL: d.URL}

	// A prefix too short, and a declined confirmation, remove nothing. The
	// "--" keeps a prefix that starts with "-" (base64url has one) from
	// being read as a flag.
	r := cli(t, admin, "", "passkey", "remove", "--", id(laptop)[:4])
	require.Equal(t, exitError, r.code)
	r = cli(t, admin, "n\n", "passkey", "remove", id(laptop)[:10])
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "nothing was removed")

	r = cli(t, admin, "y\n", "passkey", "remove", id(laptop)[:10])
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "revoked; it can no longer approve or revert. 1 active passkeys remain")
	require.Contains(t, r.stderr, "Open this link on each device")
	var forget passkey.ForgetRequest
	linkRequest(t, r.stdout, "forget", &forget)
	require.Equal(t, passkey.ModeForget, forget.Mode)
	require.Equal(t, laptop.ID, []byte(forget.Removed[0].CredentialID))
	require.Len(t, forget.Removed[0].UserHandle, 16, "init stored the registration's user handle")
	require.Equal(t, []passkey.Bytes{phone.ID}, forget.Accepted)

	r = cli(t, nil, "", "passkey", "list", "--credential-file", credFile)
	require.NotContains(t, r.stdout, id(laptop))

	// The last passkey: --force and its label, even with --yes.
	r = cli(t, admin, "", "passkey", "remove", "--yes", id(phone))
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "last active passkey")
	r = cli(t, admin, "laptop\n", "passkey", "remove", "--force", "--yes", id(phone))
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "the label did not match")
	r = cli(t, admin, "phone\n", "passkey", "remove", "--force", "--pages-url", links.DefaultLocal, id(phone))
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Empty(t, r.stdout, "no forget link on another origin than the passkey's")
	require.Contains(t, r.stderr, "the passkey belongs to "+links.HostedConsole)
	require.Contains(t, r.stderr, "0 active passkeys remain")
	require.Contains(t, r.stderr, "basalt init --add-passkey")

	r = cli(t, nil, "", "log", "--credential-file", credFile)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "warning: no active passkey")
}

// A credential id can start with "-"; remove must read it as the id, not a
// flag, wherever it stands among the flags.
func TestPasskeyRemoveIDStartingWithDash(t *testing.T) {
	t.Parallel()
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.Bool("yes", false, "")
	fs.SetOutput(io.Discard)
	fs.String("pages-url", "", "")
	for _, args := range [][]string{
		{"-abcdefghijk"},
		{"--yes", "-abcdefghijk"},
		{"-abcdefghijk", "--yes"},
		{"--", "-abcdefghijk"},
		{"--yes", "--", "-abcdefghijk"},
		{"--pages-url", "https://p.example", "-abcdefghijk"},
		{"--pages-url", "https://p.example", "--", "-abcdefghijk"},
		{"-pages-url", "https://p.example", "-abcdefghijk"},
		{"--pages-url=https://p.example", "-abcdefghijk"},
	} {
		require.NoError(t, fs.Parse(idAfterFlags(fs, args)), args)
		require.Equal(t, []string{"-abcdefghijk"}, fs.Args(), args)
	}
	// A flag value that starts with "-" and looks like an id stays the value.
	pagesURL := fs.Lookup("pages-url")
	for _, args := range [][]string{
		{"--pages-url", "-zyxwvutsrqp", "-abcdefghijk"},
		{"--pages-url", "-zyxwvutsrqp", "--", "-abcdefghijk"},
	} {
		require.NoError(t, fs.Parse(idAfterFlags(fs, args)), args)
		require.Equal(t, []string{"-abcdefghijk"}, fs.Args(), args)
		require.Equal(t, "-zyxwvutsrqp", pagesURL.Value.String(), args)
	}
	// The boundary: minIDPrefix characters, the dash included, is an id.
	require.True(t, looksLikeID(fs, "-"+strings.Repeat("a", minIDPrefix-1)))
	require.False(t, looksLikeID(fs, "-"+strings.Repeat("a", minIDPrefix-2)))
	// A real flag and a too-short or malformed token stay flags.
	require.False(t, looksLikeID(fs, "-yes"))
	require.False(t, looksLikeID(fs, "-abc"))
	require.False(t, looksLikeID(fs, "-abc=defghijk"))
	require.False(t, looksLikeID(fs, "--abcdefghijk"))
}

// dashPasskey is a passkey whose credential id text starts with "-".
func dashPasskey(t *testing.T) *passkeytest.Authenticator {
	t.Helper()
	const attempts = 2000 // one id in 64 qualifies; failing all is impossible in practice
	for range attempts {
		a, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		if strings.HasPrefix(id(a), "-") {
			return a
		}
	}
	t.Fatal("no passkey id starting with a dash")
	return nil
}

func TestPasskeyRemoveDashID(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	laptop, tablet := dashPasskey(t), dashPasskey(t)
	phone, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	initWithPasskey(t, d, laptop)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, tablet.Credential(), "tablet"))
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, phone.Credential(), "phone"))
	admin := map[string]string{envAdminURL: d.URL}

	// The documented "--" form, with a flag value before it and a dash-led
	// id longer than the shortest prefix.
	r := cli(t, admin, "", "passkey", "remove", "--yes", "--pages-url", links.DefaultLocal, "--", id(tablet)[:12])
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "revoked; it can no longer approve or revert. 2 active passkeys remain")

	// The shortest accepted prefix (dash included), as typed, with a flag after it.
	r = cli(t, admin, "", "passkey", "remove", id(laptop)[:minIDPrefix], "--yes", "--pages-url", links.DefaultLocal)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "revoked; it can no longer approve or revert. 1 active passkeys remain")
}

func TestPasskeyCheck(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	credFile, laptop, phone := twoPasskeys(t, d)

	// The page found the laptop's passkey only. fixedRand makes the
	// challenge the CLI draws.
	challenge := fixedRand()
	req, err := passkey.NewCheckRequest(challenge, []passkey.Labeled{{CredentialID: laptop.ID, Label: "x"}})
	require.NoError(t, err)
	as, err := laptop.Sign(passkey.CheckChallenge(req.Challenge), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	code, err := passkey.CheckResponse{
		Challenge: req.Challenge,
		Found: []passkey.CheckedAssertion{{
			CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature,
		}},
		Missing: []passkey.Bytes{phone.ID},
	}.Code()
	require.NoError(t, err)

	// The default pages base (the engine's local pages) holds none of
	// them: the CLI names the --pages-url that checks them.
	r := cliRand(t, nil, "", "passkey", "check", "--credential-file", credFile)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "check it with --pages-url "+links.HostedConsole)

	// Decline the removal: nothing changes.
	r = cliRand(t, nil, code+"\nn\n", "passkey", "check", "--credential-file", credFile, "--pages-url", links.HostedConsole)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "https://console.basaltvault.app/passkeys/check#1.")
	require.Contains(t, r.stdout, id(laptop)+"  "+dbName(t, d))
	require.Contains(t, r.stdout, "found on this device")
	require.Contains(t, r.stdout, id(phone)+"  phone                not found on this device")
	keys, err := guard.ActivePasskeys(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Len(t, keys, 2)

	// Accept it: the phone's passkey is revoked with the admin connection.
	r = cliRand(t, map[string]string{envAdminURL: d.URL}, code+"\ny\n", "passkey", "check", "--credential-file", credFile, "--pages-url", links.HostedConsole)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, `passkey "phone" revoked`)
	keys, err = guard.ActivePasskeys(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Equal(t, laptop.ID, keys[0].ID)

	// A code that does not verify is refused.
	tampered, err := passkey.CheckResponse{Challenge: req.Challenge, Found: []passkey.CheckedAssertion{{
		CredentialID: as.CredentialID, AuthenticatorData: as.AuthenticatorData, ClientDataJSON: as.ClientDataJSON, Signature: as.Signature[:len(as.Signature)-1],
	}}}.Code()
	require.NoError(t, err)
	r = cliRand(t, nil, tampered+"\n", "passkey", "check", "--credential-file", credFile, "--pages-url", links.HostedConsole)
	require.Equal(t, exitError, r.code)
	require.Contains(t, r.stderr, "does not verify")
}

func TestLogWarnsAboutAnUnusedPasskey(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	credFile, laptop, _ := twoPasskeys(t, d)
	d.Exec(t, `UPDATE basalt_meta.passkeys SET created_at = now() - interval '91 days' WHERE credential_id = $1`, laptop.ID)

	r := cli(t, nil, "", "log", "--credential-file", credFile)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "warning: passkey \""+dbName(t, d)+"\" ("+id(laptop)+") has not signed anything for 90 days or more")
	require.NotContains(t, r.stderr, "\"phone\"")
}
