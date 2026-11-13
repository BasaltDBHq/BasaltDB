package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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
	frag, ok := strings.CutPrefix(strings.TrimSpace(link), "https://portal.basaltvault.app/passkeys/"+page+"#")
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
	require.Contains(t, r.stderr, "the passkey belongs to "+links.Portal)
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
	require.False(t, looksLikeID(fs, "--pages-url"))
	// Ids that start with one, two or three dashes are ids.
	require.True(t, looksLikeID(fs, "-abcdefghijk"))
	require.True(t, looksLikeID(fs, "--abcdefghijk"))
	require.True(t, looksLikeID(fs, "---abcdefghij"))
	for _, args := range [][]string{
		{"--abcdefghijk", "--yes"},
		{"---abcdefghij", "--yes"},
	} {
		require.Equal(t, []string{"--yes", "--", args[0]}, idAfterFlags(fs, args), args)
	}
}

// dashPasskey is a passkey whose credential id text starts with prefix: a
// random id with its first characters replaced, so the test does not depend
// on what the random id happens to start with.
func dashPasskey(t *testing.T, prefix string) *passkeytest.Authenticator {
	t.Helper()
	a, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	text := prefix + id(a)[len(prefix):]
	a.ID, err = base64.RawURLEncoding.DecodeString(text)
	require.NoError(t, err)
	require.Equal(t, text, id(a))
	return a
}

func TestPasskeyRemoveDashID(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	one, two, three := dashPasskey(t, "-a"), dashPasskey(t, "--b"), dashPasskey(t, "---c")
	phone, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	initWithPasskey(t, d, one)
	for _, p := range []struct {
		key   *passkeytest.Authenticator
		label string
	}{{two, "two"}, {three, "three"}, {phone, "phone"}} {
		require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, p.key.Credential(), p.label))
	}
	admin := map[string]string{envAdminURL: d.URL}

	// The documented "--" form, with a flag value before it and a dash-led
	// id longer than the shortest prefix: an id starting with "---".
	r := cli(t, admin, "", "passkey", "remove", "--yes", "--pages-url", links.DefaultLocal, "--", id(three)[:12])
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "revoked; it can no longer approve or revert. 3 active passkeys remain")

	// The shortest accepted prefix (dashes included), as typed, with a flag
	// after it: an id starting with "--", then one starting with "-".
	r = cli(t, admin, "", "passkey", "remove", id(two)[:minIDPrefix], "--yes", "--pages-url", links.DefaultLocal)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "revoked; it can no longer approve or revert. 2 active passkeys remain")

	r = cli(t, admin, "", "passkey", "remove", "--pages-url", links.DefaultLocal, id(one)[:minIDPrefix], "--yes")
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "revoked; it can no longer approve or revert. 1 active passkeys remain")
}

// TestPasskeyRemoveTripleDashID removes an id starting with "---" typed
// without the "--" separator.
func TestPasskeyRemoveTripleDashID(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	three := dashPasskey(t, "---c")
	phone, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	initWithPasskey(t, d, three)
	require.NoError(t, guard.RegisterPasskey(context.Background(), d.Admin, phone.Credential(), "phone"))

	r := cli(t, map[string]string{envAdminURL: d.URL}, "", "passkey", "remove", id(three)[:minIDPrefix], "--yes", "--pages-url", links.DefaultLocal)
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
	require.Contains(t, r.stderr, "check it with --pages-url "+links.Portal)

	// Decline the removal: nothing changes.
	r = cliRand(t, nil, code+"\nn\n", "passkey", "check", "--credential-file", credFile, "--pages-url", links.Portal)
	require.Equal(t, exitOK, r.code, r.stderr)
	require.Contains(t, r.stderr, "https://portal.basaltvault.app/passkeys/check#1.")
	require.Contains(t, r.stdout, id(laptop)+"  "+dbName(t, d))
	require.Contains(t, r.stdout, "found on this device")
	require.Contains(t, r.stdout, id(phone)+"  phone                not found on this device")
	keys, err := guard.ActivePasskeys(context.Background(), d.Admin)
	require.NoError(t, err)
	require.Len(t, keys, 2)

	// Accept it: the phone's passkey is revoked with the admin connection.
	r = cliRand(t, map[string]string{envAdminURL: d.URL}, code+"\ny\n", "passkey", "check", "--credential-file", credFile, "--pages-url", links.Portal)
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
	r = cliRand(t, nil, tampered+"\n", "passkey", "check", "--credential-file", credFile, "--pages-url", links.Portal)
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
	require.Regexp(t, regexp.QuoteMeta("warning: passkey \""+dbName(t, d)+" · bot · ")+`\d{4}-\d{2}-\d{2}`+regexp.QuoteMeta("\" ("+id(laptop)+") has not signed anything for 90 days or more"), r.stderr)
	require.NotContains(t, r.stderr, "\"phone\"")
}

// A new passkey's default label tells it apart from the person's other
// passkeys on the same site: database, agent and date, within 64 bytes.
func TestDefaultPasskeyLabel(t *testing.T) {
	t.Parallel()
	day := time.Date(2026, 11, 13, 23, 30, 0, 0, time.Local)
	require.Equal(t, "postgres · demo_bot · 2026-11-13", defaultPasskeyLabel("postgres", "demo_bot", day))
	require.Equal(t, "app · 2026-11-13", defaultPasskeyLabel("app", "", day))
	long := defaultPasskeyLabel(strings.Repeat("d", 63), "demo_bot", day)
	require.LessOrEqual(t, len(long), maxPasskeyLabel)
	require.True(t, strings.HasSuffix(long, "… · demo_bot · 2026-11-13"), long)
	accents := defaultPasskeyLabel(strings.Repeat("é", 40), strings.Repeat("a", 54), day)
	require.LessOrEqual(t, len(accents), maxPasskeyLabel)
	require.True(t, utf8.ValidString(accents), accents)
	require.True(t, strings.HasSuffix(accents, " · 2026-11-13"), accents)
}
