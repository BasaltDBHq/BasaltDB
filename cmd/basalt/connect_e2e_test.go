package main

// These tests drive a setup the way the connect page does (CONTRACT.md,
// Connect): basalt init --remote makes a code and a connect link, the page's
// three JSON calls go to a test server built on the public setup package
// (internal/testkit/connecttest) with a real Postgres behind it, and an engine in
// this process picks the recorded setup up.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	connectv1 "github.com/basaltdbhq/basaltdb/api/connect/proto/basalt/connect/v1"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/adapter/outbound/postgres/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
	"github.com/basaltdbhq/basaltdb/internal/testkit/connecttest"
)

var b64url = base64.RawURLEncoding

// page is the connect page's client: a JSON POST per call, as the page sends.
type page struct {
	t    *testing.T
	base string
}

const setupService = "/basalt.connect.v1.SetupService/"

// call posts body (proto3 JSON) to method and returns the HTTP status and
// the response body.
func (p page) call(method string, body any) (int, []byte) {
	p.t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(p.t, err)
	req, err := http.NewRequest(http.MethodPost, p.base+setupService+method, bytes.NewReader(raw))
	require.NoError(p.t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(p.t, err)
	defer resp.Body.Close()
	out, err := io.ReadAll(resp.Body)
	require.NoError(p.t, err)
	return resp.StatusCode, out
}

// ok makes a call that must succeed and reads the proto3 JSON answer.
func (p page) ok(method string, body any, into proto.Message) {
	p.t.Helper()
	status, out := p.call(method, body)
	require.Equal(p.t, http.StatusOK, status, string(out))
	require.NoError(p.t, protojson.Unmarshal(out, into), string(out))
}

// refused makes a call that must fail closed with reason, and checks the
// error body the page reads: the ConnectRPC code, the Refusal detail's
// proto3 JSON form (`debug`), and that the message is the refusal's.
func (p page) refused(method string, body any, wantCode, reason string) {
	p.t.Helper()
	status, out := p.call(method, body)
	require.NotEqual(p.t, http.StatusOK, status, "%s %s: %s", method, reason, out)
	var e struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Details []struct {
			Type  string          `json:"type"`
			Debug json.RawMessage `json:"debug"`
		} `json:"details"`
	}
	require.NoError(p.t, json.Unmarshal(out, &e), string(out))
	require.Equal(p.t, wantCode, e.Code, "%s: %s", method, out)
	require.Len(p.t, e.Details, 1, string(out))
	require.Equal(p.t, "basalt.connect.v1.Refusal", e.Details[0].Type)
	var r connectv1.Refusal
	require.NoError(p.t, protojson.Unmarshal(e.Details[0].Debug, &r), string(out))
	require.Equal(p.t, reason, r.GetReason(), "%s: %s", method, out)
	require.Equal(p.t, r.GetMessage(), e.Message, "the error's message is the refusal's")
	require.NotEmpty(p.t, e.Message)
	require.NotContains(p.t, string(out), "adminsecret")
}

// passkeyOf is what navigator.credentials.create gives the page for the
// challenge, as the RunSetup request carries it.
func passkeyOf(t *testing.T, person *passkeytest.Authenticator, c *connectv1.PasskeyChallenge) map[string]any {
	t.Helper()
	ch, err := b64url.DecodeString(c.GetChallenge())
	require.NoError(t, err)
	uid, err := b64url.DecodeString(c.GetUserId())
	require.NoError(t, err)
	return registerFor(t, person, passkey.RegistrationRequest{Challenge: ch, UserID: uid, UserName: c.GetUserName(), DisplayName: c.GetDisplayName()})
}

func registerFor(t *testing.T, person *passkeytest.Authenticator, req passkey.RegistrationRequest) map[string]any {
	t.Helper()
	resp, err := person.Register(req, nil)
	require.NoError(t, err)
	return map[string]any{
		"credentialId": b64url.EncodeToString(resp.CredentialID), "clientDataJson": b64url.EncodeToString(resp.ClientDataJSON),
		"authenticatorData": b64url.EncodeToString(resp.AuthenticatorData), "publicKey": b64url.EncodeToString(resp.PublicKey),
		"publicKeyAlgorithm": resp.PublicKeyAlgorithm,
	}
}

func challengeJSON(c *connectv1.PasskeyChallenge) map[string]any {
	return map[string]any{
		"challenge": c.GetChallenge(), "userId": c.GetUserId(), "userName": c.GetUserName(),
		"displayName": c.GetDisplayName(), "expiresAt": c.GetExpiresAt(), "mac": c.GetMac(),
	}
}

// connectFixture is one database, a code for it made by basalt init
// --remote on an agent-operated engine, and a running test server.
type connectFixture struct {
	t       *testing.T
	d       *guardtest.DB
	cfg     string
	install remoteRun
	srv     *connecttest.Server
	page    page
	person  *passkeytest.Authenticator
}

func newConnectFixture(t *testing.T) connectFixture {
	t.Helper()
	d, dbURL := remoteDB(t)
	cfg := tempConfig(t)
	install := codeFor(t, d, dbURL, cfg)
	srv, base := connecttest.Start(t)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	return connectFixture{t: t, d: d, cfg: cfg, install: install, srv: srv, page: page{t, base}, person: person}
}

// codeFromLink is what the page reads from the link's fragment.
func codeFromLink(t *testing.T, link string) string {
	t.Helper()
	u, err := url.Parse(link)
	require.NoError(t, err)
	require.Equal(t, "portal.basaltvault.app", u.Host)
	require.Equal(t, "/connect", u.Path)
	return u.Fragment
}

func (f connectFixture) describe(code string) *connectv1.DescribeSetupResponse {
	f.t.Helper()
	var out connectv1.DescribeSetupResponse
	f.page.ok("DescribeSetup", map[string]any{"code": code}, &out)
	return &out
}

func (f connectFixture) runBody(code string, c *connectv1.PasskeyChallenge, pk map[string]any) map[string]any {
	// The fixture's INSTALL code asks for every table in public: the
	// person leaves public.leads ticked.
	body := map[string]any{"code": code, "databaseUrl": f.d.URL, "includedTables": []string{"public.leads"}}
	if c != nil {
		body["challenge"] = challengeJSON(c)
	}
	if pk != nil {
		body["passkey"] = pk
	}
	return body
}

func (f connectFixture) untouched() {
	f.t.Helper()
	require.Zero(f.t, installedVersion(f.t, f.d), "the database is as it was")
}

func TestConnectPageRunsASetupEndToEnd(t *testing.T) {
	t.Parallel()
	f := newConnectFixture(t)
	res := f.install.res

	// init --remote on an agent-operated engine hands the connect link; the
	// page reads the code from its fragment.
	require.NotEmpty(t, res.ConnectURL)
	code := codeFromLink(t, res.ConnectURL)
	require.Equal(t, res.Code, code)

	// 1. DescribeSetup: the summary the page shows, and the challenge.
	desc := f.describe(code)
	sum := desc.GetSummary()
	require.Equal(t, res.SetupID, sum.GetSetupId())
	require.Equal(t, "INSTALL", sum.GetKind())
	require.Equal(t, "bot", sum.GetAgent())
	require.Equal(t, res.Fingerprint, sum.GetFingerprint(), "the page shows the fingerprint the bot shows")
	require.Equal(t, f.install.payload.Prefix, sum.GetPrefix())
	require.Equal(t, []string{"public"}, sum.GetAllTablesSchemas(), "the person ticks the tables")
	require.NotEmpty(t, sum.GetLines())
	ch := desc.GetChallenge()
	require.NotEmpty(t, ch.GetMac())
	f.untouched()

	// 2. CheckSetup: nothing asked of a demo database; a passkey is needed
	// for an INSTALL code. Nothing changes.
	var chk connectv1.CheckSetupResponse
	f.page.ok("CheckSetup", map[string]any{"code": code, "databaseUrl": f.d.URL}, &chk)
	require.True(t, chk.GetPasskeyNeeded())
	require.False(t, chk.GetNothingToDo())
	f.untouched()

	// Without the passkey RunSetup is refused and changes nothing.
	f.page.refused("RunSetup", f.runBody(code, ch, nil), "failed_precondition", "PASSKEY_REQUIRED")
	f.untouched()

	// 3. RunSetup, with the passkey the person made for the challenge.
	var run connectv1.RunSetupResponse
	f.page.ok("RunSetup", f.runBody(code, ch, passkeyOf(t, f.person, ch)), &run)
	require.Len(t, run.GetPasskeys(), 1)
	wantCheck, err := f.person.Credential().CheckCode()
	require.NoError(t, err)
	require.Equal(t, wantCheck, run.GetPasskeys()[0].GetCheckCode(), "the page computes the same code from the key")
	require.Equal(t, b64url.EncodeToString(f.person.ID), run.GetPasskeys()[0].GetCredentialId())
	require.True(t, agentLogsIn(t, f.install.credFile, res.SetupID), "the setup is recorded and the bot's own password logs in")

	// The engine picks it up when the bot asks for status, and serves.
	e := startConnectEngine(t, f.cfg)
	st := e.status(t)
	require.Equal(t, "DONE", st.Setup.State)
	require.Equal(t, res.SetupID, st.Setup.SetupID)
	require.Len(t, st.Passkeys.Keys, 1)
	require.Equal(t, run.GetPasskeys()[0].GetCheckCode(), st.Passkeys.Keys[0].CheckCode,
		"status names the passkey with the check code RunSetup returned")
	require.Contains(t, st.Passkeys.Summary, wantCheck)
	require.Contains(t, e.call(t, "list_runs"), `"result"`)
	require.NotContains(t, e.call(t, "list_runs"), "SETUP_")
	cfg, err := config.Load(f.cfg)
	require.NoError(t, err)
	require.Nil(t, cfg.Agents[0].Setup, "cleared from engine.json")
}

func TestConnectPageRefusesHostileSetupsClosed(t *testing.T) {
	t.Parallel()

	t.Run("expired code", func(t *testing.T) {
		t.Parallel()
		f := newConnectFixture(t)
		code := f.install.res.Code
		desc := f.describe(code)
		f.srv.Advance(25 * time.Hour)
		f.page.refused("DescribeSetup", map[string]any{"code": code}, "invalid_argument", "EXPIRED")
		f.page.refused("CheckSetup", map[string]any{"code": code, "databaseUrl": f.d.URL}, "invalid_argument", "EXPIRED")
		f.page.refused("RunSetup", f.runBody(code, desc.GetChallenge(), passkeyOf(t, f.person, desc.GetChallenge())), "invalid_argument", "EXPIRED")
		f.untouched()
	})

	t.Run("opened live, checked inside the grace", func(t *testing.T) {
		t.Parallel()
		f := newConnectFixture(t)
		code := f.install.res.Code
		f.describe(code)
		f.srv.Advance(setupcode.Lifetime + time.Minute)
		// Opening again needs a live code; the page that opened it goes on.
		f.page.refused("DescribeSetup", map[string]any{"code": code}, "invalid_argument", "EXPIRED")
		var chk connectv1.CheckSetupResponse
		f.page.ok("CheckSetup", map[string]any{"code": code, "databaseUrl": f.d.URL}, &chk)
		f.untouched()
	})

	t.Run("used code", func(t *testing.T) {
		t.Parallel()
		f := newConnectFixture(t)
		code := f.install.res.Code
		desc := f.describe(code)
		var run connectv1.RunSetupResponse
		f.page.ok("RunSetup", f.runBody(code, desc.GetChallenge(), passkeyOf(t, f.person, desc.GetChallenge())), &run)

		again := f.describe(code) // no database: still decodes
		f.page.refused("CheckSetup", map[string]any{"code": code, "databaseUrl": f.d.URL}, "failed_precondition", "USED")
		other, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		f.page.refused("RunSetup", f.runBody(code, again.GetChallenge(), passkeyOf(t, other, again.GetChallenge())), "failed_precondition", "USED")
		keys := installedPasskeys(t, f.d)
		require.Len(t, keys, 1, "the second run registered nothing")
	})

	t.Run("code for another database", func(t *testing.T) {
		t.Parallel()
		f := newConnectFixture(t)
		other := guardtest.New(t).WithDemo(t)
		code := f.install.res.Code
		desc := f.describe(code)
		body := map[string]any{"code": code, "databaseUrl": other.URL}
		f.page.refused("CheckSetup", body, "failed_precondition", "TARGET_MISMATCH")
		body["challenge"], body["passkey"] = challengeJSON(desc.GetChallenge()), passkeyOf(t, f.person, desc.GetChallenge())
		f.page.refused("RunSetup", body, "failed_precondition", "TARGET_MISMATCH")
		require.Zero(t, installedVersion(t, other))
		f.untouched()
	})

	t.Run("code damaged in transit", func(t *testing.T) {
		t.Parallel()
		f := newConnectFixture(t)
		desc := f.describe(f.install.res.Code)
		bad := damaged(f.install.res.Code)
		f.page.refused("DescribeSetup", map[string]any{"code": bad}, "invalid_argument", "DAMAGED")
		f.page.refused("CheckSetup", map[string]any{"code": bad, "databaseUrl": f.d.URL}, "invalid_argument", "DAMAGED")
		f.page.refused("RunSetup", f.runBody(bad, desc.GetChallenge(), passkeyOf(t, f.person, desc.GetChallenge())), "invalid_argument", "DAMAGED")
		f.page.refused("DescribeSetup", map[string]any{"code": "hello"}, "invalid_argument", "NOT_A_SETUP_CODE")
		f.untouched()
	})

	t.Run("code swapped for another that decodes", func(t *testing.T) {
		t.Parallel()
		f := newConnectFixture(t)
		desc := f.describe(f.install.res.Code)

		// Someone re-encodes the code with a named table for the agent to
		// change in place of the ticks: a code that decodes and checks,
		// with another fingerprint.
		p := f.install.payload
		a := *p.Agent
		a.AllTables, a.Write = nil, []string{"public.payroll"}
		p.Agent = &a
		swapped, err := setupcode.Encode(p)
		require.NoError(t, err)
		require.NotEqual(t, f.install.res.Fingerprint, f.describe(swapped).GetSummary().GetFingerprint(), "the page shows a different fingerprint")

		// The passkey the person created for the real code's challenge does
		// not register for the swapped one.
		f.page.refused("RunSetup", f.runBody(swapped, desc.GetChallenge(), passkeyOf(t, f.person, desc.GetChallenge())), "invalid_argument", "CHALLENGE_INVALID")
		f.untouched()
	})

	t.Run("answer to a question Run did not ask", func(t *testing.T) {
		t.Parallel()
		f := newConnectFixture(t)
		code := f.install.res.Code
		desc := f.describe(code)
		var chk connectv1.CheckSetupResponse
		f.page.ok("CheckSetup", map[string]any{"code": code, "databaseUrl": f.d.URL}, &chk)
		require.Empty(t, chk.GetQuestions())
		body := f.runBody(code, desc.GetChallenge(), passkeyOf(t, f.person, desc.GetChallenge()))
		body["answers"] = []map[string]any{{"kind": "ROW_LEVEL_SECURITY", "table": "public.leads", "choice": "ALL_ROWS"}}
		f.page.refused("RunSetup", body, "invalid_argument", "ANSWERS_INVALID")
		f.untouched()
	})

	t.Run("passkey made for another setup's challenge", func(t *testing.T) {
		t.Parallel()
		a, b := newConnectFixture(t), newConnectFixture(t)
		descA := a.describe(a.install.res.Code)
		descB := b.describe(b.install.res.Code)

		// The challenge of setup A, with A's registration, sent to run B.
		b.page.refused("RunSetup", b.runBody(b.install.res.Code, descA.GetChallenge(), passkeyOf(t, b.person, descA.GetChallenge())),
			"invalid_argument", "CHALLENGE_INVALID")
		// B's own challenge, with a registration made for A's challenge.
		b.page.refused("RunSetup", b.runBody(b.install.res.Code, descB.GetChallenge(), passkeyOf(t, b.person, descA.GetChallenge())),
			"invalid_argument", "PASSKEY_INVALID")
		// A challenge the service did not make, signed by the same person.
		forged := proto.Clone(descB.GetChallenge()).(*connectv1.PasskeyChallenge)
		forged.UserId = descA.GetChallenge().GetUserId()
		b.page.refused("RunSetup", b.runBody(b.install.res.Code, forged, passkeyOf(t, b.person, forged)), "invalid_argument", "CHALLENGE_INVALID")
		a.untouched()
		b.untouched()
	})

	t.Run("passkey challenge expired", func(t *testing.T) {
		t.Parallel()
		f := newConnectFixture(t)
		desc := f.describe(f.install.res.Code)
		f.srv.Advance(connecttest.ChallengeLife + time.Minute)
		f.page.refused("RunSetup", f.runBody(f.install.res.Code, desc.GetChallenge(), passkeyOf(t, f.person, desc.GetChallenge())),
			"invalid_argument", "CHALLENGE_EXPIRED")
		f.untouched()
	})

	t.Run("opened live, run past the grace", func(t *testing.T) {
		t.Parallel()
		f := newConnectFixture(t)
		desc := f.describe(f.install.res.Code)
		// Inside the grace only the challenge (15 minutes) has run out;
		// past expiresAt plus the grace the code itself is refused.
		f.srv.Advance(setupcode.Lifetime + connecttest.OpenGrace + time.Minute)
		f.page.refused("RunSetup", f.runBody(f.install.res.Code, desc.GetChallenge(), passkeyOf(t, f.person, desc.GetChallenge())),
			"invalid_argument", "EXPIRED")
		f.untouched()
	})
}

func installedPasskeys(t *testing.T, d *guardtest.DB) []guardmodel.RegisteredPasskey {
	t.Helper()
	keys, err := guard.ActivePasskeys(context.Background(), d.Admin)
	require.NoError(t, err)
	return keys
}

// connectEngine is an engine running in this process on the config
// basalt init --remote wrote, with its socket and state in a short
// temporary directory.
type connectEngine struct {
	socket string
}

func startConnectEngine(t *testing.T, cfgPath string) connectEngine {
	t.Helper()
	dir, err := os.MkdirTemp("", "bcon") // short: macOS bounds socket paths
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	raw, err := os.ReadFile(cfgPath)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(raw, &m))
	me, err := user.Current()
	require.NoError(t, err)
	m["socketDir"], m["stateDir"], m["pagesAddr"], m["mode"] = filepath.Join(dir, "run"), filepath.Join(dir, "state"), "off", "SAME_USER"
	m["agents"].([]any)[0].(map[string]any)["osUser"] = me.Username
	raw, err = json.Marshal(m)
	require.NoError(t, err)
	require.NoError(t, config.WriteFile(cfgPath, raw))

	cfg, err := config.Load(cfgPath)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, cfg, cfgPath, slog.New(slog.DiscardHandler)) }()
	t.Cleanup(func() {
		cancel()
		require.NoError(t, <-done)
	})
	sock := config.SocketPath(cfg.SocketDir, "bot")
	require.Eventually(t, func() bool {
		c, err := net.Dial("unix", sock)
		if err != nil {
			return false
		}
		c.Close()
		return true
	}, 30*time.Second, 20*time.Millisecond)
	return connectEngine{socket: sock}
}

// call is a tools/call on the engine's socket, as the agent's MCP client
// makes it, and the response line.
func (e connectEngine) call(t *testing.T, tool string) string {
	t.Helper()
	conn, err := net.Dial("unix", e.socket)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(30*time.Second)))
	_, err = fmt.Fprintf(conn, "%s\n%s\n",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"`+tool+`","arguments":{}}}`)
	require.NoError(t, err)
	r := bufio.NewReader(conn)
	_, err = r.ReadString('\n')
	require.NoError(t, err)
	line, err := r.ReadString('\n')
	require.NoError(t, err)
	return line
}

type connectStatus struct {
	Setup struct {
		State   string `json:"state"`
		SetupID string `json:"setupId"`
	} `json:"setup"`
	Passkeys struct {
		Summary string `json:"summary"`
		Keys    []struct {
			CheckCode string `json:"checkCode"`
		} `json:"keys"`
	} `json:"passkeys"`
}

func (e connectEngine) status(t *testing.T) connectStatus {
	t.Helper()
	line := e.call(t, "status")
	var resp struct {
		Result struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(line), &resp), line)
	require.Len(t, resp.Result.Content, 1, line)
	var st connectStatus
	require.NoError(t, json.Unmarshal([]byte(resp.Result.Content[0].Text), &st), line)
	return st
}
