package engine_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os/user"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/engine"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/guard/guardtest"
	"github.com/basaltdbhq/basaltdb/internal/localsetup"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

// agentUsers has the agent's OS user alice (uid 4242) and an engine (uid
// 4000) whose group alice is not in.
type agentUsers struct{}

func (agentUsers) Lookup(name string) (*user.User, error) {
	if name != "alice" {
		return nil, user.UnknownUserError(name)
	}
	return &user.User{Username: "alice", Uid: "4242", Gid: "4242"}, nil
}

func (agentUsers) LookupID(uid string) (*user.User, error) {
	return &user.User{Uid: uid, Gid: "4000"}, nil
}
func (agentUsers) GroupIDs(*user.User) ([]string, error) { return nil, nil }
func (agentUsers) Self() int                             { return 4000 }

func postJSON(t *testing.T, base, origin, path string, body any) (int, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	var out bytes.Buffer
	_, err = out.ReadFrom(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, out.Bytes()
}

// The whole first install through the routes: check, the passkey, run.
// The engine writes its own files, the run's answer arrives in full, and
// the waiting ends with the listener handed on.
func TestFirstInstallThroughTheSetupRoutes(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t)
	if u, err := url.Parse(d.URL); err != nil || u.User == nil {
		t.Skip("the test server's admin string has no password")
	} else if _, ok := u.User.Password(); !ok {
		t.Skip("the test server's admin string has no password")
	}
	addr := freeAddr(t)
	origin := pageOrigin(addr)
	configPath := filepath.Join(t.TempDir(), "engine.json")
	type waited struct {
		ln  net.Listener
		err error
	}
	done := make(chan waited, 1)
	go func() {
		o := waitOptions(addr, configPath)
		o.Users, o.Prefix = agentUsers{}, d.Names.Prefix
		ln, err := engine.WaitForConfig(context.Background(), o)
		done <- waited{ln, err}
	}()
	waitUp(t, addr)
	base := "http://" + addr

	job := localsetup.Request{Job: localsetup.JobInstall, Agent: "demo_bot", OSUser: "alice", Demo: true, DatabaseURL: d.URL}
	code, raw := postJSON(t, base, origin, "/api/v1/setup/check", job)
	require.Equal(t, http.StatusOK, code, string(raw))
	var checked localsetup.CheckAnswer
	require.NoError(t, json.Unmarshal(raw, &checked))
	require.True(t, checked.PasskeyNeeded)

	rp, err := passkey.Local(origin)
	require.NoError(t, err)
	auth, err := passkeytest.New(rp)
	require.NoError(t, err)
	c := checked.Challenge
	rr, err := passkey.RegistrationRequestFor(c.Challenge, c.UserID, c.UserName, c.DisplayName)
	require.NoError(t, err)
	reg, err := auth.Register(rr, nil)
	require.NoError(t, err)
	run := job
	run.Challenge, run.Passkey = &c, &localsetup.Passkey{RegistrationResponse: reg, Label: "laptop"}
	code, raw = postJSON(t, base, origin, "/api/v1/setup/run", run)
	require.Equal(t, http.StatusOK, code, string(raw))
	var ran localsetup.RunAnswer
	require.NoError(t, json.Unmarshal(raw, &ran))
	require.Equal(t, "demo_bot", ran.Agent)
	require.Len(t, ran.Passkeys, 1)

	var w waited
	select {
	case w = <-done:
		require.NoError(t, w.err)
	case <-time.After(10 * time.Second):
		t.Fatal("the engine did not see the config the setup wrote")
	}
	require.NoError(t, w.ln.Close())
	cfg, err := config.Load(configPath)
	require.NoError(t, err)
	require.Len(t, cfg.Agents, 1)
	require.Equal(t, "demo_bot", cfg.Agents[0].Name)
}
