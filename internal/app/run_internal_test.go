package app

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/setupcode"
)

// The engine's pool, basalt status and the setup finisher must fit under
// the role's CONNECTION LIMIT with room for a stale session, or a raised
// pool size would fail at random under load.
func TestAgentPoolFitsTheRoleConnectionLimit(t *testing.T) {
	t.Parallel()
	const statusAndFinisher = 2
	require.Less(t, agentPoolConns+statusAndFinisher, setupcode.AgentConnectionLimit)
}

func TestListenPagesRefusesATakenPort(t *testing.T) {
	t.Parallel()
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = taken.Close() })
	addr := taken.Addr().String()
	_, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	_, err = listenPages(config.Pages{Addr: addr, Origin: "http://localhost:" + port}, nil, nil, slog.New(slog.DiscardHandler))
	require.Error(t, err)
	require.Contains(t, err.Error(), "another process holds "+addr)
	require.Contains(t, err.Error(), "lsof -nP -iTCP:"+port+" -sTCP:LISTEN")
	require.Contains(t, err.Error(), "make serve-web")
}

// TestInstructionsCarryTheLinkSentence checks the MCP initialize instructions
// hold the contract's sentence about showing links, unchanged (CONTRACT.md,
// What the agent is told).
func TestInstructionsCarryTheLinkSentence(t *testing.T) {
	t.Parallel()
	require.Contains(t, Instructions, "When you show the person a link from Basalt, put it on its own line exactly as Basalt gave it, "+
		"or as a Markdown link [label](url) with the label from links. Never put a link in a code block or inline code, "+
		"never split, wrap, shorten, encode or rewrite it, and put nothing after it on its line. "+
		"Show personMessage verbatim and keep its line breaks.")
}

// TestInstructionsPointToTheDocs checks the instructions send the agent to the
// docs site (CONTRACT.md, What the agent is told).
func TestInstructionsPointToTheDocs(t *testing.T) {
	t.Parallel()
	require.Contains(t, Instructions, "https://docs.basaltvault.app/llms.txt")
	require.Contains(t, Instructions, "For error codes and troubleshooting, read https://docs.basaltvault.app/llms.txt (each page is also Markdown at its path with .md in place of the trailing slash, e.g. https://docs.basaltvault.app/reference/errors.md).")
}

// TestInstructionsTeachNextSteps checks the instructions tell the agent to
// call status and to follow nextSteps (actionable-errors design, section 5).
func TestInstructionsTeachNextSteps(t *testing.T) {
	t.Parallel()
	for _, want := range []string{
		"Call status at the start of a session",
		"carries nextSteps: do them in order",
		"STOP means do not retry or work around it",
		"When status says operatedBy PERSON, never start, stop, restart or upgrade anything yourself.",
		"Never split a write to avoid a hold",
		"You can never approve a write or sign a revert.",
	} {
		require.Contains(t, Instructions, want)
	}
}

// TestInstructionsTeachRevertScope checks the instructions tell the agent
// what the revert scope rules mean for what it says and does (owner
// decisions RS-1 to RS-7): it proposes only its own work, the person may
// widen it (and the agent then sees totals only), reject it with a note,
// and a reissue after a widen resets the person's scope.
func TestInstructionsTeachRevertScope(t *testing.T) {
	t.Parallel()
	for _, want := range []string{
		"A revert covers only your own work",
		"they can include other agents' changes on the signing page",
		"you see only status and totals (widened: true) and get no link",
		"the wait returns REJECTED with their note: stop",
		"reissueLink on a widened revert resets it to your own work",
	} {
		require.Contains(t, Instructions, want)
	}
}

func TestListenPagesServesAFreePort(t *testing.T) {
	t.Parallel()
	site, err := listenPages(config.Pages{Addr: "127.0.0.1:0", Origin: "http://localhost:8787"}, nil, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.NoError(t, site.ln.Close())
}

// TestInstructionsKeepTheAdminCredentialAway checks the instructions carry
// the contract's sentence that the agent never asks for or accepts the admin
// credential (CONTRACT.md, What the agent is told).
func TestInstructionsKeepTheAdminCredentialAway(t *testing.T) {
	t.Parallel()
	require.Contains(t, Instructions, "Never ask the person for, or accept, their database admin connection string or password: "+
		"to set up, repair or change your access, follow nextSteps or run basalt init (basalt init --remote on a computer the person cannot reach); to remove BasaltDB from the person's own computer, run basalt init --remove; show the person the one link it prints; "+
		"they finish on that page. Never remove BasaltDB by hand (its service, files or system user): the page does it, and afterwards status answers REMOVED and says to drop your MCP entry. If the person pastes an admin password, tell them to change it now.")
	// The one basalt command the instructions name is basalt init (CONTRACT.md,
	// Next steps).
	for _, m := range regexp.MustCompile(`basalt [a-z][a-z-]*`).FindAllString(Instructions, -1) {
		require.Equal(t, "basalt init", m, "the MCP instructions name only basalt init")
	}
}

// Pages served on a handed listener keep the listener's hardening: a
// foreign Host is refused, a loopback one served.
func TestListenPagesOnAHandedListenerRefusesAForeignHost(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	site, err := listenPages(config.Pages{Addr: addr, Origin: "http://localhost:8787"}, ln, nil, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.Same(t, ln, site.ln, "served on the handed listener, not a new one")
	t.Cleanup(func() { _ = site.ln.Close() })

	get := func(host string) int {
		req := httptest.NewRequest(http.MethodGet, "http://"+addr+"/healthz", nil)
		req.Host = host
		w := httptest.NewRecorder()
		site.handler.ServeHTTP(w, req)
		return w.Code
	}
	require.Equal(t, http.StatusOK, get(addr))
	require.Equal(t, http.StatusOK, get("localhost:8787"))
	require.NotEqual(t, http.StatusOK, get("evil.example"), "a foreign Host is refused")
}
