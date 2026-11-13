package telegram_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/notify/telegram"
)

// A made-up token in the Bot API shape; never a real one.
const secret = "123456:AAFakeTokenForTestsOnly_x-y"

func token(t *testing.T) telegram.Token {
	t.Helper()
	tok, err := telegram.ParseToken(secret)
	require.NoError(t, err)
	return tok
}

type captured struct {
	path string
	body map[string]any
}

func server(t *testing.T, status int, reply string) (*httptest.Server, *captured) {
	t.Helper()
	got := &captured{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return srv, got
}

func TestSendMessage(t *testing.T) {
	t.Parallel()
	srv, got := server(t, http.StatusOK, `{"ok":true,"result":{"message_id":1}}`)
	c := telegram.NewClient(srv.Client(), srv.URL, token(t), "42")
	err := c.SendMessage(context.Background(), telegram.Message{Text: "hello", Button: &telegram.Button{Text: "Open", URL: "https://console.basaltvault.app/approvals/0190a3f2-7c1e-7000-8000-000000000001#1.x"}})
	require.NoError(t, err)
	require.Equal(t, "/bot"+secret+"/sendMessage", got.path)
	require.Equal(t, "42", got.body["chat_id"])
	require.Equal(t, "hello", got.body["text"])
	require.Equal(t, map[string]any{"is_disabled": true}, got.body["link_preview_options"])
	require.Equal(t, map[string]any{"inline_keyboard": []any{[]any{map[string]any{"text": "Open", "url": "https://console.basaltvault.app/approvals/0190a3f2-7c1e-7000-8000-000000000001#1.x"}}}}, got.body["reply_markup"])
	require.NotContains(t, got.body, "parse_mode", "plain text: nothing in a notice needs escaping")
}

func TestSendMessageWithoutButton(t *testing.T) {
	t.Parallel()
	srv, got := server(t, http.StatusOK, `{"ok":true}`)
	require.NoError(t, telegram.NewClient(srv.Client(), srv.URL, token(t), "42").SendMessage(context.Background(), telegram.Message{Text: "x"}))
	require.NotContains(t, got.body, "reply_markup")
}

func TestSendMessageErrorsNeverCarryTheToken(t *testing.T) {
	t.Parallel()
	t.Run("API refusal", func(t *testing.T) {
		srv, _ := server(t, http.StatusTooManyRequests, `{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}`)
		err := telegram.NewClient(srv.Client(), srv.URL, token(t), "42").SendMessage(context.Background(), telegram.Message{Text: "x"})
		var apiErr *telegram.APIError
		require.ErrorAs(t, err, &apiErr)
		require.Equal(t, 429, apiErr.Code)
		require.Equal(t, 7*time.Second, apiErr.RetryAfter)
		require.NotContains(t, err.Error(), secret)
	})
	t.Run("unreadable body", func(t *testing.T) {
		srv, _ := server(t, http.StatusBadGateway, `<html>bad gateway</html>`)
		err := telegram.NewClient(srv.Client(), srv.URL, token(t), "42").SendMessage(context.Background(), telegram.Message{Text: "x"})
		require.ErrorContains(t, err, "HTTP 502")
		require.NotContains(t, err.Error(), secret)
	})
	t.Run("transport failure", func(t *testing.T) {
		srv, _ := server(t, http.StatusOK, `{"ok":true}`)
		srv.Close()
		err := telegram.NewClient(srv.Client(), srv.URL, token(t), "42").SendMessage(context.Background(), telegram.Message{Text: "x"})
		require.Error(t, err)
		require.NotContains(t, err.Error(), secret)
		require.NotContains(t, err.Error(), "/bot")
	})
	t.Run("canceled", func(t *testing.T) {
		srv, _ := server(t, http.StatusOK, `{"ok":true}`)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		err := telegram.NewClient(srv.Client(), srv.URL, token(t), "42").SendMessage(ctx, telegram.Message{Text: "x"})
		require.ErrorIs(t, err, context.Canceled)
		require.NotContains(t, err.Error(), secret)
	})
}

func TestTokenNeverPrints(t *testing.T) {
	t.Parallel()
	tok := token(t)
	cfg := struct {
		Token telegram.Token `json:"token"`
	}{tok}
	raw, err := json.Marshal(cfg)
	require.NoError(t, err)
	for _, s := range []string{tok.String(), fmt.Sprint(tok), fmt.Sprintf("%v %+v %#v %s", tok, cfg, cfg, tok), string(raw)} {
		require.NotContains(t, s, secret)
		require.Contains(t, s, "[redacted]")
	}
}

func TestParseToken(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"", "nocolon", ":secret", "123:", "123:has space", "abc:def"} {
		_, err := telegram.ParseToken(bad)
		require.Error(t, err, bad)
		if bad != "" {
			require.NotContains(t, err.Error(), bad)
		}
	}
}

func TestLoadToken(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := filepath.Join(dir, "telegram.token")
	require.NoError(t, os.WriteFile(good, []byte(secret+"\n"), 0o600))
	tok, err := telegram.LoadToken(good)
	require.NoError(t, err)

	// The loaded token is the one sent.
	srv, got := server(t, http.StatusOK, `{"ok":true}`)
	require.NoError(t, telegram.NewClient(srv.Client(), srv.URL, tok, "42").SendMessage(context.Background(), telegram.Message{Text: "x"}))
	require.Equal(t, "/bot"+secret+"/sendMessage", got.path)

	open := filepath.Join(dir, "open.token")
	require.NoError(t, os.WriteFile(open, []byte(secret), 0o600))
	require.NoError(t, os.Chmod(open, 0o644))
	_, err = telegram.LoadToken(open)
	require.ErrorContains(t, err, "readable by the engine's user only")

	malformed := filepath.Join(dir, "bad.token")
	require.NoError(t, os.WriteFile(malformed, []byte("not a token at all"), 0o600))
	_, err = telegram.LoadToken(malformed)
	require.ErrorContains(t, err, "<bot id>:<secret>")
	require.NotContains(t, err.Error(), "not a token at all")

	_, err = telegram.LoadToken(filepath.Join(dir, "missing"))
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestNewClientPanicsOnMissingDeps(t *testing.T) {
	t.Parallel()
	require.Panics(t, func() { telegram.NewClient(nil, telegram.DefaultAPIBase, token(t), "42") })
	require.Panics(t, func() { telegram.NewClient(http.DefaultClient, telegram.DefaultAPIBase, token(t), " ") })
	require.Panics(t, func() { telegram.NewNotifier(nil) })
}

func notice(url string) telegram.Notice {
	return telegram.Notice{
		ApprovalID:  uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a1"),
		Agent:       "basalt_agent_bot",
		Database:    "app",
		Intent:      "Remove the spam leads from yesterday's import",
		Statement:   "DELETE FROM public.leads WHERE source = $1",
		Headline:    "Delete 15 rows in public.leads + 30 cascaded rows (public.lead_notes 28, public.note_tags 2 [values hidden])",
		ExpiresAt:   time.Date(2026, 11, 12, 6, 2, 11, 0, time.FixedZone("WIB", 7*60*60)),
		ApprovalURL: url,
	}
}

func approvalURL(n int) string {
	const prefix = "https://console.basaltvault.app/approvals/0190a3f2-7c1e-7000-8000-000000000001#1."
	return prefix + strings.Repeat("A", n-len(prefix))
}

func TestHeldMessage(t *testing.T) {
	t.Parallel()
	t.Run("short link: a button", func(t *testing.T) {
		m := telegram.HeldMessage(notice(approvalURL(2048)))
		require.Equal(t, &telegram.Button{Text: telegram.ButtonText, URL: approvalURL(2048)}, m.Button)
		require.Contains(t, m.Text, "Agent: basalt_agent_bot on app")
		require.Contains(t, m.Text, "Why: Remove the spam leads from yesterday's import")
		require.True(t, strings.HasPrefix(m.Text, "BasaltDB: approval needed\n\n"+
			"Delete 15 rows in public.leads + 30 cascaded rows (public.lead_notes 28, public.note_tags 2 [values hidden])\n\n"), m.Text)
		require.NotContains(t, m.Text, "Rows:")
		require.Contains(t, m.Text, "Statement: DELETE FROM public.leads WHERE source = $1")
		require.Contains(t, m.Text, "Expires: 2026-11-11 23:02 UTC")
	})
	t.Run("the engine's short link with its secret: in the text", func(t *testing.T) {
		n := notice(approvalURL(2048))
		n.ShortURL = "http://localhost:8787/approvals/0193a4c2-7d1e-7c3a-9f00-0000000000a1#s=c2VjcmV0LXNlY3JldC0xMg"
		m := telegram.HeldMessage(n)
		require.Contains(t, m.Text, "\nOn the engine's computer: "+n.ShortURL)
		require.Equal(t, approvalURL(2048), m.Button.URL, "the button keeps the long link")
	})
	t.Run("longer link: in the text", func(t *testing.T) {
		m := telegram.HeldMessage(notice(approvalURL(3000)))
		require.Nil(t, m.Button)
		require.Contains(t, m.Text, approvalURL(3000))
		require.LessOrEqual(t, len(utf16.Encode([]rune(m.Text))), 4096)
	})
	t.Run("too long for Telegram: open it from the computer", func(t *testing.T) {
		m := telegram.HeldMessage(notice(approvalURL(5000)))
		require.Nil(t, m.Button)
		require.NotContains(t, m.Text, "approve/#")
		require.Contains(t, m.Text, "basalt approve --show 0193a4c2-7d1e-7c3a-9f00-0000000000a1")
	})
	t.Run("long statement and intent are cut", func(t *testing.T) {
		n := notice(approvalURL(100))
		n.Statement = "UPDATE t SET v = '" + strings.Repeat("🚀", 1000) + "'"
		n.Intent = strings.Repeat("x", 1000)
		n.Headline = "Delete 1 row in public.leads + 50 cascaded rows (" + strings.Repeat("public.t 1, ", 400) + ")"
		m := telegram.HeldMessage(n)
		require.Contains(t, m.Text, "Delete 1 row in public.leads + 50 cascaded rows (public.t 1")
		require.Contains(t, m.Text, "…")
		require.LessOrEqual(t, len(utf16.Encode([]rune(m.Text))), 4096)
	})
}

func TestNotifyHeld(t *testing.T) {
	t.Parallel()
	srv, got := server(t, http.StatusOK, `{"ok":true}`)
	n := telegram.NewNotifier(telegram.NewClient(srv.Client(), srv.URL, token(t), "-100123"))
	require.NoError(t, n.NotifyHeld(context.Background(), notice(approvalURL(500))))
	require.Equal(t, "-100123", got.body["chat_id"])
	require.Contains(t, got.body["text"], "approval needed")
	require.Contains(t, got.body, "reply_markup")
}

func revertNotice(url string) telegram.RevertNotice {
	return telegram.RevertNotice{
		RevertID:  uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000b2"),
		Agent:     "bot",
		Database:  "app",
		Headline:  "Revert of run 0193a4c2-7d1e-7c3a-9f00-0000000000c3: 2 rows to restore, 0 left as they are (changed after the agent).",
		Intent:    "Undo the win",
		ExpiresAt: time.Date(2026, 11, 13, 6, 2, 11, 0, time.UTC),
		RevertURL: url,
		ShortURL:  "http://localhost:8787/reverts/0193a4c2-7d1e-7c3a-9f00-0000000000b2#s=secret",
	}
}

func TestRevertMessage(t *testing.T) {
	t.Parallel()
	t.Run("short link: a button, the short link in the text", func(t *testing.T) {
		m := telegram.RevertMessage(revertNotice(approvalURL(500)))
		require.Equal(t, &telegram.Button{Text: telegram.RevertButtonText, URL: approvalURL(500)}, m.Button)
		require.True(t, strings.HasPrefix(m.Text, "BasaltDB: revert waiting for your signature\n\nRevert of run "), m.Text)
		require.Contains(t, m.Text, "Agent: bot on app")
		require.Contains(t, m.Text, "Why: Undo the win")
		require.Contains(t, m.Text, "Expires: 2026-11-13 06:02 UTC")
		require.Contains(t, m.Text, "On the engine's computer: http://localhost:8787/reverts/")
	})
	t.Run("long link: in the text", func(t *testing.T) {
		m := telegram.RevertMessage(revertNotice(approvalURL(3000)))
		require.Nil(t, m.Button)
		require.Contains(t, m.Text, "Review and sign: "+approvalURL(3000))
	})
	t.Run("too long for the text: ask the agent", func(t *testing.T) {
		m := telegram.RevertMessage(revertNotice(approvalURL(5000)))
		require.Nil(t, m.Button)
		require.NotContains(t, m.Text, "#1.")
		require.Contains(t, m.Text, "ask the agent for it")
	})
	t.Run("widened: the headline only", func(t *testing.T) {
		n := revertNotice(approvalURL(500))
		n.Widened, n.Headline = true, "Revert widened by the person: 4 rows to restore."
		m := telegram.RevertMessage(n)
		require.Nil(t, m.Button)
		require.Equal(t, "BasaltDB: revert waiting for your signature\n\nRevert widened by the person: 4 rows to restore.", m.Text)
	})
}

func TestNotifyRevert(t *testing.T) {
	t.Parallel()
	srv, got := server(t, http.StatusOK, `{"ok":true}`)
	n := telegram.NewNotifier(telegram.NewClient(srv.Client(), srv.URL, token(t), "-100123"))
	require.NoError(t, n.NotifyRevert(context.Background(), revertNotice(approvalURL(500))))
	require.Equal(t, "-100123", got.body["chat_id"])
	require.Contains(t, got.body["text"], "revert waiting for your signature")
	require.Contains(t, got.body, "reply_markup")
}
