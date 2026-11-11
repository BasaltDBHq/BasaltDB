package engine

import (
	"context"
	"net/http"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/engine/agent"
	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/notify/telegram"
)

// notifyTimeout bounds one notification: a slow Telegram must not hold the
// agent's write call.
const notifyTimeout = 10 * time.Second

// newTelegram returns the Telegram notifier cfg configures, or nil.
func newTelegram(cfg config.Notify) (*telegram.Notifier, error) {
	if cfg.Telegram == nil {
		return nil, nil //nolint:nilnil // no notifier configured is not an error
	}
	tok, err := telegram.LoadToken(cfg.Telegram.BotTokenFile)
	if err != nil {
		return nil, err
	}
	client := telegram.NewClient(&http.Client{Timeout: notifyTimeout}, telegram.DefaultAPIBase, tok, cfg.Telegram.ChatID)
	return telegram.NewNotifier(client), nil
}

// telegramNotifier sends one agent's held writes to Telegram.
type telegramNotifier struct {
	n        *telegram.Notifier
	database string
}

// agentNotifier is the agent's Notifier: Telegram when configured, else
// none.
func agentNotifier(n *telegram.Notifier, database string) agent.Notifier {
	if n == nil {
		return nil
	}
	return telegramNotifier{n: n, database: database}
}

func (t telegramNotifier) NotifyHeld(ctx context.Context, h agent.HeldNotice) error {
	ctx, cancel := context.WithTimeout(ctx, notifyTimeout)
	defer cancel()
	return t.n.NotifyHeld(ctx, telegram.Notice{
		ApprovalID: h.ApprovalID, Agent: h.Agent, Database: t.database, Intent: h.Intent,
		Statement: h.Statement, Headline: h.Headline, ExpiresAt: h.ExpiresAt, ApprovalURL: h.ApprovalURL,
		ShortURL: h.ShortURL,
	})
}
