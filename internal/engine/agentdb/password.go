package agentdb

import (
	"context"
	"errors"
	"sync/atomic"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/basaltdbhq/basaltdb/internal/pgdial"
)

// Password is the agent's password a pool logs in with. The engine
// replaces it when it promotes a rotated credential (CONTRACT.md, Setup
// from your laptop, On the engine), then resets the pool so every new
// connection logs in with the new one.
type Password struct {
	v atomic.Pointer[string]
}

// Set replaces the password new connections log in with.
func (p *Password) Set(password string) { p.v.Store(&password) }

func (p *Password) get() string { return *p.v.Load() }

// NewSwitchablePool is NewPool whose connections log in with the password
// it returns, which the caller may replace.
func NewSwitchablePool(ctx context.Context, url string, maxConns int32) (*pgxpool.Pool, *Password, error) {
	cfg, err := pgdial.PoolConfig(url)
	if err != nil {
		// The parse error can echo the URL, which holds the password.
		return nil, nil, errors.New("the agent's credential is not a valid Postgres URL")
	}
	cfg.MaxConns = maxConns
	cfg.ConnConfig.MaxProtocolMessageBodyLen = maxMessageBytes
	cfg.ConnConfig.RuntimeParams["application_name"] = "basalt-engine"
	pw := &Password{}
	pw.Set(cfg.ConnConfig.Password)
	cfg.BeforeConnect = func(_ context.Context, cc *pgx.ConnConfig) error {
		cc.Password = pw.get()
		return nil
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, nil, err
	}
	return pool, pw, nil
}
