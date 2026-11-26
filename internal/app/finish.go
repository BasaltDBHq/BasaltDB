package app

import (
	"context"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/pgdial"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// agentConn is the agent's own connection the setup finisher reads with
// (handoff.AgentLogin).
type agentConn struct{ conn *pgx.Conn }

func (c agentConn) SetupRecorded(ctx context.Context, id uuid.UUID) (bool, error) {
	return guard.SetupRecorded(ctx, c.conn, id)
}

func (c agentConn) Close(ctx context.Context) error { return c.conn.Close(ctx) }

// connectAgent logs in with dsn for the setup finisher. A login the
// database refuses keeps its Postgres error, which setup.LoginRefused
// reads; any other is the store's mapped error, as the agent service reads
// them (postgres.MapError).
func connectAgent(ctx context.Context, dsn string) (handoff.AgentLogin, error) {
	conn, err := pgdial.Connect(ctx, dsn)
	switch {
	case setup.LoginRefused(pgErrors{}, err):
		return nil, err
	case err != nil:
		return nil, store.MapError(err)
	}
	return agentConn{conn}, nil
}

// agentFinisher is the setup finisher of one agent: its config entry, its
// credential file and the pool the engine serves it on, logging in with
// the Postgres adapter and reading a refused login's server message with
// it.
func agentFinisher(configPath, agent, credFile string, files handoff.FinishFiles, login handoff.LoginTarget,
	password interface{ Set(string) }, reset func(), log *slog.Logger,
) *handoff.Finisher {
	return &handoff.Finisher{
		ConfigPath: configPath, Agent: agent, CredFile: credFile, Files: files,
		Login: login, Parse: parseLogin, Password: password, Reset: reset,
		Connect: connectAgent, Errors: pgErrors{}, Log: log,
	}
}

// parseLogin is the target and password of a credential.
func parseLogin(dsn string) (handoff.LoginTarget, string, error) {
	cc, err := pgdial.ConnConfig(dsn)
	if err != nil {
		return handoff.LoginTarget{}, "", err
	}
	return targetOf(cc), cc.Password, nil
}

func targetOf(cc *pgx.ConnConfig) handoff.LoginTarget {
	return handoff.LoginTarget{Host: cc.Host, Port: cc.Port, Database: cc.Database, User: cc.User}
}
