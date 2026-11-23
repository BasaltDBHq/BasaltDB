// Package handoffcli is the handoff side of the CLI: the agent's own login
// that decides which setup code basalt init --remote makes.
package handoffcli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// LoginAsAgent connects with dsn: handoff.ErrLoginRefused when the database
// refuses the login (class 28, or the pooler not knowing the role).
func LoginAsAgent(ctx context.Context, sh cli.Host, dsn string) (cli.AgentConn, error) {
	ctx, cancel := context.WithTimeout(ctx, setup.LoginTimeout)
	defer cancel()
	conn, err := cli.Connect(ctx, sh, dsn)
	var pg *pgconn.PgError
	switch {
	case err == nil:
		return conn, nil
	case errors.As(err, &pg) && (strings.HasPrefix(pg.Code, setup.SQLStateClassAuth) ||
		(pg.Code == setup.SQLStateInternal && strings.Contains(pg.Message, setup.SupavisorNoTenant))):
		return nil, handoff.ErrLoginRefused
	}
	return nil, fmt.Errorf("cannot reach the database to check the agent's role (nothing changed): %w", err)
}
