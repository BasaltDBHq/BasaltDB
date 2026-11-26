// Package handoffcli is the handoff side of the CLI: the agent's own login
// that decides which setup code basalt init --remote makes.
package handoffcli

import (
	"context"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/handoff"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// LoginAsAgent connects with dsn: handoff.ErrLoginRefused when the database
// refuses the login (setup.LoginRefused: class 28, or the pooler not
// knowing the role, its message read through e).
func LoginAsAgent(ctx context.Context, sh cli.Host, e setup.DBErrors, dsn string) (cli.AgentConn, error) {
	ctx, cancel := context.WithTimeout(ctx, setup.LoginTimeout)
	defer cancel()
	conn, err := cli.Connect(ctx, sh, dsn)
	switch {
	case err == nil:
		return conn, nil
	case setup.LoginRefused(e, err):
		return nil, handoff.ErrLoginRefused
	}
	return nil, fmt.Errorf("cannot reach the database to check the agent's role (nothing changed): %w", err)
}
