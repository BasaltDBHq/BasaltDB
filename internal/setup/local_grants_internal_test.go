package setup

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

// The guard's refusal of a finish that leaves a grant on an unpicked table
// reaches the page as GRANTS_NOT_REVOKED, naming the role and the tables
// and what to do; any other guard refusal stays SETUP_FAILED.
func TestGrantsNotRevokedIsAReadableRefusal(t *testing.T) {
	t.Parallel()
	s := &LocalService{be: testBackend{}}
	pg := &pgconn.PgError{
		Code: sqlstateLedgerInputInvalid, Message: "LEDGER_INPUT_INVALID",
		Detail: "bt_agent_bot " + guardmodel.UnpickedGrantsDetail + "public.t2, sales.\u202enotes",
	}
	r := s.grantsNotRevoked(fmt.Errorf("init step 9: %w", pg), "bt_agent_bot")
	require.NotNil(t, r)
	require.Equal(t, CodeGrantsNotRevoked, r.Code)
	require.Contains(t, r.Message, "The agent role bt_agent_bot still has access to tables or sequences that were not picked (public.t2, sales.?notes)")
	require.Contains(t, r.Message, "That role, or the owner of the table or sequence, must revoke them (REVOKE ALL ON <table or sequence> FROM bt_agent_bot)")
	require.Contains(t, r.Message, "Nothing changed.")

	other := &pgconn.PgError{Code: sqlstateLedgerInputInvalid, Detail: "bt_agent_bot is not a plain agent role"}
	require.Nil(t, s.grantsNotRevoked(fmt.Errorf("init step 2: %w", other), "bt_agent_bot"))
	require.Nil(t, s.grantsNotRevoked(&pgconn.PgError{Code: "42501", Detail: pg.Detail}, "bt_agent_bot"))
	require.Nil(t, s.grantsNotRevoked(errors.New("no database error"), "bt_agent_bot"))
}
