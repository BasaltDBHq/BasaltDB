package guard

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"time"

	sq "github.com/Masterminds/squirrel"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Setup kinds (CONTRACT.md, The setup code).
const (
	SetupInstall = "INSTALL"
	SetupAgent   = "AGENT"
	SetupUpgrade = "UPGRADE"
)

// SETUP_REFUSED reasons: the DETAIL record_setup raises with BS010.
const (
	SetupUsed         = "USED"
	SetupSuperseded   = "SUPERSEDED"
	SetupExpired      = "EXPIRED"
	SetupIDInFuture   = "SETUP_ID_IN_FUTURE"
	SetupExpiryTooFar = "EXPIRY_TOO_FAR"
)

// Setup is one setup code to record with RecordSetup.
type Setup struct {
	// ID is the code's setupId (a UUIDv7).
	ID   uuid.UUID
	Kind string
	// Agent is the agent's name (not its role); empty for SetupUpgrade.
	Agent string
	// GuardVersion is the code's guard.to.
	GuardVersion int
	ExpiresAt    time.Time
}

// RecordSetup records s with the admin connection (basalt init
// --setup-code), in the transaction that applies the code, and returns the
// seq of its AGENT_SETUP ledger row. Postgres refuses a used, superseded,
// expired or forged-time code with SETUP_REFUSED (see SetupRefusal).
func RecordSetup(ctx context.Context, q Querier, n Names, s Setup) (int64, error) {
	if err := n.Validate(); err != nil {
		return 0, err
	}
	var agent any // NULL for UPGRADE
	if s.Agent != "" {
		role, err := n.Agent(s.Agent)
		if err != nil {
			return 0, err
		}
		agent = role
	}
	sql, args, err := psql.Select().Column(sq.Expr("basalt_meta.record_setup(?::uuid, ?::text, ?::name, ?::int, ?::timestamptz)",
		s.ID, s.Kind, agent, s.GuardVersion, s.ExpiresAt)).ToSql()
	if err != nil {
		return 0, err
	}
	var seq int64
	err = q.QueryRow(ctx, sql, args...).Scan(&seq)
	return seq, err
}

// SetupRefusal returns the reason (SetupUsed, ...) of a SETUP_REFUSED
// error, and false when err is not one.
func SetupRefusal(err error) (string, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != sqlstateSetupRefused {
		return "", false
	}
	return pg.Detail, true
}

// verifierPattern is the SCRAM-SHA-256 verifier of a setup code
// (api/mcp/setup/setup-code.schema.json): 4096 iterations, a 16-byte salt,
// 32-byte keys, standard base64. Its alphabet holds no quote or backslash.
var verifierPattern = regexp.MustCompile(`^SCRAM-SHA-256\$4096:([A-Za-z0-9+/]{22}==)\$([A-Za-z0-9+/]{43}=):([A-Za-z0-9+/]{43}=)$`)

// CheckVerifier returns ErrInvalidAgent unless v is a SCRAM-SHA-256
// verifier in the setup code's format, with canonical base64.
func CheckVerifier(v string) error {
	m := verifierPattern.FindStringSubmatch(v)
	if m == nil {
		return fmt.Errorf("%w: the password must be a SCRAM-SHA-256 verifier", ErrInvalidAgent)
	}
	for _, part := range m[1:] {
		if _, err := base64.StdEncoding.Strict().DecodeString(part); err != nil {
			return fmt.Errorf("%w: the SCRAM-SHA-256 verifier is not canonical base64", ErrInvalidAgent)
		}
	}
	return nil
}
