package guard

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
)

const (
	sqlstateApproval     = "BS005"
	sqlstateRevert       = "BS009"
	sqlstateSetupRefused = "BS010"
	sqlstateScopeRefused = "BS011"
)

// byMessage lists the SQLSTATEs that carry several codes, told apart by
// the MESSAGE the guard raised.
var byMessage = map[string]map[string]guardmodel.Code{
	sqlstateApproval: {
		string(guardmodel.CodeApprovalInvalid): guardmodel.CodeApprovalInvalid, string(guardmodel.CodeApprovalExpired): guardmodel.CodeApprovalExpired,
		string(guardmodel.CodeRevertInvalid): guardmodel.CodeRevertInvalid, string(guardmodel.CodeRevertExpired): guardmodel.CodeRevertExpired,
	},
	sqlstateRevert: {
		string(guardmodel.CodeNothingToRevert): guardmodel.CodeNothingToRevert,
		string(guardmodel.CodeRevertCascade):   guardmodel.CodeRevertCascade,
	},
}

var sqlstateCodes = map[string]guardmodel.Code{
	"BS001":              guardmodel.CodeIntentRequired,
	"BS002":              guardmodel.CodeApprovalRequired,
	"BS003":              guardmodel.CodeRowLimitExceeded,
	"BS004":              guardmodel.CodeStaleRead,
	sqlstateApproval:     guardmodel.CodeApprovalInvalid,
	"BS006":              guardmodel.CodePreviewCannotCommit,
	"BS007":              guardmodel.CodeNotAllowed,
	"BS008":              guardmodel.CodeLedgerInputInvalid,
	sqlstateRevert:       guardmodel.CodeNothingToRevert,
	sqlstateSetupRefused: guardmodel.CodeSetupRefused,
	sqlstateScopeRefused: guardmodel.CodeScopeRefused,
}

// ScopeRefusal returns the detail (ScopeShape, ScopeNotOwnRun, ...) and the
// guard's explanation of a SCOPE_REFUSED error, and false for any other
// error.
func ScopeRefusal(err error) (detail, hint string, ok bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) || pg.Code != sqlstateScopeRefused {
		return "", "", false
	}
	return pg.Detail, pg.Hint, true
}

// CodeOf returns the guard-level code (the MESSAGE the guard raised) of
// err, and false when err is not a guard error. BS005 and BS009 carry
// several codes, told apart by the message. MCP tool codes are mapped from SQLSTATEs in
// internal/core/guidance (ErrorMap), per CONTRACT.md "Error codes".
func CodeOf(err error) (guardmodel.Code, bool) {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return "", false
	}
	code, ok := sqlstateCodes[pg.Code]
	if !ok {
		return "", false
	}
	if byMsg, ok := byMessage[pg.Code][pg.Message]; ok {
		return byMsg, true
	}
	return code, true
}
