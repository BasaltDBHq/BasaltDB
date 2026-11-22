package guard

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

const (
	sqlstateApproval     = "BS005"
	sqlstateRevert       = "BS009"
	sqlstateSetupRefused = "BS010"
	sqlstateScopeRefused = "BS011"
)

// byMessage lists the SQLSTATEs that carry several codes, told apart by
// the MESSAGE the guard raised.
var byMessage = map[string]map[string]Code{
	sqlstateApproval: {
		string(CodeApprovalInvalid): CodeApprovalInvalid, string(CodeApprovalExpired): CodeApprovalExpired,
		string(CodeRevertInvalid): CodeRevertInvalid, string(CodeRevertExpired): CodeRevertExpired,
	},
	sqlstateRevert: {
		string(CodeNothingToRevert): CodeNothingToRevert,
		string(CodeRevertCascade):   CodeRevertCascade,
	},
}

var sqlstateCodes = map[string]Code{
	"BS001":              CodeIntentRequired,
	"BS002":              CodeApprovalRequired,
	"BS003":              CodeRowLimitExceeded,
	"BS004":              CodeStaleRead,
	sqlstateApproval:     CodeApprovalInvalid,
	"BS006":              CodePreviewCannotCommit,
	"BS007":              CodeNotAllowed,
	"BS008":              CodeLedgerInputInvalid,
	sqlstateRevert:       CodeNothingToRevert,
	sqlstateSetupRefused: CodeSetupRefused,
	sqlstateScopeRefused: CodeScopeRefused,
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
// internal/service/agent, per CONTRACT.md "Error codes".
func CodeOf(err error) (Code, bool) {
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
