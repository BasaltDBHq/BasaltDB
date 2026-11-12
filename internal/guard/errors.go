package guard

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// Code is a guard error code. Values match the MESSAGE the guard raises and
// the CONTRACT.md tool error codes where one exists.
type Code string

// Guard error codes (SQLSTATE class BS).
const (
	CodeIntentRequired      Code = "INTENT_REQUIRED"       // BS001
	CodeApprovalRequired    Code = "APPROVAL_REQUIRED"     // BS002
	CodeRowLimitExceeded    Code = "ROW_LIMIT_EXCEEDED"    // BS003
	CodeStaleRead           Code = "STALE_READ"            // BS004
	CodeApprovalInvalid     Code = "APPROVAL_INVALID"      // BS005
	CodeApprovalExpired     Code = "APPROVAL_EXPIRED"      // BS005
	CodePreviewCannotCommit Code = "PREVIEW_CANNOT_COMMIT" // BS006
	CodeNotAllowed          Code = "NOT_ALLOWED"           // BS007
	CodeLedgerInputInvalid  Code = "LEDGER_INPUT_INVALID"  // BS008
	CodeRevertInvalid       Code = "REVERT_INVALID"        // BS005
	CodeRevertExpired       Code = "REVERT_EXPIRED"        // BS005
	CodeNothingToRevert     Code = "NOTHING_TO_REVERT"     // BS009
	CodeRevertCascade       Code = "REVERT_CASCADE"        // BS009, caught inside a revert
	CodeSetupRefused        Code = "SETUP_REFUSED"         // BS010, to the admin only
)

const (
	sqlstateApproval     = "BS005"
	sqlstateRevert       = "BS009"
	sqlstateSetupRefused = "BS010"
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
}

// CodeOf returns the guard-level code (the MESSAGE the guard raised) of
// err, and false when err is not a guard error. BS005 and BS009 carry
// several codes, told apart by the message. MCP tool codes are mapped from SQLSTATEs in
// internal/engine/agent, per CONTRACT.md "Error codes".
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
