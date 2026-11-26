package store

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approvalstore"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
)

func approvalInvalid(detail string) error { return guardErr("BS005", "APPROVAL_INVALID", detail, "") }

// noSuchApprovalErr is APPROVAL_INVALID NO_SUCH_APPROVAL with the hint hint.
func noSuchApprovalErr(hint string) error {
	return guardErr("BS005", "APPROVAL_INVALID", "NO_SUCH_APPROVAL", hint)
}

// approvalRefusalRow is one guard answer to one approval call: the refusal
// the adapter maps it to, or none (reason "") when the service reads the
// mapped error as it is.
type approvalRefusalRow struct {
	name    string
	mapping func(error) error
	err     error
	reason  approvalstore.ApprovalReason
	detail  string
}

// Each approval call maps the guard's answers the way the approval use
// case told them apart. The reveal compares the detail for equality, so a
// detail that only contains a known one is NOT_OPEN, and "another agent"
// is NOT_OPEN there although MapError reads it as NOT_THIS_AGENT. Every
// answer is mapped after MapError and keeps the mapped error in its chain.
func TestApprovalRefusalsPerCall(t *testing.T) {
	t.Parallel()
	const (
		noSuchApproval = "no such approval"
		approved       = "approval already approved"
		used           = "approval already used"
		anotherAgent   = "approval is for another agent"
	)
	expired := guardErr("BS005", "APPROVAL_EXPIRED", "approval 0193a3f0-0000-7000-8000-000000000001 expired at 2026-11-25 10:00:00+00", "")
	rows := []approvalRefusalRow{
		{"find: not held by the role", findApprovalRefusal, ledger.ErrApprovalNotFound, approvalstore.ApprovalNotFound, ""},
		{"find: any other error", findApprovalRefusal, errors.New("conn closed"), "", ""},
		{"find: no rows", findApprovalRefusal, action.ErrNotFound, "", ""},

		{"reveal: refused", revealApprovalRefusal, approvalInvalid("REVEAL_REFUSED"), approvalstore.ApprovalRevealRefused, "REVEAL_REFUSED"},
		{"reveal: rows changed", revealApprovalRefusal, approvalInvalid("ROWS_CHANGED"), approvalstore.ApprovalRevealRowsChanged, "ROWS_CHANGED"},
		{"reveal: no such approval", revealApprovalRefusal, noSuchApprovalErr(noSuchApproval), approvalstore.ApprovalNotFound, noSuchApproval},
		{"reveal: no such approval, any hint", revealApprovalRefusal, noSuchApprovalErr("x"), approvalstore.ApprovalNotFound, "x"},
		// Told apart by the detail, never the words: the sentence as the
		// detail, as a guard before version 13 gave it, is not open.
		{"reveal: no such approval words, untyped", revealApprovalRefusal, approvalInvalid(noSuchApproval), approvalstore.ApprovalNotOpen, noSuchApproval},
		{"reveal: already approved", revealApprovalRefusal, approvalInvalid(approved), approvalstore.ApprovalNotOpen, approved},
		{"reveal: already used", revealApprovalRefusal, approvalInvalid(used), approvalstore.ApprovalNotOpen, used},
		{"reveal: another agent", revealApprovalRefusal, approvalInvalid(anotherAgent), approvalstore.ApprovalNotOpen, anotherAgent},
		{"reveal: contains REVEAL_REFUSED", revealApprovalRefusal, approvalInvalid("not REVEAL_REFUSED"), approvalstore.ApprovalNotOpen, "not REVEAL_REFUSED"},
		{"reveal: expired", revealApprovalRefusal, expired, "", ""},
		{"reveal: time limit", revealApprovalRefusal, statementTimeout(), "", ""},
		{"reveal: revert invalid", revealApprovalRefusal, revertInvalid("REVEAL_REFUSED"), "", ""},
		{"reveal: permission denied", revealApprovalRefusal, guardErr("42501", "permission denied", "", ""), "", ""},
		{"reveal: not a store error", revealApprovalRefusal, errors.New("conn closed"), "", ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			t.Parallel()
			mapped := MapError(row.err)
			out := row.mapping(mapped)
			refused := approvalstore.ApprovalRefusalOf(out)
			if row.reason == "" {
				require.Nil(t, refused, "%v", out)
				require.Equal(t, mapped, out, "returned as MapError made it")
				return
			}
			require.NotNil(t, refused, "%v", out)
			require.Equal(t, row.reason, refused.Reason)
			require.Equal(t, row.detail, refused.Detail)
			require.Same(t, mapped, refused.Err, "wraps the mapped error")
			require.Equal(t, mapped.Error(), out.Error(), "keeps the store's text")
			require.ErrorIs(t, out, row.err)
		})
	}
}

// The store's own error stays readable through a refusal: the tool error
// mapping reads its code and SQLSTATE as before.
func TestApprovalRefusalKeepsTheStoreError(t *testing.T) {
	t.Parallel()
	out := revealApprovalRefusal(MapError(approvalInvalid("approval already used")))
	var se *action.StoreError
	require.ErrorAs(t, out, &se)
	require.Equal(t, action.CodeApprovalInvalid, se.Code)
	require.Equal(t, "BS005", se.StoreCode)
}
