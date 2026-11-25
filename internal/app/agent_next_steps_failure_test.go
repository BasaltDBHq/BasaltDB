package app

import (
	"testing"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	linksvc "github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"
)

// The step builders of APPROVAL_REQUIRED, HOLD_TOO_LARGE and REVERT_INVALID
// live in the approval and revert packages, whose own tests run the catalog's
// cases on them. These cases run one of each through the real Failure, so the
// agent's error mapping that calls them keeps an end-to-end test, with the
// catalog's expectations.
func TestFailureCallsTheApprovalAndRevertStepBuilders(t *testing.T) {
	t.Parallel()
	const url = "http://localhost:7878/approvals/" + caseApproval + "#s=AAAAAAAAAAAAAAAAAAAAAA"
	held := linksvc.HeldAnswer{
		Reason: guidance.ReasonHeld,
		ApprovalNotice: toolresult.ApprovalNotice{
			ApprovalID: caseApproval, ExpiresAt: "2026-11-12T10:00:00Z", Rows: 3, Headline: "Delete 3 rows in public.leads", ApprovalURL: url,
			PersonMessage: "Held for your approval: Delete 3 rows in public.leads.\nApprove it with your passkey here:\n\n" + url + "\n\nExpires 2026-11-12 10:00 UTC.",
			Links:         []toolresult.Link{{Label: linksvc.LabelApprove, URL: url}},
		},
	}
	cases := map[string]catalogCase{
		stepcatalogtest.CaseKey("APPROVAL_REQUIRED", "HELD", ""): {
			"write", writeArgs0, plainFunc(func() error { return approval.ApprovalRequiredError(held) }),
		},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "HOLD_TOO_LARGE", ""): {
			"write", writeArgs0, pgFail("BS007", "NOT_ALLOWED", guard.DetailHoldTooLarge),
		},
		stepcatalogtest.CaseKey("REVERT_INVALID", "LINE_INVALID", ""): {
			"apply_revert_batch", map[string]any{"revertId": caseRevertID, "lines": []any{1}}, pgFail("BS005", "REVERT_INVALID", "line 9 is not in the plan"),
		},
	}
	for key, kase := range cases {
		for _, operatedBy := range []string{"", mcpcontract.OperatedByAgent} {
			t.Run(key+"/"+operatedBy, func(t *testing.T) {
				t.Parallel()
				s := operatedService(t, "linux", "", operatedBy)
				te := s.Failure(kase.tool, kase.args, kase.fail(t, s))
				stepcatalogtest.RequireObeysCatalog(t, kase.step(), te, operatedBy)
			})
		}
	}
}
