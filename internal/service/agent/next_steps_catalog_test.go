package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/ledger"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/resultsize"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/store"
)

// This file is the contract test of the engine's error guidance
// (CONTRACT.md, Next steps): every error entry of api/mcp/errors/next-steps.json
// has a case that provokes it, and every provoked body obeys the catalog and
// the contract's rules. The cases raise each failure the way the layer below
// does (a Postgres error carrying the guard's SQLSTATE, a statement
// refusal, a store error) and run it through Service.Failure, the one place
// every tool error passes; the guard cases on a real database are in
// guidance_pg_test.go.

const (
	caseRunID    = "0193a4c2-7d1e-7c3a-9f00-0000000000a1"
	caseRevertID = "0193a4c2-7d1e-7c3a-9f00-0000000000b2"
	caseChangeID = "0193a4c2-7d1e-7c3a-9f00-0000000000c3"
	caseApproval = "0193a4c2-7d1e-7c3a-9f00-0000000000d4"
)

var (
	writeArgs0 = map[string]any{
		"sql": "UPDATE leads SET status = $1 WHERE id = $2", "params": []any{"lost", 42},
		"intent": "No answer for a week", "runId": caseRunID,
	}
	queryArgs0 = map[string]any{"sql": "SELECT id FROM leads", "runId": caseRunID}
)

type catalogCase struct {
	tool string
	args map[string]any
	fail func(t *testing.T, s *Service) error
}

// catalogReverts and catalogApprovals are the stores the cases need: the
// failure is raised by the test, so only the lookups the engine makes while
// building steps answer.
type catalogReverts struct {
	Reverts
	lines []string
	by    uuid.UUID
}

func (r catalogReverts) PreviewRevert(context.Context, action.Scope, string, int) (action.PreviewPage, error) {
	out := action.PreviewPage{Lines: len(r.lines), AllAlreadyReverted: true, CursorFound: true}
	for _, text := range r.lines {
		l, err := revert.ParseLine(text)
		if err != nil {
			return action.PreviewPage{}, err
		}
		if l.Action == revert.ActionRestore {
			out.Restore++
		}
		out.AllAlreadyReverted = out.AllAlreadyReverted && l.Conflict != nil && *l.Conflict == revert.ConflictAlreadyReverted
	}
	return out, nil
}

func (r catalogReverts) RevertedBy(context.Context, action.Scope) (uuid.UUID, error) {
	return r.by, nil
}

type catalogApprovals struct{ approvalStore }

func (catalogApprovals) Passkeys(context.Context) ([]passkey.Credential, error) { return nil, nil }

func pgFail(code, message, detail string) func(*testing.T, *Service) error {
	return func(*testing.T, *Service) error {
		return store.MapError(&pgconn.PgError{Code: code, Message: message, Detail: detail})
	}
}

func staleText(table, key string) string {
	return fmt.Sprintf("%s %s read at xmin 7, now 9", table, key)
}

func refusal(reason action.RefusalReason) func(*testing.T, *Service) error {
	return func(*testing.T, *Service) error { return &action.RefusalError{Reason: reason, Detail: "detail"} }
}

func plain(err error) func(*testing.T, *Service) error {
	return func(*testing.T, *Service) error { return err }
}

func asToolError(te *toolresult.ToolError) func(*testing.T, *Service) error {
	return func(*testing.T, *Service) error { return te }
}

func guardApproval(detail string) func(*testing.T, *Service) error {
	return pgFail("BS005", "APPROVAL_INVALID", detail)
}

func guardRevert(detail string) func(*testing.T, *Service) error {
	return pgFail("BS005", "REVERT_INVALID", detail)
}

func caseRevert(signed bool) action.Revert {
	r := action.Revert{
		ID: uuid.MustParse(caseRevertID), Status: "PENDING", Scope: "RUN", ScopeID: uuid.MustParse(caseRunID),
		ExpiresAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC),
	}
	if signed {
		at := r.ExpiresAt
		r.SignedAt = &at
	}
	return r
}

func caseNotice(url string) toolresult.ApprovalNotice {
	return toolresult.ApprovalNotice{
		ApprovalID: caseApproval, ExpiresAt: "2026-11-12T10:00:00Z", Rows: 3,
		Headline: "Delete 3 rows in public.leads", ApprovalURL: url,
		PersonMessage: "Held for your approval: Delete 3 rows in public.leads.\nApprove it with your passkey here:\n\n" + url + "\n\nExpires 2026-11-12 10:00 UTC.",
		Links:         []toolresult.Link{{Label: linksvc.LabelApprove, URL: url}},
	}
}

const caseShortLink = "http://localhost:7878/approvals/" + caseApproval + "#s=AAAAAAAAAAAAAAAAAAAAAA"

func held(reason string, url string) func(*testing.T, *Service) error {
	return func(_ *testing.T, s *Service) error {
		n := linksvc.HeldAnswer{ApprovalNotice: caseNotice(url), Reason: reason}
		if reason == guidance.ReasonWaitEnded {
			return approvalStillPendingError(n)
		}
		return approvalRequiredError(n)
	}
}

func approvalLink(reason string) func(*testing.T, *Service) error {
	return func(_ *testing.T, s *Service) error {
		n := linksvc.HeldAnswer{ApprovalNotice: caseNotice(caseShortLink), LongURL: caseShortLink, Pick: linksvc.HandOver{URL: caseShortLink, Kind: linksvc.LinkLong}}
		return s.approvalLinkError(&toolresult.ToolError{Code: guidance.CodeApprovalInvalid, Reason: reason, Message: "m"}, n)
	}
}

func nothingToRevert(tool string, lines []string, detail string, by uuid.UUID) func(*testing.T, *Service) error {
	return func(t *testing.T, s *Service) error {
		setReverts(&s.deps, catalogReverts{lines: lines, by: by})
		scope := action.Scope{Kind: "RUN", ID: uuid.MustParse(caseRunID)}
		return s.revert.nothingToRevert(context.Background(), tool, scope, store.MapError(&pgconn.PgError{Code: "BS009", Message: "NOTHING_TO_REVERT", Detail: detail}))
	}
}

const alreadyRevertedLine = `{"op": "UPDATE", "key": {"id": 3}, "now": {"id": 3}, "set": {"id": 3}, "table": "public.leads", ` +
	`"action": "SKIP", "cascaded": false, "conflict": "ALREADY_REVERTED", "sqlState": null, "changeIds": ["` + caseChangeID + `"]}`

const changedAfterLine = `{"op": "UPDATE", "key": {"id": 3}, "now": {"id": 3}, "set": {"id": 3}, "table": "public.leads", ` +
	`"action": "SKIP", "cascaded": false, "conflict": "CHANGED_AFTER", "sqlState": null, "changeIds": ["` + caseChangeID + `"]}`

func caseKey(code, reason, tool string) string { return code + "|" + reason + "|" + tool }

// tooLargeHeads are the heads of a held write's lines an agent's read left
// out (ledger.withRequest).
var tooLargeHeads = []string{`{"op": "DELETE", "table": "public.leads", "cascaded": false}`}

// tooLargeNotice is the notice of a held write whose request no link this
// engine has can carry: no local pages, no Vault.
func tooLargeNotice(t *testing.T, s *Service, issue bool) linksvc.HeldAnswer {
	t.Helper()
	s = serviceWith(s, withoutLocalPages)
	if p, _ := s.deps.Core.Store.(parts); p.approvalStore == nil {
		setApprovals(&s.deps, catalogApprovals{})
	}
	req := linksvc.SizedRequest{Binding: "{}", Lines: tooLargeHeads, LeftOut: true, Cost: 2 << 20}
	n, err := s.approval.approvalNotice(context.Background(), uuid.MustParse(caseApproval), uuid.MustParse(caseRunID), req,
		time.Now().Add(time.Hour), issue)
	require.NoError(t, err)
	return n
}

// catalogCases has one case per error entry of the catalog. A new code or
// reason needs its case here or TestEveryCatalogErrorHasACase fails.
func catalogCases() map[string]catalogCase {
	revertArgs := map[string]any{"revertId": caseRevertID}
	timeoutRevert := func(tool string) func(*testing.T, *Service) error {
		return func(t *testing.T, s *Service) error {
			return s.revert.prepareTimeout(tool, action.Scope{Kind: "RUN", ID: uuid.MustParse(caseRunID)}, "57014")
		}
	}
	cases := map[string]catalogCase{
		caseKey("INTENT_REQUIRED", "", ""): {"write", map[string]any{"sql": "DELETE FROM leads WHERE id = 1"}, pgFail("BS001", "INTENT_REQUIRED", "")},
		caseKey("STALE_READ", "", ""): {
			"write", writeArgs0,
			pgFail("BS004", "STALE_READ", staleText("public.leads", `{"id": 42}`)),
		},

		caseKey("STATEMENT_REFUSED", "PARSE_ERROR", ""):           {"query", queryArgs0, refusal(action.ReasonParseError)},
		caseKey("STATEMENT_REFUSED", "MULTIPLE_STATEMENTS", ""):   {"query", queryArgs0, refusal(action.ReasonMultipleStatements)},
		caseKey("STATEMENT_REFUSED", "WRONG_TOOL", ""):            {"query", queryArgs0, refusal(action.ReasonWrongTool)},
		caseKey("STATEMENT_REFUSED", "DDL_NOT_ALLOWED", ""):       {"write", writeArgs0, refusal(action.ReasonDDL)},
		caseKey("STATEMENT_REFUSED", "STATEMENT_NOT_ALLOWED", ""): {"write", writeArgs0, refusal(action.ReasonUtility)},
		caseKey("STATEMENT_REFUSED", "SELECT_INTO", ""):           {"query", queryArgs0, refusal(action.ReasonSelectInto)},
		caseKey("STATEMENT_REFUSED", "LOCKING_READ", ""):          {"query", queryArgs0, refusal(action.ReasonLockingRead)},
		caseKey("STATEMENT_REFUSED", "MERGE_NOT_ALLOWED", ""):     {"write", writeArgs0, refusal(action.ReasonMerge)},
		caseKey("STATEMENT_REFUSED", "DATA_MODIFYING_WITH", ""):   {"query", queryArgs0, refusal(action.ReasonDataModifyingWith)},
		caseKey("STATEMENT_REFUSED", "FUNCTION_NOT_ALLOWED", ""):  {"query", queryArgs0, refusal(action.ReasonFunction)},
		caseKey("STATEMENT_REFUSED", "NOT_REPEATABLE", ""):        {"write", writeArgs0, refusal(action.ReasonNotRepeatable)},
		caseKey("STATEMENT_REFUSED", "NO_PRIMARY_KEY", ""): {
			"write", writeArgs0,
			pgFail("BS007", "NOT_ALLOWED", "table public.events has no primary key; the guard keys ledger rows by it"),
		},
		caseKey("STATEMENT_REFUSED", "NOT_ALLOWED", ""):    {"write", writeArgs0, pgFail("BS007", "NOT_ALLOWED", "TRUNCATE by an agent")},
		caseKey("STATEMENT_REFUSED", "HOLD_TOO_LARGE", ""): {"write", writeArgs0, pgFail("BS007", "NOT_ALLOWED", guardmodel.DetailHoldTooLarge)},

		caseKey("ROW_LIMIT_EXCEEDED", "", ""): {
			"write", writeArgs0,
			pgFail("BS003", "ROW_LIMIT_EXCEEDED", "more than 50 rows in one action (cascades included)"),
		},

		caseKey("QUERY_TIMEOUT", "ROW_LIMIT", ""):  {"query", queryArgs0, plain(action.ErrRowLimit)},
		caseKey("QUERY_TIMEOUT", "SIZE_LIMIT", ""): {"query", queryArgs0, plain(budget.ErrSizeLimit)},
		caseKey("QUERY_TIMEOUT", "ROW_TOO_LARGE", ""): {
			"query", queryArgs0,
			plain(&resultsize.RowTooLargeError{Bytes: 20 << 20, Columns: []resultsize.ColumnSize{{Name: "body", Bytes: 20 << 20}}}),
		},
		caseKey("QUERY_TIMEOUT", "TIME_LIMIT", ""): {"query", queryArgs0, pgFail("57014", "canceling statement due to statement timeout", "")},
		caseKey("QUERY_TIMEOUT", "TIME_LIMIT", "preview_revert"): {
			"preview_revert",
			map[string]any{"runId": caseRunID},
			timeoutRevert("preview_revert"),
		},
		caseKey("QUERY_TIMEOUT", "TIME_LIMIT", "request_revert"): {
			"request_revert",
			map[string]any{"runId": caseRunID, "intent": "Undo"},
			timeoutRevert("request_revert"),
		},

		caseKey("QUERY_TIMEOUT", "REQUEST_TOO_LARGE", "request_revert"): {
			"request_revert",
			map[string]any{"runId": caseRunID, "intent": "Undo"},
			func(t *testing.T, s *Service) error {
				return s.delivery.RevertTooLargeError(uuid.MustParse(caseRevertID), 2<<20, time.Now().Add(time.Hour))
			},
		},
		caseKey("APPROVAL_REQUIRED", "REQUEST_TOO_LARGE", ""): {"write", writeArgs0, func(t *testing.T, s *Service) error {
			n := tooLargeNotice(t, s, linksvc.IssueLink)
			require.Equal(t, linksvc.ReasonRequestTooLarge, n.Reason)
			return approvalError(n, "")
		}},
		caseKey("APPROVAL_REQUIRED", "HELD", ""):          {"write", writeArgs0, held(guidance.ReasonHeld, caseShortLink)},
		caseKey("APPROVAL_REQUIRED", "HELD_NO_PAGES", ""): {"write", writeArgs0, held(guidance.ReasonHeldNoPages, "http://localhost:7878/approvals/"+caseApproval+"#1.abc")},
		caseKey("APPROVAL_REQUIRED", "NO_PASSKEY", ""):    {"write", writeArgs0, held(guidance.ReasonNoPasskey, caseShortLink)},
		caseKey("APPROVAL_REQUIRED", "WAIT_ENDED", ""): {
			"write", withApproval(writeArgs0),
			held(guidance.ReasonWaitEnded, "http://localhost:7878/approvals/"+caseApproval+"#1.abc"),
		},

		caseKey("APPROVAL_EXPIRED", "", ""): {"write", withApproval(writeArgs0), asToolError(&toolresult.ToolError{Code: guidance.CodeApprovalExpired, Message: "approval expired"})},

		caseKey("APPROVAL_INVALID", "NOT_SIGNED", ""):      {"write", withApproval(writeArgs0), approvalLink(guidance.ReasonNotSigned)},
		caseKey("APPROVAL_INVALID", "ALREADY_USED", ""):    {"write", withApproval(writeArgs0), guardApproval("approval already used")},
		caseKey("APPROVAL_INVALID", "DIFFERENT_WRITE", ""): {"write", withApproval(writeArgs0), guardApproval("the statement or its parameters differ from the approval")},
		caseKey("APPROVAL_INVALID", "NOT_THIS_AGENT", ""):  {"write", withApproval(writeArgs0), guardApproval("approval is for another agent")},
		caseKey("APPROVAL_INVALID", "ROWS_CHANGED", ""): {
			"write", withApproval(writeArgs0),
			guardApproval("rows changed since the preview; a fresh preview and approval are needed"),
		},
		caseKey("APPROVAL_INVALID", "BAD_SIGNATURE", ""):   {"write", withApproval(writeArgs0), approvalLink(guidance.ReasonBadSignature)},
		caseKey("APPROVAL_INVALID", "PASSKEY_REVOKED", ""): {"write", withApproval(writeArgs0), approvalLink(guidance.ReasonPasskeyRevoked)},

		caseKey("REVERT_INVALID", "LINE_INVALID", ""): {
			"apply_revert_batch",
			map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			guardRevert("line 9 is not in the plan"),
		},
		caseKey("REVERT_INVALID", "PLAN_NOT_SIGNED", ""): {
			"apply_revert_batch",
			map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			guardRevert("the person has not signed this revert yet: they sign it on the revert page"),
		},
		caseKey("REVERT_INVALID", "PLAN_FINISHED", ""): {
			"apply_revert_batch",
			map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			guardRevert("revert already applied: no line is pending"),
		},
		caseKey("REVERT_INVALID", "NOT_THIS_AGENT", ""): {
			"apply_revert_batch",
			map[string]any{"revertId": caseRevertID, "lines": []any{1}},
			guardRevert("no such revert"),
		},
		caseKey("REVERT_INVALID", "ROWS_CHANGED", ""): {"request_revert", revertArgs, func(t *testing.T, s *Service) error {
			return s.revert.rowsChanged(caseRevert(false), "rows changed")
		}},
		caseKey("REVERT_INVALID", "BAD_SIGNATURE", ""): {"request_revert", revertArgs, func(t *testing.T, s *Service) error {
			return s.revert.badSignatureWith(guidance.OpenLink(caseShortLink, signAgainText), caseRevert(false), "the code does not verify")
		}},
		caseKey("REVERT_INVALID", "PASSKEY_REVOKED", ""): {"request_revert", revertArgs, func(t *testing.T, s *Service) error {
			return s.revert.passkeyRevokedWith(guidance.OpenLink(caseShortLink, signRevokedText), caseRevert(false))
		}},

		caseKey("REVERT_EXPIRED", "NOT_SIGNED", ""):   {"request_revert", revertArgs, func(t *testing.T, s *Service) error { return s.revert.revertExpired(caseRevert(false)) }},
		caseKey("REVERT_EXPIRED", "NOT_FINISHED", ""): {"request_revert", revertArgs, func(t *testing.T, s *Service) error { return s.revert.revertExpired(caseRevert(true)) }},

		caseKey("NOTHING_TO_REVERT", "READS_ONLY", ""): {
			"request_revert",
			map[string]any{"runId": caseRunID, "intent": "Undo"},
			nothingToRevert("request_revert", nil, "the run changed no rows", uuid.Nil),
		},
		caseKey("NOTHING_TO_REVERT", "ALL_CHANGED_BY_PEOPLE", ""): {
			"preview_revert",
			map[string]any{"runId": caseRunID},
			nothingToRevert("preview_revert", []string{changedAfterLine}, "every line skipped", uuid.Nil),
		},
		caseKey("NOTHING_TO_REVERT", "ALREADY_REVERTED", ""): {
			"preview_revert",
			map[string]any{"runId": caseRunID},
			nothingToRevert("preview_revert", []string{alreadyRevertedLine}, "every line skipped", uuid.MustParse(caseChangeID)),
		},

		caseKey("PERMISSION_DENIED", "", ""): {"query", queryArgs0, pgFail("42501", "permission denied for table events", "")},

		caseKey("NOT_FOUND", "RUN", ""):      {"query", queryArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "RUN", Message: "no such run"})},
		caseKey("NOT_FOUND", "CHANGE", ""):   {"request_revert", map[string]any{"changeId": caseChangeID, "intent": "Undo", "runId": caseRunID}, asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "CHANGE", Message: "no such change"})},
		caseKey("NOT_FOUND", "APPROVAL", ""): {"write", withApproval(writeArgs0), asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "APPROVAL", Message: "no such approval"})},
		caseKey("NOT_FOUND", "REVERT", ""):   {"request_revert", revertArgs, plainFunc(func() error { return revertNotFound(uuid.MustParse(caseRevertID)) })},
		caseKey("NOT_FOUND", "TASK", ""): {
			"preview_revert",
			map[string]any{"taskId": caseRunID},
			plainFunc(func() error {
				return notOwnTask(action.Scope{Kind: "TASK", ID: uuid.MustParse(caseRunID)})
			}),
		},
		caseKey("NOT_FOUND", "LINK", ""):       {"approval_page", nil, asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "LINK", Message: "no such link"})},
		caseKey("NOT_FOUND", "LINK_RESET", ""): {"revert_page", nil, asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "LINK_RESET", Message: "the link was reset"})},
		caseKey("APPROVAL_INVALID", "REVEAL_REFUSED", ""): {"approval_page", nil, func(*testing.T, *Service) error {
			return linksvc.RevealRefused(guidance.CodeApprovalInvalid, "http://localhost:8787/approvals/0193a3f0-0000-7000-8000-000000000001#s=AAECAwQFBgcICQoLDA0ODw")
		}},
		caseKey("REVERT_INVALID", "REVEAL_REFUSED", ""): {"revert_page", nil, func(*testing.T, *Service) error {
			return linksvc.RevealRefused(guidance.CodeRevertInvalid, "http://localhost:8787/reverts/0193a3f0-0000-7000-8000-000000000001#s=AAECAwQFBgcICQoLDA0ODw")
		}},
		caseKey("NOT_FOUND", "", "describe"): {
			"describe",
			map[string]any{"resource": "billing.invoices"},
			plainFunc(func() error { return describeNotFound("billing.invoices") }),
		},

		caseKey("SQL_ERROR", "", ""):            {"write", writeArgs0, pgFail("42703", `column "x" does not exist`, "")},
		caseKey("SQL_ERROR", "NO_ROWS_NOW", ""): {"write", writeArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeSQLError, Reason: guidance.ReasonNoRowsNow, Message: "changes no rows now"})},
		caseKey("INVALID_ARGUMENT", "", ""):     {"write", writeArgs0, plain(&guidance.ArgumentError{Message: "invalid arguments"})},
		caseKey("INVALID_ARGUMENT", "STALE_CURSOR", ""): {
			"run_history",
			map[string]any{"runId": caseRunID, "cursor": "x"},
			plain(fmt.Errorf("%w: %w", ledger.ErrInvalidParams, errors.New("invalid cursor: missing id"))),
		},
		caseKey("INVALID_ARGUMENT", "SCOPE_FILTER", ""): {
			"preview_revert",
			map[string]any{"runId": caseRunID, "tables": []any{"public.ghost"}},
			plainFunc(func() error {
				return scopeRefused(action.Scope{Kind: "RUN", ID: uuid.MustParse(caseRunID)}, store.MapError(&pgconn.PgError{
					Code: "BS011", Message: "SCOPE_REFUSED", Detail: guardmodel.ScopeFilter, Hint: "public.ghost has no change of yours in this scope",
				}))
			}),
		},
		caseKey("INVALID_ARGUMENT", "SCOPE_FILTER_CAP", ""): {
			"request_revert",
			map[string]any{"taskId": caseRunID, "intent": "Undo", "tables": []any{"public.leads"}},
			plainFunc(ScopeFilterCapped),
		},

		caseKey("INVALID_ARGUMENT", "ADMIN_CREDENTIAL", ""): {"query", queryArgs0, plain(adminCredentialError())},

		caseKey("UNAVAILABLE", "DATABASE_UNREACHABLE", ""): {"query", queryArgs0, plain(context.DeadlineExceeded)},
		caseKey("UNAVAILABLE", "TOO_MANY_CONNECTIONS", ""): {"query", queryArgs0, pgFail("53300", `too many connections for role "basalt_agent_bot"`, "")},
		caseKey("UNAVAILABLE", "CREDENTIAL_REJECTED", ""):  {"query", queryArgs0, pgFail("28P01", "password authentication failed", "")},
		caseKey("UNAVAILABLE", "GUARD_MISSING", ""):        {"query", queryArgs0, pgFail("3F000", `schema "basalt_meta" does not exist`, "")},
		caseKey("UNAVAILABLE", "GUARD_OUTDATED", ""):       {"query", queryArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeUnavailable, Reason: guidance.ReasonGuardOutdated, Message: "the guard is outdated"})},
		caseKey("UNAVAILABLE", "ENGINE_UNREACHABLE", ""):   {"query", queryArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeUnavailable, Reason: guidance.ReasonEngineUnreachable, Message: "no engine"})},
		caseKey("UNAVAILABLE", "PAGES_OFF", ""):            {"write", writeArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeUnavailable, Reason: guidance.ReasonPagesOff, Message: "no pages"})},

		caseKey("UNAVAILABLE", "SETUP_PENDING", ""): {"query", queryArgs0, plain(&guidance.SetupError{Code: testSetupCode, Fingerprint: testFingerprint})},
		caseKey("UNAVAILABLE", "SETUP_EXPIRED", ""): {"query", queryArgs0, plain(&guidance.SetupError{Code: testSetupCode, Fingerprint: testFingerprint, Expired: true})},
		caseKey("UNAVAILABLE", "DATABASE_NOT_CONFIRMED", ""): {"query", queryArgs0, plain(&guidance.DatabaseNotConfirmedError{
			SetupID: caseSetupID, Database: caseDatabase,
		})},

		caseKey("INTERNAL", "", ""): {"query", queryArgs0, plain(errors.New("boom"))},
	}
	maps.Copy(cases, pluginCatalogCases())
	return cases
}

func plainFunc(f func() error) func(*testing.T, *Service) error {
	return func(*testing.T, *Service) error { return f() }
}

func withApproval(args map[string]any) map[string]any {
	out := make(map[string]any, len(args)+1)
	for k, v := range args {
		out[k] = v
	}
	out["approvalId"] = caseApproval
	return out
}

func catalogOf(t *testing.T) mcpcontract.NextSteps {
	t.Helper()
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	return c
}

func entryKey(e mcpcontract.ErrorSteps) string { return caseKey(e.Code, e.Reason, e.Tool) }

// TestEveryCatalogErrorHasACase walks the catalog: an error entry without a
// case fails, so a new code or reason cannot ship without guidance, and a
// case without an entry is stale.
func TestEveryCatalogErrorHasACase(t *testing.T) {
	t.Parallel()
	cases := catalogCases()
	seen := map[string]bool{}
	var missing []string
	for _, e := range catalogOf(t).Errors {
		seen[entryKey(e)] = true
		if _, ok := cases[entryKey(e)]; !ok {
			missing = append(missing, entryKey(e))
		}
	}
	require.Empty(t, missing, "catalog errors without a case in catalogCases")
	var stale []string
	for k := range cases {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	sort.Strings(stale)
	require.Empty(t, stale, "cases without a catalog entry")
}

// serviceFor builds the service the cases run on: configPath "" is the
// platform default config.
func serviceFor(t *testing.T, goos, configPath string, opts ...func(*Deps)) *Service {
	t.Helper()
	return operatedService(t, goos, configPath, "", opts...)
}

// serviceWith is a service over s's dependencies after edit changed them. The
// use cases copy what they read of the shared settings when they are built, so
// a test that needs other settings builds its service again.
func serviceWith(s *Service, edit func(*Deps)) *Service {
	d := s.deps
	edit(&d)
	return NewService(d)
}

// withoutLocalPages is an engine that serves no local pages.
func withoutLocalPages(d *Deps) { d.Core.PagesOrigin = "" }

// operatedService is serviceFor on an engine whose operatedBy is operatedBy.
func operatedService(t *testing.T, goos, configPath, operatedBy string, opts ...func(*Deps)) *Service {
	t.Helper()
	cmds, err := NewCommands("bot", configPath, goos, testManager())
	require.NoError(t, err)
	d := deps()
	d.Core.Commands = cmds
	d.Status.OperatedBy = operatedBy
	setApprovals(&d, catalogApprovals{})
	setReverts(&d, catalogReverts{})
	for _, opt := range opts {
		opt(&d)
	}
	return NewService(d)
}

func TestEveryCatalogErrorGivesTheCatalogsSteps(t *testing.T) {
	t.Parallel()
	for _, variant := range []struct {
		name, goos, config, operatedBy string
		initArgs                       []string
	}{
		{"default config", "linux", "", "", []string{"--agent=bot", "--write=public.leads"}},
		{"custom config", "darwin", "/srv/basalt/engine.json", "", []string{"--agent=bot", "--read=public.leads"}},
		{"agent-operated", "linux", "", mcpcontract.OperatedByAgent, []string{"--agent=bot", "--write=public.leads", "--os-user=bot", "--operated-by=agent"}},
		{"agent-operated custom config", "darwin", "/srv/basalt/engine.json", mcpcontract.OperatedByAgent, []string{"--agent=bot", "--read=public.leads", "--operated-by=agent"}},
	} {
		for key, kase := range catalogCases() {
			t.Run(variant.name+"/"+key, func(t *testing.T) {
				t.Parallel()
				s := operatedService(t, variant.goos, variant.config, variant.operatedBy)
				te := s.Failure(kase.tool, kase.args, kase.fail(t, s))
				requireObeysCatalog(t, kase, te, variant.operatedBy)
			})
		}
	}
}

// expectedSteps is what the catalog fixes for an entry with steps and
// personMessage on an engine operated by operatedBy: its agentOperated
// variant of kind on an agent-operated engine, if there is one, else its
// own steps with OPERATOR resolved (CONTRACT.md, Next steps on an
// agent-operated engine).
func expectedSteps(t *testing.T, kind, code, reason, tool string, steps []mcpcontract.StepKind, personMessage bool, operatedBy string) ([]mcpcontract.StepKind, bool, bool) {
	t.Helper()
	if operatedBy == mcpcontract.OperatedByAgent {
		if v, ok := catalogOf(t).AgentOperatedEntry(kind, code, reason, tool); ok {
			return v.Steps, v.PersonMessage, true
		}
	}
	return mcpcontract.Resolve(steps, operatedBy), personMessage, false
}

// requireOperatorRules checks the agent's commands on an engine operated by
// operatedBy: an AGENT command runs on the engine's machine and never needs
// the admin connection string (CO-9), so it is basalt init (with --remote
// exactly on an agent-operated engine) or, on an agent-operated engine, the
// engine's start; and a variant's personMessage names none of them.
func requireOperatorRules(t *testing.T, steps []toolresult.NextStep, personMessage string, variant bool, operatedBy, where string) {
	t.Helper()
	for _, st := range steps {
		if st.Actor != toolresult.ActorAgent || st.Action != toolresult.ActionRunCommand {
			continue
		}
		// basalt init prints the link the person opens and never takes the
		// admin connection string (CONTRACT.md, basalt init); on an
		// agent-operated engine it names --remote.
		if strings.HasPrefix(st.Command, "basalt init") {
			require.Regexp(t, initCommand, st.Command, where)
			require.Equal(t, operatedBy == mcpcontract.OperatedByAgent, strings.Contains(st.Command, " --remote"),
				"%s: --remote exactly on an agent-operated engine: %q", where, st.Command)
			continue
		}
		require.Equal(t, mcpcontract.OperatedByAgent, operatedBy, "%s: on a person-operated engine the agent runs only basalt init: %q", where, st.Command)
		machine := serviceManager.MatchString(st.Command) ||
			strings.HasPrefix(st.Command, "basalt engine ")
		require.True(t, machine, "%s: an AGENT command is basalt init, the engine's start or basalt plugin enable, disable or remove: %q", where, st.Command)
		if variant {
			require.NotContains(t, personMessage, st.Command, "%s: personMessage names no command on the agent's machine", where)
		}
	}
	if variant {
		require.NotContains(t, personMessage, "sudo ", where)
		require.NotContains(t, personMessage, "basalt engine", where)
	}
}

func requireObeysCatalog(t *testing.T, kase catalogCase, te *toolresult.ToolError, operatedBy string) {
	t.Helper()
	entry, ok := catalogOf(t).ErrorEntry(te.Code, te.Reason, kase.tool)
	require.True(t, ok, "no catalog entry for %s %s %s", te.Code, te.Reason, kase.tool)
	require.NotEmpty(t, te.Message, "the message stays")
	require.NotEmpty(t, te.NextSteps, "nextSteps is required")
	got := catalogKinds(te.NextSteps)
	want, pm, variant := expectedSteps(t, mcpcontract.VariantError, entry.Code, entry.Reason, entry.Tool, entry.Steps, entry.PersonMessage, operatedBy)
	require.Equal(t, want, got, "(actor, action) sequence of %s", entryKey(entry))
	require.Equal(t, pm, te.PersonMessage != "", "personMessage set exactly when the catalog says: %q", te.PersonMessage)
	requireOperatorRules(t, te.NextSteps, te.PersonMessage, variant, operatedBy, entryKey(entry))
	requirePersonMessage(t, te.PersonMessage, te.Links)
	for i, st := range te.NextSteps {
		requireStepObeysRules(t, st, kase, fmt.Sprintf("%s step %d", entryKey(entry), i+1))
	}
	if te.Code == guidance.CodeInternal || te.Code == guidance.CodeUnavailable {
		require.NotEmpty(t, te.ErrorID, "errorId on UNAVAILABLE and INTERNAL")
	}
	if te.Code == guidance.CodeRowLimitExceeded {
		require.Equal(t, guidance.MaxRetryRows, te.NextSteps[2].MaxRows)
		require.Contains(t, te.NextSteps[2].Text, "only on an explicit yes", "AE-7")
	}
}

var conditionalWords = regexp.MustCompile(`(?i)\b(if|unless|otherwise)\b`)

var secretPattern = regexp.MustCompile(`(?i)(://|#s=|secret|token|postgres)`)

func requireStepObeysRules(t *testing.T, st toolresult.NextStep, kase catalogCase, where string) {
	t.Helper()
	require.Contains(t, mcpcontract.ActorActions[st.Actor], st.Action, where)
	require.NotEmpty(t, st.Text, where)
	require.LessOrEqual(t, len([]rune(st.Text)), guidance.MaxStepTextLength, where)
	require.Empty(t, conditionalWords.FindString(st.Text), "%s: no conditional steps: %q", where, st.Text)
	require.Empty(t, removedCommand.FindString(st.Text+" "+st.Command), "%s: a step names no removed command: %q %q", where, st.Text, st.Command)
	require.Empty(t, secretPattern.FindString(st.Command), "%s: a command never carries a secret: %q", where, st.Command)
	require.NotContains(t, strings.ReplaceAll(strings.ToLower(st.Command), "--rotate-password", ""), "password", where)
	require.LessOrEqual(t, st.WaitSeconds, guidance.MaxWaitSeconds, where)

	switch st.Action {
	case toolresult.ActionCallTool, toolresult.ActionReviseCall:
		requireToolArguments(t, st, kase, where)
	case toolresult.ActionRetrySmallerBatches:
		require.Positive(t, st.MaxRows, where)
		require.LessOrEqual(t, st.MaxRows, guidance.MaxRetryRows, where)
	case toolresult.ActionRunCommand:
		requireCommand(t, st.Command, where)
	case toolresult.ActionOpenLink:
		require.NotEmpty(t, st.URL, where)
		if st.Command != "" {
			requireCommand(t, st.Command, where)
		}
	}
	if st.Action != toolresult.ActionRetrySmallerBatches {
		require.Zero(t, st.MaxRows, where)
	}
	if st.Action != toolresult.ActionRunCommand && st.Action != toolresult.ActionOpenLink {
		require.Empty(t, st.Command, where)
	}
	if st.Action != toolresult.ActionOpenLink {
		require.Empty(t, st.URL, where)
	}
}

// serviceManager is a root command on the engine's machine: the service
// manager, or giving a lock file back to the engine's user
// (LOCK_FILE_UNUSABLE).
var serviceManager = regexp.MustCompile(`^sudo (systemctl|launchctl|chown) `)

// initCommand is the agent's basalt init as a step names it.
var initCommand = regexp.MustCompile(`^basalt init --agent bot( --remote)?$`)

func requireCommand(t *testing.T, command, where string) {
	t.Helper()
	require.NotEmpty(t, command, where)
	if serviceManager.MatchString(command) {
		return
	}
	require.True(t, strings.HasPrefix(command, "basalt "), "%s: %q", where, command)
	if strings.HasPrefix(command, "basalt init") {
		// The one setup command (CONTRACT.md, Next steps): --agent, and
		// --remote on an agent-operated engine, never --config or a saved
		// flag.
		require.Regexp(t, initCommand, command, where)
		return
	}
	if strings.HasPrefix(command, "basalt engine ") { // the foreground engine names its config itself
		return
	}
	require.Fail(t, "a step names no other basalt command", "%s: %q", where, command)
}

func requireToolArguments(t *testing.T, st toolresult.NextStep, kase catalogCase, where string) {
	t.Helper()
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), st.Tool)
	require.True(t, ok, "%s: %q is not a contract tool", where, st.Tool)
	args := jsonMap(t, st.Arguments)
	if st.RepeatCall {
		require.Equal(t, kase.tool, st.Tool, "%s: a repeated call is a call of the same tool", where)
		merged := jsonMap(t, kase.args)
		for k, v := range args {
			if v == nil {
				delete(merged, k)
				continue
			}
			merged[k] = v
		}
		require.NoError(t, validateSchema(tool.InputSchema, merged), "%s: the repeated call's arguments", where)
		return
	}
	if st.Action == toolresult.ActionReviseCall {
		props, _ := tool.InputSchema["properties"].(map[string]any)
		for k := range args {
			require.Contains(t, props, k, "%s: %s has no argument %q", where, st.Tool, k)
		}
		return
	}
	if st.Tool == toolConfirmDatabase {
		// The one CALL_TOOL whose arguments are not complete (CONTRACT.md,
		// Next steps): the engine never fills in the person's answer.
		require.NotContains(t, args, argAnswer, "%s: the engine never fills in answer", where)
		args[argAnswer] = answerYes
	}
	require.NoError(t, validateSchema(tool.InputSchema, args), "%s: arguments of %s must validate against its inputSchema", where, st.Tool)
}

func jsonMap(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	out := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// validateSchema checks v against the subset of JSON Schema the tool input
// schemas use: type, required, properties, additionalProperties false, enum,
// minimum, minLength, maxLength, pattern, format uuid, items, maxItems, and
// oneOf (exactly one branch).
func validateSchema(schema map[string]any, v any) error {
	if branches, ok := schema["oneOf"].([]any); ok {
		matched := 0
		for _, b := range branches {
			if sub, ok := b.(map[string]any); ok && validateSchema(sub, v) == nil {
				matched++
			}
		}
		if matched != 1 {
			return fmt.Errorf("%v matches %d branches of oneOf, not one", v, matched)
		}
	}
	if types, ok := schemaTypes(schema["type"]); ok && !matchesAnyType(types, v) {
		return fmt.Errorf("%v is not of type %v", v, types)
	}
	if enum, ok := schema["enum"].([]any); ok && !containsValue(enum, v) {
		return fmt.Errorf("%v is not one of %v", v, enum)
	}
	switch x := v.(type) {
	case map[string]any:
		return validateObject(schema, x)
	case []any:
		return validateArray(schema, x)
	case string:
		return validateString(schema, x)
	case float64:
		if lower, ok := schema["minimum"].(float64); ok && x < lower {
			return fmt.Errorf("%v is below %v", x, lower)
		}
	}
	return nil
}

func validateObject(schema map[string]any, obj map[string]any) error {
	props, _ := schema["properties"].(map[string]any)
	if req, ok := schema["required"].([]any); ok {
		for _, r := range req {
			if _, present := obj[r.(string)]; !present {
				return fmt.Errorf("missing required argument %q", r)
			}
		}
	}
	for k, val := range obj {
		sub, known := props[k].(map[string]any)
		if !known {
			if schema["additionalProperties"] == false {
				return fmt.Errorf("unknown argument %q", k)
			}
			continue
		}
		if err := validateSchema(sub, val); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
	}
	return nil
}

func validateArray(schema map[string]any, arr []any) error {
	if most, ok := schema["maxItems"].(float64); ok && float64(len(arr)) > most {
		return fmt.Errorf("%d items, at most %v", len(arr), most)
	}
	items, ok := schema["items"].(map[string]any)
	if !ok {
		return nil
	}
	for _, it := range arr {
		if err := validateSchema(items, it); err != nil {
			return err
		}
	}
	return nil
}

var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validateString(schema map[string]any, s string) error {
	n := float64(len([]rune(s)))
	if least, ok := schema["minLength"].(float64); ok && n < least {
		return fmt.Errorf("%q is shorter than %v", s, least)
	}
	if most, ok := schema["maxLength"].(float64); ok && n > most {
		return fmt.Errorf("a string longer than %v", most)
	}
	if p, ok := schema["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(s) {
		return fmt.Errorf("%q does not match %s", s, p)
	}
	if schema["format"] == "uuid" && !uuidPattern.MatchString(s) {
		return fmt.Errorf("%q is not a uuid", s)
	}
	return nil
}

func schemaTypes(v any) ([]string, bool) {
	switch x := v.(type) {
	case string:
		return []string{x}, true
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, e.(string))
		}
		return out, true
	}
	return nil, false
}

func matchesAnyType(types []string, v any) bool {
	for _, t := range types {
		switch {
		case t == "object" && isKind[map[string]any](v), t == "array" && isKind[[]any](v), t == "string" && isKind[string](v),
			t == "boolean" && isKind[bool](v), t == "null" && v == nil:
			return true
		case t == "number" && isKind[float64](v):
			return true
		case t == "integer":
			if f, ok := v.(float64); ok && f == float64(int64(f)) {
				return true
			}
		}
	}
	return false
}

func isKind[T any](v any) bool { _, ok := v.(T); return ok }

func containsValue(list []any, v any) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

// TestStepRulesRefuseABadStep: the rules above are live, so a step that
// breaks one fails the table test.
func TestStepRulesRefuseABadStep(t *testing.T) {
	t.Parallel()
	require.Error(t, validateSchema(mcpcontract.MustLoad()[0].InputSchema, map[string]any{"nope": 1}))
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), "query")
	require.True(t, ok)
	require.Error(t, validateSchema(tool.InputSchema, map[string]any{}), "sql is required")
	require.NoError(t, validateSchema(tool.InputSchema, map[string]any{"sql": "SELECT 1", "params": []any{1.0, "a", nil}}))
	require.Error(t, validateSchema(tool.InputSchema, map[string]any{"sql": "SELECT 1", "runId": "x"}), "format uuid")
}

// A STALE_READ whose detail the engine cannot read still tells the agent what
// to do: stop and ask.
func TestStaleReadWithAnUnreadableDetailStopsAndAsks(t *testing.T) {
	t.Parallel()
	s := serviceFor(t, "linux", "")
	te := s.Failure("write", writeArgs0, store.MapError(&pgconn.PgError{Code: "BS004", Message: "STALE_READ", Detail: "something else"}))
	require.Equal(t, guidance.CodeStaleRead, te.Code)
	require.Len(t, te.NextSteps, 2)
	require.Equal(t, toolresult.ActionStop, te.NextSteps[0].Action)
	require.Equal(t, toolresult.ActionAskPerson, te.NextSteps[1].Action)
}

// A row too large for the connection's message cap is SIZE_LIMIT on the
// tools that declare QUERY_TIMEOUT, and the INTERNAL error of any other
// failed read elsewhere.
func TestMessageTooLargeIsSizeLimitOnlyWhereDeclared(t *testing.T) {
	t.Parallel()
	s := serviceFor(t, "linux", "")
	tooLarge := store.MapError(fmt.Errorf("read: %w", &pgproto3.ExceededMaxBodyLenErr{MaxExpectedBodyLen: 1, ActualBodyLen: 2}))
	for tool, want := range map[string]string{
		"query": guidance.CodeQueryTimeout, "write": guidance.CodeQueryTimeout, "describe": guidance.CodeQueryTimeout,
		"run_history": guidance.CodeQueryTimeout, "list_pending": guidance.CodeQueryTimeout, "revert_plan": guidance.CodeQueryTimeout,
		"list_runs": guidance.CodeInternal, "status": guidance.CodeInternal,
	} {
		te := s.Failure(tool, nil, tooLarge)
		require.Equal(t, want, te.Code, tool)
		if want == guidance.CodeQueryTimeout {
			require.Equal(t, guidance.ReasonSizeLimit, te.Reason, tool)
		}
	}
}

// One row over the budget alone is ROW_TOO_LARGE for the tools whose own
// statement it refuses (query, a write's RETURNING), naming the columns,
// and SIZE_LIMIT for any other tool.
func TestRowTooLargeOnlyForTheAgentsOwnStatement(t *testing.T) {
	t.Parallel()
	s := serviceFor(t, "linux", "")
	row := fmt.Errorf("read: %w", &resultsize.RowTooLargeError{Bytes: 20 << 20, Columns: []resultsize.ColumnSize{{Name: "body", Bytes: 20 << 20}}})
	for tool, want := range map[string]string{
		"query": guidance.ReasonRowTooLarge, "write": guidance.ReasonRowTooLarge,
		"run_history": guidance.ReasonSizeLimit, "describe": guidance.ReasonSizeLimit, "preview_revert": guidance.ReasonSizeLimit,
	} {
		te := s.Failure(tool, nil, row)
		require.Equal(t, guidance.CodeQueryTimeout, te.Code, tool)
		require.Equal(t, want, te.Reason, tool)
		if want == guidance.ReasonRowTooLarge {
			require.Contains(t, te.Message, "body (20.0 MiB)", tool)
			require.Contains(t, te.Message, "substr(col, 1, 100000)", tool)
		}
	}
}

// PERMISSION_DENIED hands the grant to the setup page: the agent's basalt
// init, whatever table Postgres named, and a message that names the table
// but no command.
func TestPermissionDeniedHandsTheGrantToTheSetupPage(t *testing.T) {
	t.Parallel()
	s := serviceFor(t, "linux", "")
	for message, table := range map[string]string{
		"permission denied for table public.events": "public·events",
		"permission denied for table events":        "events",
		`permission denied for table "a,b"`:         `"a,b"`,
	} {
		te := s.Failure("query", queryArgs0, store.MapError(&pgconn.PgError{Code: "42501", Message: message}))
		last := te.NextSteps[len(te.NextSteps)-1]
		require.Equal(t, toolresult.ActorAgent, last.Actor, message)
		require.Equal(t, "basalt init --agent bot", last.Command, message)
		require.Contains(t, te.PersonMessage, "read access to "+table, message)
		require.NotContains(t, te.PersonMessage, "basalt ", "the person runs no command")
		requirePersonMessage(t, te.PersonMessage, te.Links)
	}
}
