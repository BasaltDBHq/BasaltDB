package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	revertsvc "github.com/basaltdbhq/basaltdb/internal/revert"

	"github.com/basaltdbhq/basaltdb/internal/testkit/stepcatalogtest"

	linksvc "github.com/basaltdbhq/basaltdb/internal/links"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/budget"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"
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

// step is the tool call the case answers, for the shared catalog checks.
func (c catalogCase) step() stepcatalogtest.Case {
	return stepcatalogtest.Case{Tool: c.tool, Args: c.args}
}

// catalogReverts and catalogApprovals are the stores the cases need: the
// failure is raised by the test, so only the lookups the engine makes while
// building steps answer.
type catalogReverts struct {
	revertsvc.Store
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

func caseNotice(url string) toolresult.ApprovalNotice {
	return toolresult.ApprovalNotice{
		ApprovalID: caseApproval, ExpiresAt: "2026-11-12T10:00:00Z", Rows: 3,
		Headline: "Delete 3 rows in public.leads", ApprovalURL: url,
		PersonMessage: "Held for your approval: Delete 3 rows in public.leads.\nApprove it with your passkey here:\n\n" + url + "\n\nExpires 2026-11-12 10:00 UTC.",
		Links:         []toolresult.Link{{Label: linksvc.LabelApprove, URL: url}},
	}
}

const caseShortLink = "http://localhost:7878/approvals/" + caseApproval + "#s=AAAAAAAAAAAAAAAAAAAAAA"

func approvalLink(reason string) func(*testing.T, *Service) error {
	return func(_ *testing.T, s *Service) error {
		n := linksvc.HeldAnswer{ApprovalNotice: caseNotice(caseShortLink), LongURL: caseShortLink, Pick: linksvc.HandOver{URL: caseShortLink, Kind: linksvc.LinkLong}}
		return s.ApprovalLinkError(&toolresult.ToolError{Code: guidance.CodeApprovalInvalid, Reason: reason, Message: "m"}, n)
	}
}

// catalogCases has one case per error entry of the catalog. A new code or
// reason needs its case here or TestEveryCatalogErrorHasACase fails.
func catalogCases() map[string]catalogCase {
	cases := map[string]catalogCase{
		stepcatalogtest.CaseKey("INTENT_REQUIRED", "", ""): {"write", map[string]any{"sql": "DELETE FROM leads WHERE id = 1"}, pgFail("BS001", "INTENT_REQUIRED", "")},
		stepcatalogtest.CaseKey("STALE_READ", "", ""): {
			"write", writeArgs0,
			pgFail("BS004", "STALE_READ", staleText("public.leads", `{"id": 42}`)),
		},

		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "PARSE_ERROR", ""):           {"query", queryArgs0, refusal(action.ReasonParseError)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "MULTIPLE_STATEMENTS", ""):   {"query", queryArgs0, refusal(action.ReasonMultipleStatements)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "WRONG_TOOL", ""):            {"query", queryArgs0, refusal(action.ReasonWrongTool)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "DDL_NOT_ALLOWED", ""):       {"write", writeArgs0, refusal(action.ReasonDDL)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "STATEMENT_NOT_ALLOWED", ""): {"write", writeArgs0, refusal(action.ReasonUtility)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "SELECT_INTO", ""):           {"query", queryArgs0, refusal(action.ReasonSelectInto)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "LOCKING_READ", ""):          {"query", queryArgs0, refusal(action.ReasonLockingRead)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "MERGE_NOT_ALLOWED", ""):     {"write", writeArgs0, refusal(action.ReasonMerge)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "DATA_MODIFYING_WITH", ""):   {"query", queryArgs0, refusal(action.ReasonDataModifyingWith)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "FUNCTION_NOT_ALLOWED", ""):  {"query", queryArgs0, refusal(action.ReasonFunction)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "NOT_REPEATABLE", ""):        {"write", writeArgs0, refusal(action.ReasonNotRepeatable)},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "NO_PRIMARY_KEY", ""): {
			"write", writeArgs0,
			pgFail("BS007", "NOT_ALLOWED", "table public.events has no primary key; the guard keys ledger rows by it"),
		},
		stepcatalogtest.CaseKey("STATEMENT_REFUSED", "NOT_ALLOWED", ""): {"write", writeArgs0, pgFail("BS007", "NOT_ALLOWED", "TRUNCATE by an agent")},

		stepcatalogtest.CaseKey("ROW_LIMIT_EXCEEDED", "", ""): {
			"write", writeArgs0,
			pgFail("BS003", "ROW_LIMIT_EXCEEDED", "more than 50 rows in one action (cascades included)"),
		},

		stepcatalogtest.CaseKey("QUERY_TIMEOUT", "ROW_LIMIT", ""):  {"query", queryArgs0, plain(action.ErrRowLimit)},
		stepcatalogtest.CaseKey("QUERY_TIMEOUT", "SIZE_LIMIT", ""): {"query", queryArgs0, plain(budget.ErrSizeLimit)},
		stepcatalogtest.CaseKey("QUERY_TIMEOUT", "ROW_TOO_LARGE", ""): {
			"query", queryArgs0,
			plain(&resultsize.RowTooLargeError{Bytes: 20 << 20, Columns: []resultsize.ColumnSize{{Name: "body", Bytes: 20 << 20}}}),
		},
		stepcatalogtest.CaseKey("QUERY_TIMEOUT", "TIME_LIMIT", ""): {"query", queryArgs0, pgFail("57014", "canceling statement due to statement timeout", "")},

		stepcatalogtest.CaseKey("QUERY_TIMEOUT", "REQUEST_TOO_LARGE", "request_revert"): {
			"request_revert",
			map[string]any{"runId": caseRunID, "intent": "Undo"},
			func(t *testing.T, s *Service) error {
				return s.delivery.RevertTooLargeError(uuid.MustParse(caseRevertID), 2<<20, time.Now().Add(time.Hour))
			},
		},

		stepcatalogtest.CaseKey("APPROVAL_EXPIRED", "", ""): {"write", withApproval(writeArgs0), asToolError(&toolresult.ToolError{Code: guidance.CodeApprovalExpired, Message: "approval expired"})},

		stepcatalogtest.CaseKey("APPROVAL_INVALID", "NOT_SIGNED", ""):      {"write", withApproval(writeArgs0), approvalLink(guidance.ReasonNotSigned)},
		stepcatalogtest.CaseKey("APPROVAL_INVALID", "BAD_SIGNATURE", ""):   {"write", withApproval(writeArgs0), approvalLink(guidance.ReasonBadSignature)},
		stepcatalogtest.CaseKey("APPROVAL_INVALID", "PASSKEY_REVOKED", ""): {"write", withApproval(writeArgs0), approvalLink(guidance.ReasonPasskeyRevoked)},

		stepcatalogtest.CaseKey("PERMISSION_DENIED", "", ""): {"query", queryArgs0, pgFail("42501", "permission denied for table events", "")},

		stepcatalogtest.CaseKey("NOT_FOUND", "RUN", ""):        {"query", queryArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "RUN", Message: "no such run"})},
		stepcatalogtest.CaseKey("NOT_FOUND", "CHANGE", ""):     {"request_revert", map[string]any{"changeId": caseChangeID, "intent": "Undo", "runId": caseRunID}, asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "CHANGE", Message: "no such change"})},
		stepcatalogtest.CaseKey("NOT_FOUND", "APPROVAL", ""):   {"write", withApproval(writeArgs0), asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "APPROVAL", Message: "no such approval"})},
		stepcatalogtest.CaseKey("NOT_FOUND", "LINK", ""):       {"approval_page", nil, asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "LINK", Message: "no such link"})},
		stepcatalogtest.CaseKey("NOT_FOUND", "LINK_RESET", ""): {"revert_page", nil, asToolError(&toolresult.ToolError{Code: guidance.CodeNotFound, Reason: "LINK_RESET", Message: "the link was reset"})},
		stepcatalogtest.CaseKey("APPROVAL_INVALID", "REVEAL_REFUSED", ""): {"approval_page", nil, func(*testing.T, *Service) error {
			return linksvc.RevealRefused(guidance.CodeApprovalInvalid, "http://localhost:8787/approvals/0193a3f0-0000-7000-8000-000000000001#s=AAECAwQFBgcICQoLDA0ODw")
		}},
		stepcatalogtest.CaseKey("REVERT_INVALID", "REVEAL_REFUSED", ""): {"revert_page", nil, func(*testing.T, *Service) error {
			return linksvc.RevealRefused(guidance.CodeRevertInvalid, "http://localhost:8787/reverts/0193a3f0-0000-7000-8000-000000000001#s=AAECAwQFBgcICQoLDA0ODw")
		}},
		stepcatalogtest.CaseKey("NOT_FOUND", "", "describe"): {
			"describe",
			map[string]any{"resource": "billing.invoices"},
			plainFunc(func() error {
				_, err := describeUseCase(guidance.Commands{}, &fakeCatalog{}).DescribeResource(context.Background(), "billing.invoices", "")
				return err
			}),
		},

		stepcatalogtest.CaseKey("SQL_ERROR", "", ""):            {"write", writeArgs0, pgFail("42703", `column "x" does not exist`, "")},
		stepcatalogtest.CaseKey("SQL_ERROR", "NO_ROWS_NOW", ""): {"write", writeArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeSQLError, Reason: guidance.ReasonNoRowsNow, Message: "changes no rows now"})},
		stepcatalogtest.CaseKey("INVALID_ARGUMENT", "", ""):     {"write", writeArgs0, plain(&guidance.ArgumentError{Message: "invalid arguments"})},
		stepcatalogtest.CaseKey("INVALID_ARGUMENT", "STALE_CURSOR", ""): {
			"run_history",
			map[string]any{"runId": caseRunID, "cursor": "x"},
			plain(fmt.Errorf("%w: %w", ledger.ErrInvalidParams, errors.New("invalid cursor: missing id"))),
		},

		stepcatalogtest.CaseKey("INVALID_ARGUMENT", "SCOPE_FILTER", ""): {
			"preview_revert",
			map[string]any{"runId": caseRunID, "tables": []any{"public.ghost"}},
			plain(&guidance.ArgumentError{Reason: guidance.ReasonScopeFilter, Message: "the revert filter names work that is not yours, nothing was prepared: public.ghost has no change of yours in this scope. runs lists only your own runs in the task, and tables only tables you wrote in this scope; run_history shows them"}),
		},
		stepcatalogtest.CaseKey("INVALID_ARGUMENT", "SCOPE_FILTER_CAP", ""): {
			"request_revert",
			map[string]any{"taskId": caseRunID, "intent": "Undo", "tables": []any{"public.leads"}},
			plainFunc(revertsvc.ScopeFilterCapped),
		},
		stepcatalogtest.CaseKey("INVALID_ARGUMENT", "ADMIN_CREDENTIAL", ""): {"query", queryArgs0, plain(mcpserver.AdminCredentialError())},

		stepcatalogtest.CaseKey("UNAVAILABLE", "DATABASE_UNREACHABLE", ""): {"query", queryArgs0, plain(context.DeadlineExceeded)},
		stepcatalogtest.CaseKey("UNAVAILABLE", "TOO_MANY_CONNECTIONS", ""): {"query", queryArgs0, pgFail("53300", `too many connections for role "basalt_agent_bot"`, "")},
		stepcatalogtest.CaseKey("UNAVAILABLE", "CREDENTIAL_REJECTED", ""):  {"query", queryArgs0, pgFail("28P01", "password authentication failed", "")},
		stepcatalogtest.CaseKey("UNAVAILABLE", "GUARD_MISSING", ""):        {"query", queryArgs0, pgFail("3F000", `schema "basalt_meta" does not exist`, "")},
		stepcatalogtest.CaseKey("UNAVAILABLE", "GUARD_OUTDATED", ""):       {"query", queryArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeUnavailable, Reason: guidance.ReasonGuardOutdated, Message: "the guard is outdated"})},
		stepcatalogtest.CaseKey("UNAVAILABLE", "ENGINE_UNREACHABLE", ""):   {"query", queryArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeUnavailable, Reason: guidance.ReasonEngineUnreachable, Message: "no engine"})},
		stepcatalogtest.CaseKey("UNAVAILABLE", "PAGES_OFF", ""):            {"write", writeArgs0, asToolError(&toolresult.ToolError{Code: guidance.CodeUnavailable, Reason: guidance.ReasonPagesOff, Message: "no pages"})},

		stepcatalogtest.CaseKey("UNAVAILABLE", "SETUP_PENDING", ""): {"query", queryArgs0, plain(&guidance.SetupError{Code: testSetupCode, Fingerprint: testFingerprint})},
		stepcatalogtest.CaseKey("UNAVAILABLE", "SETUP_EXPIRED", ""): {"query", queryArgs0, plain(&guidance.SetupError{Code: testSetupCode, Fingerprint: testFingerprint, Expired: true})},
		stepcatalogtest.CaseKey("UNAVAILABLE", "DATABASE_NOT_CONFIRMED", ""): {"query", queryArgs0, plain(&guidance.DatabaseNotConfirmedError{
			SetupID: caseSetupID, Database: caseDatabase,
		})},

		stepcatalogtest.CaseKey("INTERNAL", "", ""): {"query", queryArgs0, plain(errors.New("boom"))},
	}
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

// TestEveryCatalogErrorHasACase walks the catalog: an error entry without a
// case fails, so a new code or reason cannot ship without guidance, and a
// case without an entry is stale.
func TestEveryCatalogErrorHasACase(t *testing.T) {
	t.Parallel()
	cases := catalogCases()
	seen := map[string]bool{}
	var missing []string
	for _, e := range stepcatalogtest.CatalogOf(t).Errors {
		seen[stepcatalogtest.EntryKey(e)] = true
		if _, ok := cases[stepcatalogtest.EntryKey(e)]; !ok && !slices.Contains(stepcatalogtest.RevertErrorKeys(), stepcatalogtest.EntryKey(e)) && !slices.Contains(stepcatalogtest.ApprovalErrorKeys(), stepcatalogtest.EntryKey(e)) && !slices.Contains(stepcatalogtest.PluginErrorKeys(), stepcatalogtest.EntryKey(e)) {
			missing = append(missing, stepcatalogtest.EntryKey(e))
		}
	}
	require.Empty(t, missing, "catalog errors without a case in catalogCases or in the revert, approval or plugin package's")
	for _, k := range slices.Concat(stepcatalogtest.RevertErrorKeys(), stepcatalogtest.ApprovalErrorKeys(), stepcatalogtest.PluginErrorKeys()) {
		require.NotContains(t, cases, k, "a revert, approval or plugin error case runs in its own package only")
	}
	var stale []string
	for k := range cases {
		if !seen[k] {
			stale = append(stale, k)
		}
	}
	slices.Sort(stale)
	require.Empty(t, stale, "cases without a catalog entry")
}

// serviceFor builds the service the cases run on: configPath "" is the
// platform default config.
func serviceFor(t *testing.T, goos, configPath string, opts ...func(*Deps)) *Service {
	t.Helper()
	return operatedService(t, goos, configPath, "", opts...)
}

// operatedService is serviceFor on an engine whose operatedBy is operatedBy.
func operatedService(t *testing.T, goos, configPath, operatedBy string, opts ...func(*Deps)) *Service {
	t.Helper()
	cmds, err := newCommands("bot", configPath, goos, testManager())
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
				stepcatalogtest.RequireObeysCatalog(t, kase.step(), te, variant.operatedBy)
			})
		}
	}
}

// TestStepRulesRefuseABadStep: the rules above are live, so a step that
// breaks one fails the table test.
func TestStepRulesRefuseABadStep(t *testing.T) {
	t.Parallel()
	require.Error(t, stepcatalogtest.ValidateSchema(mcpcontract.MustLoad()[0].InputSchema, map[string]any{"nope": 1}))
	tool, ok := mcpcontract.Find(mcpcontract.MustLoad(), "query")
	require.True(t, ok)
	require.Error(t, stepcatalogtest.ValidateSchema(tool.InputSchema, map[string]any{}), "sql is required")
	require.NoError(t, stepcatalogtest.ValidateSchema(tool.InputSchema, map[string]any{"sql": "SELECT 1", "params": []any{1.0, "a", nil}}))
	require.Error(t, stepcatalogtest.ValidateSchema(tool.InputSchema, map[string]any{"sql": "SELECT 1", "runId": "x"}), "format uuid")
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
		stepcatalogtest.RequirePersonMessage(t, te.PersonMessage, te.Links)
	}
}
