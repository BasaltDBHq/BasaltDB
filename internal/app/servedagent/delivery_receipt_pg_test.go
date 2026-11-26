package servedagent_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/channel"
	"github.com/basaltdbhq/basaltdb/internal/core/channel/channeltest"
	"github.com/basaltdbhq/basaltdb/internal/core/links/linkstest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// verifiedReceipt checks token against the engine's key, which the test
// holds apart from the receipt, as the person's check in the chat does.
func verifiedReceipt(t *testing.T, env agentEnv, token any) channel.Receipt {
	t.Helper()
	s, ok := token.(string)
	require.True(t, ok, "a receipt: %v", token)
	r, err := channeltest.VerifyReceipt(s, env.keys.PublicKeySPKI())
	require.NoError(t, err)
	return r
}

// heldApproval holds a write of leads first to last and returns the write's
// arguments, its approval id and its short link's secret.
func heldApproval(t *testing.T, env agentEnv, first, last int) (map[string]any, string, string) {
	t.Helper()
	args := holdWrite(t, env.h, nil)
	args["params"] = []any{"closed", first, last}
	body, isError := env.h.call(t, "write", args)
	requireToolError(t, body, isError, "APPROVAL_REQUIRED", "", "")
	ap := approvalOf(t, body)
	return args, str(t, ap["approvalId"]), linkstest.SecretOf(str(t, ap["approvalUrl"]))
}

// postgresBinding is the approval's binding as Postgres holds it, read
// with the admin connection apart from the engine.
func postgresBinding(t *testing.T, env agentEnv, id string) approval.Binding {
	t.Helper()
	var text string
	require.NoError(t, env.d.Admin.QueryRow(context.Background(), `SELECT binding_text FROM basalt_meta.approvals WHERE approval_id = $1`, id).Scan(&text))
	b, err := approval.ParseBinding(text)
	require.NoError(t, err)
	return b
}

func requireApprovalReceipt(t *testing.T, env agentEnv, r channel.Receipt, id string, rows int) {
	t.Helper()
	require.Equal(t, channel.ReceiptApproval, r.Kind)
	require.Equal(t, id, r.ItemID)
	require.Equal(t, channel.ReceiptApproved, r.Status)
	require.Equal(t, fmt.Sprintf("Update %d rows in public.leads", rows), r.Headline)
	require.Equal(t, postgresBinding(t, env, id).RowsHash, r.RowsHash, "the rows the passkey signed, from Postgres")
	require.Equal(t, "agent:bot", r.Agent)
	require.Equal(t, env.keys.EngineID(), r.EngineID)
	require.Empty(t, r.ChangeID)
}

// After an approval is relayed, the page's answer and the write's result
// carry a receipt whose item, headline, rows and status are Postgres's,
// verified against the engine's key; the personMessage shows its line.
func TestApprovalReceipt(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)

	args, id, secret := heldApproval(t, env, 21, 35)
	var ok map[string]any
	require.Equal(t, http.StatusOK, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, secret, p.signApproval(id, secret, env.person), &ok))
	requireApprovalReceipt(t, env, verifiedReceipt(t, env, ok["receipt"]), id, 15)
	require.NotContains(t, ok, "noReceipt")

	args["approvalId"] = id
	body, isError := env.h.call(t, "write", args)
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])
	requireApprovalReceipt(t, env, verifiedReceipt(t, env, body["receipt"]), id, 15)
	msg := str(t, body["personMessage"])
	require.Equal(t, "Approved: Update 15 rows in public·leads (approval "+id+"), receipt from engine "+env.keys.Fingerprint()+".", msg)
	mcptest.Require(t, msg, nil)
}

// A page that sends another item's binding is refused by Postgres and no
// receipt is made; a page that has the person sign item B while showing A
// gets a receipt naming B, so the swap shows in the chat.
func TestApprovalReceiptNamesWhatWasSigned(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)

	_, a, secretA := heldApproval(t, env, 21, 35)
	_, b, secretB := heldApproval(t, env, 41, 52)

	// B's signature presented as A's: Postgres refuses it, no receipt.
	signedB := p.signApproval(b, secretB, env.person)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(signedB, &resp))
	resp["approvalId"] = a
	asA, err := json.Marshal(resp)
	require.NoError(t, err)
	var perr pageError
	require.Equal(t, http.StatusConflict, p.post("/api/v1/approvals/"+a+"/approve", pageOrigin, secretA, asA, &perr))
	require.Equal(t, "APPROVAL_INVALID", perr.Code)

	// The page showed A but had the person sign B: the receipt names B.
	var ok map[string]any
	require.Equal(t, http.StatusOK, p.post("/api/v1/approvals/"+b+"/approve", pageOrigin, secretB, signedB, &ok))
	r := verifiedReceipt(t, env, ok["receipt"])
	require.Equal(t, b, r.ItemID)
	require.Equal(t, "Update 12 rows in public.leads", r.Headline)
	require.NotEqual(t, postgresBinding(t, env, a).RowsHash, r.RowsHash)
}

// With the engine key file refused (KEY_ERROR) the approval still applies;
// the answers carry no receipt and say why.
func TestApprovalWithoutReceiptOnKeyError(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessKeys(t, d, d.NewAgent(t, "bot", leads, leads), nil, pageOrigin)
	p := newLocalPages(t, env)

	args, id, secret := heldApproval(t, env, 21, 35)
	var ok map[string]any
	require.Equal(t, http.StatusOK, p.post("/api/v1/approvals/"+id+"/approve", pageOrigin, secret, p.signApproval(id, secret, env.person), &ok))
	require.Equal(t, map[string]any{"approvalId": id, "status": "APPROVED", "noReceipt": "KEY_ERROR"}, ok)

	args["approvalId"] = id
	body, isError := env.h.call(t, "write", args)
	require.False(t, isError, "%v", body)
	require.Equal(t, "APPLIED", body["status"])
	require.Equal(t, "closed", leadStatus(t, d, 21), "the approval applies all the same")
	require.NotContains(t, body, "receipt")
	require.Equal(t, "KEY_ERROR", body["noReceipt"])
	require.Equal(t, "No receipt: the engine's key file is refused (Basalt's status reports KEY_ERROR), so nothing confirms what was signed.", body["personMessage"])
}

func requireRevertReceipt(t *testing.T, env agentEnv, r channel.Receipt, id, changeID string) {
	t.Helper()
	var text string
	require.NoError(t, env.d.Admin.QueryRow(context.Background(), `SELECT binding_text FROM basalt_meta.reverts WHERE revert_id = $1`, id).Scan(&text))
	b, err := revert.ParseBinding(text)
	require.NoError(t, err)
	require.Equal(t, channel.ReceiptRevert, r.Kind)
	require.Equal(t, id, r.ItemID)
	require.Equal(t, channel.ReceiptApplied, r.Status)
	require.Equal(t, b.RowsHash, r.RowsHash, "the rows the passkey signed, from Postgres")
	require.True(t, strings.HasPrefix(r.Headline, "Revert of run "), r.Headline)
	require.Equal(t, "agent:bot", r.Agent)
	require.Equal(t, env.keys.EngineID(), r.EngineID)
	require.Equal(t, changeID, r.ChangeID)
}

// After a revert is relayed, the page's answer and request_revert's result
// carry a receipt from the store's record, with the revert's change.
func TestRevertReceipt(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)

	runID, _ := winLeads(t, env.h, "87, 88")
	req := requestRevert(t, env.h, map[string]any{"runId": runID, "intent": "Undo"})
	id, secret := str(t, req["revertId"]), linkstest.SecretOf(str(t, req["revertUrl"]))
	var rreq revert.Request
	require.Equal(t, http.StatusOK, p.get("/api/v1/reverts/"+id, secret, &rreq))
	b, err := rreq.Check()
	require.NoError(t, err)
	signed, err := json.Marshal(reverttest.NewResponse(b.RevertID, signBinding(t, env.person, rreq.Binding)))
	require.NoError(t, err)
	var out map[string]any
	require.Equal(t, http.StatusOK, p.post("/api/v1/reverts/"+id+"/apply", pageOrigin, secret, signed, &out))
	changeID := str(t, out["changeId"])
	requireRevertReceipt(t, env, verifiedReceipt(t, env, out["receipt"]), id, changeID)

	body := requestRevert(t, env.h, map[string]any{"revertId": id, "waitForSignature": 0})
	require.Equal(t, "APPLIED", body["status"])
	requireRevertReceipt(t, env, verifiedReceipt(t, env, body["receipt"]), id, changeID)
	msg := str(t, body["personMessage"])
	line, rest, found := strings.Cut(msg, "\n")
	require.True(t, found, msg)
	require.True(t, strings.HasPrefix(line, "Signed: Revert of run "+runID), line)
	require.True(t, strings.HasSuffix(line, "(revert "+id+"), receipt from engine "+env.keys.Fingerprint()+"."), line)
	require.True(t, strings.HasPrefix(rest, "Reverted: "), rest)
	mcptest.Require(t, msg, nil)
}

// A revert the page signed: the agent's wait returns the receipt.
func TestRevertReceiptForAPageSignature(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	runID, _ := winLeads(t, env.h, "87, 88")
	req := requestRevert(t, env.h, map[string]any{"runId": runID, "intent": "Undo"})
	personSigns(t, env, str(t, req["revertUrl"]))
	body := requestRevert(t, env.h, map[string]any{"revertId": req["revertId"], "waitForSignature": 0})
	require.Equal(t, "APPLIED", body["status"])
	requireRevertReceipt(t, env, verifiedReceipt(t, env, body["receipt"]), str(t, req["revertId"]), str(t, body["changeId"]))
}
