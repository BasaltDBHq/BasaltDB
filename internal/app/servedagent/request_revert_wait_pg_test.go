package servedagent_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/testkit/agenttest"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/action"
	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/links/linkstest"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
	"github.com/basaltdbhq/basaltdb/internal/core/revert"
	"github.com/basaltdbhq/basaltdb/internal/core/revert/reverttest"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver/mcptest"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard"
	"github.com/basaltdbhq/basaltdb/internal/platform/postgres/guard/guardtest"
)

// testPoll is how often a waiting call reads the person's signature in
// tests, so a signature lands well inside the wait.
const testPoll = 20 * time.Millisecond

// signRevertPage is the revert page on the local pages: read the request
// for id with the link's secret, check it and sign it with the person's
// passkey; it returns the response JSON the page posts to the relay.
func (p localPages) signRevertPage(id, secret string, person *passkeytest.Authenticator) []byte {
	p.t.Helper()
	var req revert.Request
	require.Equal(p.t, http.StatusOK, p.get("/api/v1/reverts/"+id, secret, &req))
	b, err := req.Check()
	require.NoError(p.t, err)
	as, err := person.Sign(approval.Challenge(req.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(p.t, err)
	body, err := json.Marshal(reverttest.NewResponse(b.RevertID, as))
	require.NoError(p.t, err)
	return body
}

// relayLater posts the page's signed response to the relay once after
// returns (nil: at once), while the agent waits, and sends the HTTP status
// (0 when the request failed).
func (p localPages) relayLater(id, secret string, body []byte, after func()) <-chan int {
	done := make(chan int, 1)
	go func() {
		if after != nil {
			after()
		}
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
			p.srv.URL+"/api/v1/reverts/"+id+"/apply", bytes.NewReader(body))
		if err != nil {
			done <- 0
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", pageOrigin)
		req.Header.Set(links.SecretHeader, secret)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- 0
			return
		}
		_ = resp.Body.Close()
		done <- resp.StatusCode
	}()
	return done
}

// requestRevert asks for a revert through MCP and returns the result.
func requestRevert(t *testing.T, h harness, args map[string]any) map[string]any {
	t.Helper()
	body, isError := h.call(t, "request_revert", args)
	require.False(t, isError, "%v", body)
	return body
}

// longLinkBinding is what the revert page reads from a long link: the
// revert's id and the binding the person signs.
func longLinkBinding(t *testing.T, link string) (uuid.UUID, string) {
	t.Helper()
	req, b, err := reverttest.ParseRequest(link[strings.Index(link, "#")+1:])
	require.NoError(t, err)
	return b.RevertID, req.Binding
}

func signBinding(t *testing.T, signer *passkeytest.Authenticator, binding string) passkey.Assertion {
	t.Helper()
	as, err := signer.Sign(approval.Challenge(binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	return as
}

// relayRevert is what the revert page does after the passkey signed: it
// posts the signature, which the engine relays to Postgres (RelayRevert),
// on its own pages or through the Vault. Nothing is pasted.
func relayRevert(svc *app.Service, id uuid.UUID, as passkey.Assertion) error {
	_, _, err := svc.RelayRevert(context.Background(), reverttest.NewResponse(id, as))
	return err
}

// personSigns is the person signing the revert behind link on its page, and
// the page relaying the signature.
func personSigns(t *testing.T, env agentEnv, link string) {
	t.Helper()
	id, binding := longLinkBinding(t, link)
	require.NoError(t, relayRevert(env.svc, id, signBinding(t, env.person, binding)))
}

func revertStatus(t *testing.T, h harness, id string) string {
	t.Helper()
	return str(t, requestRevert(t, h, map[string]any{"revertId": id, "waitForSignature": 0})["status"])
}

func expireRevert(t *testing.T, env agentEnv, id string) {
	t.Helper()
	env.d.Exec(t, `UPDATE basalt_meta.reverts SET expires_at = now() - interval '1 second' WHERE revert_id = $1`, id)
}

// maxStepText is the longest a step's text may be (next-step.schema.json).
const maxStepText = 200

// requireSteps checks body's nextSteps have exactly the actors and actions
// of the catalog entry, each with its text, and personMessage when the
// entry sets it. It returns the steps.
func requireSteps(t *testing.T, body map[string]any, want []mcpcontract.StepKind, personMessage bool) []map[string]any {
	t.Helper()
	raw, ok := body["nextSteps"].([]any)
	require.True(t, ok, "nextSteps: %v", body)
	steps := make([]map[string]any, 0, len(raw))
	got := make([]mcpcontract.StepKind, 0, len(raw))
	for _, r := range raw {
		step, ok := r.(map[string]any)
		require.True(t, ok, "%v", r)
		text := str(t, step["text"])
		require.NotEmpty(t, text)
		require.LessOrEqual(t, len(text), maxStepText, text)
		steps = append(steps, step)
		if len(steps) == 1 && step["action"] == toolresult.ActionSendRequest {
			// Not in the catalog's sequences: first exactly when the result
			// carries requestFile (CONTRACT.md, Next steps).
			require.Contains(t, body, "requestFile", "%v", body)
			continue
		}
		got = append(got, mcpcontract.StepKind{Actor: str(t, step["actor"]), Action: str(t, step["action"])})
	}
	require.Equal(t, want, got, "%v", body)
	if personMessage {
		require.NotEmpty(t, body["personMessage"], "%v", body)
	}
	return steps
}

// requireResultSteps checks a request_revert result against its catalog
// case (api/mcp/errors/next-steps.json).
func requireResultSteps(t *testing.T, body map[string]any, kase string) []map[string]any {
	t.Helper()
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	// A request that handed over a long or hash link (no local pages, no
	// live Vault connection) cannot be signed: its own case.
	if link, _ := body["revertUrl"].(string); kase == "REQUESTED" && (strings.Contains(link, "#2.") || strings.Contains(link, "#h=")) {
		kase = "REQUESTED_NO_PAGES"
	}
	for _, r := range c.Results {
		if r.Tool == "request_revert" && r.Case == kase {
			return requireSteps(t, body, r.Steps, r.PersonMessage)
		}
	}
	require.Failf(t, "no catalog case", "request_revert %s", kase)
	return nil
}

// requireErrorSteps checks a request_revert error body: its code and reason
// and the catalog's steps for them.
func requireErrorSteps(t *testing.T, body map[string]any, isError bool, code, reason string) []map[string]any {
	t.Helper()
	return requireScopedErrorSteps(t, body, isError, code, reason, "")
}

// requireScopedErrorSteps is requireErrorSteps for a failure in scope (TASK).
func requireScopedErrorSteps(t *testing.T, body map[string]any, isError bool, code, reason, scope string) []map[string]any {
	t.Helper()
	requireToolError(t, body, isError, code, reason, "")
	if reason == "" {
		require.NotContains(t, body, "reason")
	}
	c, err := mcpcontract.LoadNextSteps()
	require.NoError(t, err)
	e, ok := c.ErrorEntryFor(code, reason, "request_revert", scope)
	require.True(t, ok, "%s %s", code, reason)
	return requireSteps(t, body, e.Steps, e.PersonMessage)
}

func TestRequestRevertWaitsForTheRelayedSignature(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)
	runID, _ := winLeads(t, env.h, "81, 82, 83")
	d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 83`)
	req := requestRevert(t, env.h, map[string]any{"runId": runID, "intent": "Undo the merge"})
	id, secret := str(t, req["revertId"]), linkstest.SecretOf(str(t, req["revertUrl"]))

	relayed := p.relayLater(id, secret, p.signRevertPage(id, secret, env.person), env.afterRevertPolls())
	start := time.Now()
	body := requestRevert(t, env.h, map[string]any{"revertId": id})
	require.Less(t, time.Since(start), 30*time.Second, "returns as soon as the person signs")
	require.Equal(t, http.StatusOK, <-relayed)
	require.Equal(t, "APPLIED", body["status"])
	require.Equal(t, "RUN", body["scope"])
	require.Equal(t, runID, body["scopeId"])
	require.Equal(t, "Undo the merge", body["intent"])
	require.EqualValues(t, "2", body["rows"])
	require.EqualValues(t, "1", body["skipped"])
	_, err := uuid.Parse(str(t, body["changeId"]))
	require.NoError(t, err, "the revert's own change record")
	require.NotContains(t, body, "revertUrl")
	require.NotContains(t, body, "progress")
	require.Equal(t, "Reverted: 2 rows restored, 1 left as they are because someone changed them after the agent (people win).", afterReceiptLine(t, body["personMessage"]))
	requireResultSteps(t, body, "APPLIED")
	require.Equal(t, "open", leadStatus(t, d, 81))
	require.Equal(t, "person", leadStatus(t, d, 83), "people win")
}

// A large plan signed during the wait is APPLYING: the agent then restores
// it in batches.
func TestRequestRevertWaitForALargePlan(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t, pageOrigin)
	p := newLocalPages(t, e.agentEnv)
	req := requestRevert(t, e.h, map[string]any{"runId": e.runID.String(), "intent": "Undo the bulk update"})
	id, secret := str(t, req["revertId"]), linkstest.SecretOf(str(t, req["revertUrl"]))
	steps := requireResultSteps(t, req, "REQUESTED")
	require.Equal(t, req["revertUrl"], steps[0]["url"])

	relayed := p.relayLater(id, secret, p.signRevertPage(id, secret, e.person), e.afterRevertPolls())
	body := requestRevert(t, e.h, map[string]any{"revertId": id, "waitForSignature": 30})
	require.Equal(t, http.StatusOK, <-relayed)
	requireApplying(t, body)
	require.Equal(t, planRows, itemsLeft(t, e.d, "agent"), "signing a plan restores nothing yet")

	applyEveryBatch(t, e.h, id)
	require.Equal(t, planRows, itemsLeft(t, e.d, "before"))
	done := requestRevert(t, e.h, map[string]any{"revertId": id, "waitForSignature": 0})
	require.Equal(t, "APPLIED", done["status"])
	require.Equal(t, fmt.Sprintf("Reverted: %d rows restored, 0 left as they are because someone changed them after the agent (people win).",
		planRows), afterReceiptLine(t, done["personMessage"]))
	requireResultSteps(t, done, "APPLIED")
	require.Equal(t, body["changeId"], done["changeId"])
}

func requireApplying(t *testing.T, body map[string]any) {
	t.Helper()
	require.Equal(t, "APPLYING", body["status"])
	require.Equal(t, true, body["batched"])
	_, err := uuid.Parse(str(t, body["changeId"]))
	require.NoError(t, err)
	require.NotEmpty(t, body["applyBy"])
	progress, ok := body["progress"].(map[string]any)
	require.True(t, ok, "%v", body)
	require.EqualValues(t, "0", progress["restored"])
	require.EqualValues(t, fmt.Sprint(planRows), progress["pending"])
	require.EqualValues(t, "0", progress["batches"])
	steps := requireResultSteps(t, body, "APPLYING")
	require.Equal(t, "revert_plan", steps[0]["tool"])
	require.Equal(t, map[string]any{"revertId": body["revertId"], "pending": true, "limit": json.Number("200")}, steps[0]["arguments"])
	msg := str(t, body["personMessage"])
	require.True(t, strings.HasPrefix(msg, "Signed: "), "APPLYING tells the person only the receipt line: the last batch tells the rest: %s", msg)
	require.NotContains(t, msg, "\n")
	require.NotEmpty(t, body["receipt"])
}

// One wait, then end the turn: a wait that runs out returns PENDING, with
// no link and the no-repeat step; it writes nothing.
func TestRequestRevertWaitRunsOut(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	runID, _ := winLeads(t, env.h, "84")
	id := str(t, requestRevert(t, env.h, map[string]any{"runId": runID, "intent": "Undo"})["revertId"])

	start := time.Now()
	body := requestRevert(t, env.h, map[string]any{"revertId": id, "waitForSignature": 1})
	require.GreaterOrEqual(t, time.Since(start), time.Second)
	require.Equal(t, "PENDING", body["status"])
	require.NotContains(t, body, "revertUrl", "the link already given keeps working")
	require.NotContains(t, body, "changeId")
	steps := requireResultSteps(t, body, "WAIT_ENDED")
	require.True(t, strings.HasPrefix(str(t, steps[0]["url"]), links.DefaultLocal+"/reverts/"+id+"#2."),
		"no local pages: the long link, as the request gave")
	requireWaitEndedCalls(t, steps, id)
	expires, err := time.Parse(time.RFC3339, str(t, body["expiresAt"]))
	require.NoError(t, err)
	require.Equal(t, "The revert of run "+runID+" waits until "+
		expires.UTC().Format("2006-01-02 15:04 UTC")+", but its link cannot be signed. Ask the agent for a new link later.",
		body["personMessage"])

	start = time.Now()
	body = requestRevert(t, env.h, map[string]any{"revertId": id, "waitForSignature": 0})
	require.Less(t, time.Since(start), time.Second, "waitForSignature 0 reads the state at once")
	require.Equal(t, "PENDING", body["status"])
	requireResultSteps(t, body, "WAIT_ENDED")
	require.Equal(t, "won", leadStatus(t, env.d, 84), "a wait writes nothing")

	expireRevert(t, env, id)
	start = time.Now()
	body = requestRevert(t, env.h, map[string]any{"revertId": id})
	require.Less(t, time.Since(start), 5*time.Second, "an expired revert does not wait")
	require.Equal(t, "EXPIRED", body["status"])
	require.Contains(t, str(t, body["personMessage"]), "without your signature; nothing was reverted")
	steps = requireResultSteps(t, body, "EXPIRED")
	require.Equal(t, map[string]any{"runId": runID}, steps[1]["arguments"])
	require.Equal(t, "won", leadStatus(t, env.d, 84))
}

// requireWaitEndedCalls checks WAIT_ENDED's two calls for the agent: the
// one after the turn does not wait, and a fresh link only if it was lost.
func requireWaitEndedCalls(t *testing.T, steps []map[string]any, id string) {
	t.Helper()
	require.Equal(t, "request_revert", steps[3]["tool"])
	require.Equal(t, map[string]any{"revertId": id, "waitForSignature": json.Number("0")}, steps[3]["arguments"])
	require.Equal(t, "request_revert", steps[4]["tool"])
	require.Equal(t, map[string]any{"revertId": id, "reissueLink": true}, steps[4]["arguments"])
	require.Contains(t, str(t, steps[4]["text"]), "For a lost link")
}

// reissueLink issues a new short link at once and revokes the old one.
func TestRequestRevertReissueLink(t *testing.T) {
	t.Parallel()
	d := guardtest.New(t).WithDemo(t)
	env := agentHarnessFor(t, d, d.NewAgent(t, "bot", leads, leads), pageOrigin)
	p := newLocalPages(t, env)
	runID, _ := winLeads(t, env.h, "85")
	req := requestRevert(t, env.h, map[string]any{"runId": runID, "intent": "Undo"})
	id, old := str(t, req["revertId"]), linkstest.SecretOf(str(t, req["revertUrl"]))

	// With local pages a wait that runs out never hands out the long link:
	// the person signs at the short link the agent gave them earlier.
	ended := requestRevert(t, env.h, map[string]any{"revertId": id, "waitForSignature": 0})
	require.Equal(t, "PENDING", ended["status"])
	require.NotContains(t, ended, "revertUrl")
	steps := requireResultSteps(t, ended, "WAIT_ENDED")
	require.NotContains(t, steps[0], "url", "the engine keeps only the short link's hash; the agent still has the link")
	require.Contains(t, str(t, steps[0]["text"]), "short link the agent gave you earlier")
	require.Contains(t, str(t, steps[2]["text"]), "the revert link you gave earlier")
	requireWaitEndedCalls(t, steps, id)
	require.Contains(t, str(t, ended["personMessage"]), "at the short link the agent gave you")
	require.NotContains(t, str(t, ended["personMessage"]), "#2.")
	require.NotContains(t, fmt.Sprint(ended), "#2.", "no long link anywhere")

	start := time.Now()
	body := requestRevert(t, env.h, map[string]any{"revertId": id, "reissueLink": true})
	require.Less(t, time.Since(start), 5*time.Second, "a new link returns at once, to be shown before the wait")
	require.Equal(t, "PENDING", body["status"])
	link := str(t, body["revertUrl"])
	secret := linkstest.SecretOf(link)
	require.NotEqual(t, old, secret)
	require.Equal(t, pageOrigin+"/reverts/"+id+"#s="+secret, link)
	require.Contains(t, str(t, body["personMessage"]), "Sign it with your passkey here:\n\n"+link)
	mcptest.Require(t, str(t, body["personMessage"]), mcptest.LinksOf(t, body))
	steps = requireResultSteps(t, body, "REQUESTED")
	require.Equal(t, link, steps[0]["url"])

	var perr pageError
	require.Equal(t, http.StatusNotFound, p.get("/api/v1/reverts/"+id, old, &perr), "the old link is revoked")
	var r revert.Request
	require.Equal(t, http.StatusOK, p.get("/api/v1/reverts/"+id, secret, &r))

	var out action.AppliedRevert
	require.Equal(t, http.StatusOK, p.post("/api/v1/reverts/"+id+"/apply", pageOrigin, secret, p.signRevertPage(id, secret, env.person), &out))
	body = requestRevert(t, env.h, map[string]any{"revertId": id, "reissueLink": true})
	require.Equal(t, "APPLIED", body["status"])
	require.NotContains(t, body, "revertUrl", "no link for a revert already signed")

	// The run is reverted: a second request has nothing to revert, and says
	// how to undo the revert instead.
	again, isError := env.h.call(t, "request_revert", map[string]any{"runId": runID, "intent": "Undo again"})
	requireErrorSteps(t, again, isError, "NOTHING_TO_REVERT", "ALREADY_REVERTED")
	require.Contains(t, str(t, again["personMessage"]), "Reverting that revert brings the agent's changes back")
}

// The person signs on the revert page and the agent's wait sees it
// applied; the revert's own change can then be reverted the same way (a
// revert can be reverted).
func TestRequestRevertSignedOnThePage(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	runID, _ := winLeads(t, env.h, "87, 88")
	env.d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 88`)
	req := requestRevert(t, env.h, map[string]any{"runId": runID, "intent": "Undo"})
	require.NotContains(t, str(t, req["personMessage"]), "code", "nothing to give the agent")

	personSigns(t, env, str(t, req["revertUrl"]))
	body := requestRevert(t, env.h, map[string]any{"revertId": req["revertId"], "waitForSignature": 0})
	require.Equal(t, "APPLIED", body["status"])
	require.EqualValues(t, "1", body["rows"])
	require.EqualValues(t, "1", body["skipped"])
	require.Equal(t, "Reverted: 1 rows restored, 1 left as they are because someone changed them after the agent (people win).", afterReceiptLine(t, body["personMessage"]))
	requireResultSteps(t, body, "APPLIED")
	require.Equal(t, "open", leadStatus(t, env.d, 87))
	require.Equal(t, "person", leadStatus(t, env.d, 88))
	revertChange := str(t, body["changeId"])

	again := requestRevert(t, env.h, map[string]any{"changeId": revertChange, "intent": "Undo the undo"})
	require.Equal(t, "CHANGE", again["scope"])
	require.Equal(t, revertChange, again["scopeId"])
	personSigns(t, env, str(t, again["revertUrl"]))
	body = requestRevert(t, env.h, map[string]any{"revertId": again["revertId"], "waitForSignature": 0})
	require.Equal(t, "APPLIED", body["status"])
	require.Equal(t, "won", leadStatus(t, env.d, 87), "the revert of the revert puts the agent's value back")
	require.Equal(t, "person", leadStatus(t, env.d, 88))
}

func TestRequestRevertLargePlanSignedOnThePage(t *testing.T) {
	t.Parallel()
	e := newBatchEnv(t)
	require.NoError(t, relayRevert(e.svc, e.prep.RevertID, signBinding(t, e.person, e.prep.BindingText)))
	id := e.prep.RevertID.String()

	body := requestRevert(t, e.h, map[string]any{"revertId": id, "waitForSignature": 0})
	requireApplying(t, body)
	applyEveryBatch(t, e.h, id)
	require.Equal(t, planRows, itemsLeft(t, e.d, "before"))
	require.Equal(t, "APPLIED", revertStatus(t, e.h, id))
}

// Security: only the person's own signature of this very revert applies
// it. Every other signature the page could relay is refused and writes
// nothing, by the engine and again by Postgres.
func TestRelayedRevertRefusesSignaturesThePersonDidNotMakeForIt(t *testing.T) {
	t.Parallel()
	env := agentHarness(t)
	ctx := context.Background()
	runA, _ := winLeads(t, env.h, "89")
	runB, _ := winLeads(t, env.h, "90")
	reqA := requestRevert(t, env.h, map[string]any{"runId": runA, "intent": "Undo A"})
	reqB := requestRevert(t, env.h, map[string]any{"runId": runB, "intent": "Undo B"})
	idA, bindingA := longLinkBinding(t, str(t, reqA["revertUrl"]))
	idB, bindingB := longLinkBinding(t, str(t, reqB["revertUrl"]))
	refused := func(revertID uuid.UUID, as passkey.Assertion, want, reason string) {
		t.Helper()
		te := agenttest.ToolError(relayRevert(env.svc, revertID, as))
		require.Equal(t, want, te.Code, "%v", te)
		require.Equal(t, reason, te.Reason, "%v", te)
	}

	// A's signature relabelled as B's.
	asA := signBinding(t, env.person, bindingA)
	refused(idB, asA, "REVERT_INVALID", "BAD_SIGNATURE")
	_, err := guard.ApplyRevert(ctx, env.a.Conn, idB, asA)
	requireRevertInvalid(t, err)

	// A tampered signature.
	tampered := signBinding(t, env.person, bindingA)
	tampered.Signature = bytes.Clone(tampered.Signature)
	tampered.Signature[len(tampered.Signature)-1] ^= 1
	refused(idA, tampered, "REVERT_INVALID", "BAD_SIGNATURE")
	_, err = guard.ApplyRevert(ctx, env.a.Conn, idA, tampered)
	requireRevertInvalid(t, err)

	// A signature by a passkey that was revoked since.
	spare, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	require.NoError(t, guard.RegisterPasskey(ctx, env.d.Admin, spare.Credential(), "spare"))
	bySpare := signBinding(t, spare, bindingA)
	_, err = guard.RevokePasskey(ctx, env.d.Admin, spare.ID, false)
	require.NoError(t, err)
	refused(idA, bySpare, "REVERT_INVALID", "PASSKEY_REVOKED")
	_, err = guard.ApplyRevert(ctx, env.a.Conn, idA, bySpare)
	requireRevertInvalid(t, err)

	// An approval's signature relabelled as a revert's.
	held, isError := env.h.call(t, "write", map[string]any{
		"sql": "UPDATE leads SET status = 'closed' WHERE id BETWEEN 21 AND 35", "intent": "Close cold leads",
	})
	requireToolError(t, held, isError, "APPROVAL_REQUIRED", "", "")
	approvalSigned := signLink(t, str(t, approvalOf(t, held)["approvalUrl"]), env.person)
	refused(idA, approvalSigned.Assertion(), "REVERT_INVALID", "BAD_SIGNATURE")

	require.Equal(t, "won", leadStatus(t, env.d, 89), "nothing was written")
	require.Equal(t, "won", leadStatus(t, env.d, 90))
	require.Equal(t, "open", leadStatus(t, env.d, 21))
	require.Equal(t, "PENDING", revertStatus(t, env.h, idA.String()))
	require.Equal(t, "PENDING", revertStatus(t, env.h, idB.String()))

	// The person's own signature applies A once; a replay is refused.
	asA = signBinding(t, env.person, bindingA)
	require.NoError(t, relayRevert(env.svc, idA, asA))
	require.Equal(t, "APPLIED", revertStatus(t, env.h, idA.String()))
	require.Equal(t, "open", leadStatus(t, env.d, 89))
	env.d.Exec(t, `UPDATE public.leads SET status = 'person' WHERE id = 89`)
	refused(idA, asA, "REVERT_INVALID", "PLAN_FINISHED")
	_, err = guard.ApplyRevert(ctx, env.a.Conn, idA, asA)
	requireRevertInvalid(t, err)
	require.Equal(t, "person", leadStatus(t, env.d, 89), "a replay writes nothing")

	// An expired revert takes no signature, even the person's own.
	expireRevert(t, env, idB.String())
	asB := signBinding(t, env.person, bindingB)
	refused(idB, asB, "REVERT_EXPIRED", "NOT_SIGNED")
	_, err = guard.ApplyRevert(ctx, env.a.Conn, idB, asB)
	code, ok := guard.CodeOf(err)
	require.True(t, ok, "%v", err)
	require.Equal(t, guard.CodeRevertExpired, code)
	require.Equal(t, "won", leadStatus(t, env.d, 90))
	require.Equal(t, "EXPIRED", revertStatus(t, env.h, idB.String()))
}

// afterReceiptLine is a signed item's personMessage after its receipt line
// (CONTRACT.md, Vault channel, Receipts), which comes first.
func afterReceiptLine(t *testing.T, msg any) string {
	t.Helper()
	line, rest, ok := strings.Cut(str(t, msg), "\n")
	require.True(t, ok, "%v", msg)
	require.True(t, strings.HasPrefix(line, "Signed: ") || strings.HasPrefix(line, "No receipt: "), line)
	return rest
}
