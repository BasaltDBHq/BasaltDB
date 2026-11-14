package approval_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/approval"
	"github.com/basaltdbhq/basaltdb/internal/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/links"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/passkey/passkeytest"
)

var update = flag.Bool("update", false, "rewrite testdata/fixtures.json")

const fixturesFile = "testdata/fixtures.json"

var (
	approvalID = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000a1")
	runID      = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000b2")
	taskID     = uuid.MustParse("0193a4c2-7d1e-7c3a-9f00-0000000000c3")
)

// previewLines are three lines as Postgres's jsonb text prints them, in
// COLLATE "C" order: a deleted lead, a cascaded note, and a cascaded row of a
// table the agent cannot read. Non-ASCII text checks every client hashes
// UTF-8 bytes.
func previewLines() []string {
	return []string{
		`{"op": "DELETE", "key": {"id": 3}, "old": {"id": 3, "name": "Café ✓ lead", "status": "open"}, "set": null, "table": "public.leads", "cascaded": false}`,
		`{"op": "DELETE", "key": {"id": 5}, "old": {"id": 5, "note": "note 5 — 日本 🚀", "lead_id": 3}, "set": null, "table": "public.lead_notes", "cascaded": true}`,
		`{"op": "DELETE", "table": "public.note_tags", "rowHash": "` + strings.Repeat("ab", sha256.Size) + `", "cascaded": true, "redacted": true}`,
	}
}

func bindingText(lines []string) string {
	return fmt.Sprintf(`{"kind": "APPROVE", "rows": %d, "agent": "basalt_agent_bot", "runId": %q, "intent": "Remove the spam lead", "params": [3], "taskId": %q, "database": "app", "rowsHash": %q, "expiresAt": "2026-11-12T06:02:11.123456Z", "statement": "DELETE FROM public.leads WHERE id = $1", "approvalId": %q, "assignedColumns": []}`,
		len(lines), runID.String(), taskID.String(), approval.RowsHash(lines), approvalID.String())
}

func seq(n int, start byte) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

// fixtures is shared with the approval page's JavaScript tests
// (web/lib/codec.test.mjs), so Go and the page agree byte for byte.
type fixtures struct {
	Request struct {
		ApprovalID    string   `json:"approvalId"`
		Binding       string   `json:"binding"`
		Lines         []string `json:"lines"`
		CredentialIDs []string `json:"credentialIds"`
		Fragment      string   `json:"fragment"`
		RowsHash      string   `json:"rowsHash"`
		Challenge     string   `json:"challenge"`
	} `json:"request"`
	Response struct {
		ApprovalID        string `json:"approvalId"`
		CredentialID      string `json:"credentialId"`
		AuthenticatorData string `json:"authenticatorData"`
		ClientDataJSON    string `json:"clientDataJson"`
		Signature         string `json:"signature"`
		Code              string `json:"code"`
	} `json:"response"`
	RegistrationRequest struct {
		Challenge   string `json:"challenge"`
		UserID      string `json:"userId"`
		UserName    string `json:"userName"`
		DisplayName string `json:"displayName"`
		Fragment    string `json:"fragment"`
	} `json:"registrationRequest"`
	RegistrationResponse struct {
		CredentialID       string `json:"credentialId"`
		ClientDataJSON     string `json:"clientDataJson"`
		AuthenticatorData  string `json:"authenticatorData"`
		PublicKey          string `json:"publicKey"`
		PublicKeyAlgorithm int    `json:"publicKeyAlgorithm"`
		Code               string `json:"code"`
	} `json:"registrationResponse"`
	Summaries []summaryCase `json:"summaries"`
}

func buildFixtures(t *testing.T) fixtures {
	t.Helper()
	var f fixtures
	lines := previewLines()
	binding := bindingText(lines)
	req := approval.Request{ApprovalID: approvalID, Binding: binding, Lines: lines, CredentialIDs: []passkey.Bytes{seq(16, 1)}}
	// The page's fixtures keep format 1, which the pages still read; format 2
	// has its shared vectors in api/mcp/links/compact-request.json.
	frag, err := linkcodec.Encode(linkcodec.Format1, req)
	require.NoError(t, err)
	f.Request.ApprovalID = approvalID.String()
	f.Request.Binding = binding
	f.Request.Lines = lines
	f.Request.CredentialIDs = []string{passkey.Bytes(seq(16, 1)).String()}
	f.Request.Fragment = frag
	f.Request.RowsHash = approval.RowsHash(lines)
	f.Request.Challenge = passkey.Bytes(approval.Challenge(binding)).String()

	resp := approval.Response{
		ApprovalID:        approvalID,
		CredentialID:      seq(16, 1),
		AuthenticatorData: seq(37, 0x10),
		ClientDataJSON:    []byte(`{"type":"webauthn.get","challenge":"` + f.Request.Challenge + `","origin":"https://basaltvault.app","crossOrigin":false}`),
		Signature:         seq(70, 0x30),
	}
	code, err := resp.Code()
	require.NoError(t, err)
	f.Response.ApprovalID = approvalID.String()
	f.Response.CredentialID = resp.CredentialID.String()
	f.Response.AuthenticatorData = resp.AuthenticatorData.String()
	f.Response.ClientDataJSON = resp.ClientDataJSON.String()
	f.Response.Signature = resp.Signature.String()
	f.Response.Code = code

	rreq := passkey.RegistrationRequest{Challenge: seq(32, 0x40), UserID: seq(16, 0x80), UserName: "app", DisplayName: "BasaltDB · app"}
	rfrag, err := rreq.Fragment()
	require.NoError(t, err)
	f.RegistrationRequest.Challenge = rreq.Challenge.String()
	f.RegistrationRequest.UserID = rreq.UserID.String()
	f.RegistrationRequest.UserName = rreq.UserName
	f.RegistrationRequest.DisplayName = rreq.DisplayName
	f.RegistrationRequest.Fragment = rfrag

	rresp := passkey.RegistrationResponse{
		CredentialID:       seq(16, 1),
		ClientDataJSON:     []byte(`{"type":"webauthn.create"}`),
		AuthenticatorData:  seq(55, 0x20),
		PublicKey:          seq(91, 0x50),
		PublicKeyAlgorithm: passkey.AlgES256,
	}
	rcode, err := rresp.Code()
	require.NoError(t, err)
	f.RegistrationResponse.CredentialID = rresp.CredentialID.String()
	f.RegistrationResponse.ClientDataJSON = rresp.ClientDataJSON.String()
	f.RegistrationResponse.AuthenticatorData = rresp.AuthenticatorData.String()
	f.RegistrationResponse.PublicKey = rresp.PublicKey.String()
	f.RegistrationResponse.PublicKeyAlgorithm = rresp.PublicKeyAlgorithm
	f.RegistrationResponse.Code = rcode
	f.Summaries = summaryCases()
	return f
}

// TestFixtures keeps testdata/fixtures.json in step with the Go encoders.
// Run with -update after a deliberate format change, then rerun the page's
// tests (make web-check).
func TestFixtures(t *testing.T) {
	t.Parallel()
	got, err := json.MarshalIndent(buildFixtures(t), "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *update {
		require.NoError(t, os.WriteFile(fixturesFile, got, 0o600))
	}
	want, err := os.ReadFile(fixturesFile)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "run go test ./internal/approval -update")
}

func TestPreviewLinesAreInCOrder(t *testing.T) {
	t.Parallel()
	lines := previewLines()
	require.True(t, sort.StringsAreSorted(lines), "fixture lines must be in byte order, as COLLATE \"C\" returns them")
	for _, l := range lines {
		parsed, err := approval.ParseLine(l)
		require.NoError(t, err)
		require.Equal(t, approval.OpDelete, parsed.Op)
	}
	redacted, err := approval.ParseLine(lines[2])
	require.NoError(t, err)
	require.True(t, redacted.Redacted)
	require.Empty(t, redacted.Old)

	for _, bad := range []string{`{"op": "MERGE", "table": "t", "cascaded": false}`, `{"op": "DELETE", "cascaded": false}`, `{"op": "DELETE", "table": "t", "cascaded": false, "extra": 1}`, `[]`} {
		_, err := approval.ParseLine(bad)
		require.ErrorIs(t, err, approval.ErrInvalid, bad)
	}
}

func TestRequestRoundTrip(t *testing.T) {
	t.Parallel()
	f := buildFixtures(t)
	url, err := approval.Request{ApprovalID: approvalID, Binding: f.Request.Binding, Lines: f.Request.Lines}.URL(links.Portal)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(url, "https://portal.basaltvault.app/approvals/"+approvalID.String()+"#2."), url)

	_, frag, ok := strings.Cut(url, "#")
	require.True(t, ok)
	req, b, err := approval.ParseRequest(frag)
	require.NoError(t, err)
	require.Equal(t, f.Request.Lines, req.Lines)
	require.Equal(t, approvalID, b.ApprovalID)
	require.Equal(t, runID, b.RunID)
	require.Equal(t, taskID, *b.TaskID)
	require.Equal(t, 3, b.Rows)
	require.Equal(t, "2026-11-12T06:02:11.123456Z", b.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000000Z"))
	require.JSONEq(t, `3`, string(b.Params[0]))
}

func TestRequestRefusesMismatch(t *testing.T) {
	t.Parallel()
	lines := previewLines()
	binding := bindingText(lines)
	encode := func(r approval.Request) string {
		frag, err := r.Fragment()
		require.NoError(t, err)
		return frag
	}
	changed := append([]string{}, lines...)
	changed[0] = strings.Replace(changed[0], `"open"`, `"won"`, 1)

	cases := []struct {
		name, fragment, detail string
	}{
		{"a line changed after signing", encode(approval.Request{ApprovalID: approvalID, Binding: binding, Lines: changed}), "rowsHash"},
		{"a line dropped", encode(approval.Request{ApprovalID: approvalID, Binding: binding, Lines: lines[:2]}), "2 lines, binding 3"},
		{"lines reordered", encode(approval.Request{ApprovalID: approvalID, Binding: binding, Lines: []string{lines[1], lines[0], lines[2]}}), "rowsHash"},
		{"another approval id (format 1)", encodeV1(t, approval.Request{ApprovalID: runID, Binding: binding, Lines: lines}), "binding for"},
		{"binding kind", encode(approval.Request{ApprovalID: approvalID, Binding: strings.Replace(binding, "APPROVE", "REVERT", 1), Lines: lines}), "kind"},
		{"binding unknown field", encode(approval.Request{ApprovalID: approvalID, Binding: strings.Replace(binding, `{"kind"`, `{"x": 1, "kind"`, 1), Lines: lines}), "unknown field"},
		{"wrong version", "3." + strings.TrimPrefix(encode(approval.Request{ApprovalID: approvalID, Binding: binding, Lines: lines}), "2."), "must start with"},
		{"not deflate", "2." + passkey.Bytes("plain json").String(), "deflate"},
		{"not base64url", "2.@@@", "base64url"},
		{"format 1 not deflate", "1." + passkey.Bytes("plain json").String(), "deflate"},
		{"too many lines", encode(approval.Request{ApprovalID: approvalID, Binding: binding, Lines: make([]string, approval.MaxRows+1)}), "at most 50"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := approval.ParseRequest(tc.fragment)
			require.ErrorIs(t, err, approval.ErrInvalid)
			require.ErrorContains(t, err, tc.detail)
		})
	}
}

// encodeV1 encodes r in format 1, which carries the approval id apart from
// the binding.
func encodeV1(t *testing.T, r approval.Request) string {
	t.Helper()
	frag, err := linkcodec.Encode(linkcodec.Format1, r)
	require.NoError(t, err)
	return frag
}

func TestRequestReadsFormat1(t *testing.T) {
	t.Parallel()
	f := buildFixtures(t)
	require.True(t, strings.HasPrefix(f.Request.Fragment, "1."))
	req, _, err := approval.ParseRequest("#" + f.Request.Fragment)
	require.NoError(t, err)
	require.Equal(t, f.Request.Lines, req.Lines)
	require.Len(t, req.CredentialIDs, 1, "format 1 still carries credential ids")
}

func TestFormat2IsShorter(t *testing.T) {
	t.Parallel()
	req := approval.Request{ApprovalID: approvalID, Binding: bindingText(previewLines()), Lines: previewLines(), CredentialIDs: []passkey.Bytes{seq(16, 1)}}
	v1, err := linkcodec.Encode(linkcodec.Format1, req)
	require.NoError(t, err)
	v2, err := req.Fragment()
	require.NoError(t, err)
	require.Less(t, len(v2), len(v1))
	got, _, err := approval.ParseRequest(v2)
	require.NoError(t, err)
	require.Equal(t, req.Lines, got.Lines)
	require.Equal(t, []passkey.Bytes{seq(16, 1)}, got.CredentialIDs, "format 2 carries the credential ids, so the page offers only those passkeys")
}

// FuzzParseRequest: whatever an approval link carries, parsing never
// panics, and a request it accepts hashes to its binding.
func FuzzParseRequest(f *testing.F) {
	lines := previewLines()
	req := approval.Request{ApprovalID: approvalID, Binding: bindingText(lines), Lines: lines}
	v1, err := linkcodec.Encode(linkcodec.Format1, req)
	require.NoError(f, err)
	v2, err := req.Fragment()
	require.NoError(f, err)
	f.Add(v1)
	f.Add(v2)
	f.Add("#2.")
	f.Add("2.@@@")
	f.Fuzz(func(t *testing.T, fragment string) {
		got, b, err := approval.ParseRequest(fragment)
		if err != nil {
			require.ErrorIs(t, err, approval.ErrInvalid)
			return
		}
		require.Equal(t, b.RowsHash, approval.RowsHash(got.Lines))
	})
}

// A fragment whose JSON inflates past the page's limit is refused. The
// encoder refuses to build one (ErrRequestTooLarge), so the test deflates
// the compact request itself, as a forged link would.
func TestRequestRefusesInflationBomb(t *testing.T) {
	t.Parallel()
	_, err := approval.Request{ApprovalID: approvalID, Binding: strings.Repeat(" ", 2<<20), Lines: previewLines()}.Fragment()
	require.ErrorIs(t, err, linkcodec.ErrRequestTooLarge)
	frag, err := linkcodec.Encode(linkcodec.Format2, linkcodec.Compact(append([]string{strings.Repeat(" ", 2<<20)}, previewLines()...)))
	require.NoError(t, err)
	_, _, err = approval.ParseRequest(frag)
	require.ErrorContains(t, err, "inflates past")
}

func TestBindingLimits(t *testing.T) {
	t.Parallel()
	lines := previewLines()
	binding := bindingText(lines)
	_, err := approval.ParseBinding(strings.Replace(binding, `"rows": 3`, `"rows": 51`, 1))
	require.ErrorContains(t, err, "out of 1..50")
	_, err = approval.ParseBinding(strings.Replace(binding, approval.RowsHash(lines), "xyz", 1))
	require.ErrorContains(t, err, "rowsHash")
}

// TestVerify signs a request's challenge with a software passkey, carries it
// through the response code, and verifies it like submit_approval.
func TestVerify(t *testing.T) {
	t.Parallel()
	binding := bindingText(previewLines())
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)

	as, err := person.Sign(approval.Challenge(binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	code, err := approval.NewResponse(approvalID, as).Code()
	require.NoError(t, err)
	resp, err := approval.ParseResponse("\n" + code + " ")
	require.NoError(t, err)

	count, err := approval.Verify(binding, person.Credential(), resp)
	require.NoError(t, err)
	require.Equal(t, uint32(1), count)

	t.Run("another binding", func(t *testing.T) {
		other := strings.Replace(binding, "Remove the spam lead", "Remove every lead", 1)
		_, err := approval.Verify(other, person.Credential(), resp)
		require.ErrorIs(t, err, passkey.ErrRejected)
	})
	t.Run("another approval id", func(t *testing.T) {
		moved := resp
		moved.ApprovalID = runID
		_, err := approval.Verify(binding, person.Credential(), moved)
		require.ErrorContains(t, err, "binding for")
	})
	t.Run("an agent's own key", func(t *testing.T) {
		agent, err := passkeytest.New(passkey.Production)
		require.NoError(t, err)
		agent.ID = person.ID
		forged, err := agent.Sign(approval.Challenge(binding), passkeytest.FlagsUPUV, nil)
		require.NoError(t, err)
		_, err = approval.Verify(binding, person.Credential(), approval.NewResponse(approvalID, forged))
		require.ErrorContains(t, err, "bad passkey signature")
	})
}

func TestParseResponseRefuses(t *testing.T) {
	t.Parallel()
	for _, code := range []string{
		"",
		"basalt-passkey.1.e30",
		approval.ResponsePrefix + passkey.Bytes(`{"approvalId":"0193a4c2-7d1e-7c3a-9f00-0000000000a1"}`).String(),
		approval.ResponsePrefix + passkey.Bytes(`{"approvalId":"nope","credentialId":"AQ","authenticatorData":"AQ","clientDataJson":"AQ","signature":"AQ"}`).String(),
	} {
		_, err := approval.ParseResponse(code)
		require.ErrorIs(t, err, approval.ErrInvalid, code)
	}
}

func TestChallengeHashesUTF8Bytes(t *testing.T) {
	t.Parallel()
	want := sha256.Sum256([]byte("é"))
	require.True(t, bytes.Equal(want[:], approval.Challenge("é")))
}
