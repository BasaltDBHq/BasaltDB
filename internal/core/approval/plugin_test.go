package approval_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/core/approval"
	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/links/linkstest"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey/passkeytest"
)

// pluginVector is one of the contract's plugin approval vectors
// (api/plugin/approval/vectors.json).
type pluginVector struct {
	Name     string `json:"name"`
	Binding  string `json:"binding"`
	Settings string `json:"settings"`
	Expect   struct {
		SettingsMatch *bool  `json:"settingsMatch"`
		Error         string `json:"error"`
	} `json:"expect"`
}

type pluginVectors struct {
	Vectors  []pluginVector  `json:"vectors"`
	Response json.RawMessage `json:"response"`
}

func readPluginVectors(t *testing.T) pluginVectors {
	t.Helper()
	raw, err := os.ReadFile("../../../api/plugin/approval/vectors.json")
	require.NoError(t, err)
	var v pluginVectors
	require.NoError(t, json.Unmarshal(raw, &v))
	require.NotEmpty(t, v.Vectors)
	return v
}

func pluginID(t *testing.T, binding string) uuid.UUID {
	t.Helper()
	var b struct {
		ApprovalID uuid.UUID `json:"approvalId"`
	}
	require.NoError(t, json.Unmarshal([]byte(binding), &b))
	return b.ApprovalID
}

// TestPluginLinkRoundTrip: every vector's binding and settings travel in a
// long link, and in its hash link's request file, and come back byte for
// byte. A link whose settings do not hash to settingsSha256, or whose
// binding is not a plugin approval's, is refused, as the page refuses it.
func TestPluginLinkRoundTrip(t *testing.T) {
	t.Parallel()
	ids := []passkey.Bytes{passkey.Bytes("one passkey"), passkey.Bytes("another")}
	for _, v := range readPluginVectors(t).Vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			id := pluginID(t, v.Binding)
			req := approval.PluginRequest{ApprovalID: id, Binding: v.Binding, Settings: v.Settings, CredentialIDs: ids}
			url := pluginURL(t, req, links.DefaultLocal+"/")
			page, frag, ok := strings.Cut(url, "#")
			require.True(t, ok)
			require.Equal(t, "http://localhost:8787/plugins/"+id.String(), page)
			require.True(t, strings.HasPrefix(frag, linkcodec.Format2), frag)

			// The hash link carries the same text in its request file.
			hashLink, file, err := links.HashLink(url, linkstest.PluginFile(id))
			require.NoError(t, err)
			require.Equal(t, page+"#h="+links.RequestHash(frag), hashLink)
			require.Equal(t, "basalt-plugin-"+id.String()+".txt", file.FileName)
			require.Equal(t, frag, file.Text)

			got, b, err := approval.ParsePluginRequest("#" + frag)
			if v.Expect.Error != "" || (v.Expect.SettingsMatch != nil && !*v.Expect.SettingsMatch) {
				require.ErrorIs(t, err, approval.ErrInvalid)
				return
			}
			require.NoError(t, err)
			require.Equal(t, v.Binding, got.Binding, "the binding text, byte for byte")
			require.Equal(t, v.Settings, got.Settings, "the settings text, byte for byte")
			require.Equal(t, id, got.ApprovalID)
			require.Equal(t, ids, got.CredentialIDs)
			require.Equal(t, id, b.ApprovalID)
			require.Equal(t, approval.KindPlugin, b.Kind)
		})
	}
}

// pluginURL is req's long link as PluginRequest.URL writes it, but also for
// a vector the engine would refuse to relay, so the page can be tested on
// refusing it.
func pluginURL(t *testing.T, req approval.PluginRequest, base string) string {
	t.Helper()
	if _, err := req.Check(); err == nil {
		url, err := req.URL(base)
		require.NoError(t, err)
		return url
	}
	frag, err := linkcodec.EncodeRequest(req.Binding, []string{req.Settings}, req.CredentialIDs)
	require.NoError(t, err)
	return links.PluginApproval(base, req.ApprovalID) + "#" + frag
}

const pluginLinksFile = "testdata/plugin-links.json"

// pluginLink is one vector's links as Go writes them, which the page's
// tests open (web/lib/plugin.test.mjs).
type pluginLink struct {
	Name          string   `json:"name"`
	URL           string   `json:"url"`
	HashLink      string   `json:"hashLink"`
	RequestText   string   `json:"requestText"`
	CredentialIDs []string `json:"credentialIds"`
}

// TestPluginLinkFixtures keeps testdata/plugin-links.json in step with the
// Go encoder: every vector's long link, hash link and request text, so the
// page is tested on the links the engine writes. Run with -update after a
// deliberate change.
func TestPluginLinkFixtures(t *testing.T) {
	t.Parallel()
	ids := []passkey.Bytes{seq(16, 1)}
	vs := readPluginVectors(t).Vectors
	out := make([]pluginLink, 0, len(vs))
	for _, v := range vs {
		req := approval.PluginRequest{ApprovalID: pluginID(t, v.Binding), Binding: v.Binding, Settings: v.Settings, CredentialIDs: ids}
		url := pluginURL(t, req, links.DefaultLocal)
		hashLink, file, err := links.HashLink(url, linkstest.PluginFile(req.ApprovalID))
		require.NoError(t, err)
		out = append(out, pluginLink{Name: v.Name, URL: url, HashLink: hashLink, RequestText: file.Text, CredentialIDs: []string{ids[0].String()}})
	}
	got, err := json.MarshalIndent(out, "", "  ")
	require.NoError(t, err)
	got = append(got, '\n')
	if *update {
		require.NoError(t, os.WriteFile(pluginLinksFile, got, 0o600))
	}
	want, err := os.ReadFile(pluginLinksFile)
	require.NoError(t, err)
	require.Equal(t, string(want), string(got), "run go test ./internal/core/approval -update")
}

func TestPluginRequestRefuses(t *testing.T) {
	t.Parallel()
	v := readPluginVectors(t).Vectors[0]
	id := pluginID(t, v.Binding)
	good := approval.PluginRequest{ApprovalID: id, Binding: v.Binding, Settings: v.Settings}
	_, err := good.Check()
	require.NoError(t, err)

	cases := map[string]approval.PluginRequest{
		"another id":       {ApprovalID: uuid.Must(uuid.NewV7()), Binding: v.Binding, Settings: v.Settings},
		"changed settings": {ApprovalID: id, Binding: v.Binding, Settings: strings.Replace(v.Settings, "2000", "2001", 1)},
		"an unknown key":   {ApprovalID: id, Binding: strings.Replace(v.Binding, `{"kind"`, `{"extra": 1, "kind"`, 1), Settings: v.Settings},
		"a held write":     {ApprovalID: id, Binding: strings.Replace(v.Binding, `"PLUGIN"`, `"APPROVE"`, 1), Settings: v.Settings},
	}
	for name, r := range cases {
		_, err := r.Check()
		require.ErrorIs(t, err, approval.ErrInvalid, name)
	}

	// Only format 2.
	f2, err := good.Fragment()
	require.NoError(t, err)
	_, _, err = approval.ParsePluginRequest("1." + strings.TrimPrefix(f2, linkcodec.Format2))
	require.ErrorIs(t, err, approval.ErrInvalid)

	// Exactly two texts: a held write's link with lines is not a plugin
	// approval's.
	three, err := linkcodec.EncodeRequest(v.Binding, []string{v.Settings, "{}"}, nil)
	require.NoError(t, err)
	_, _, err = approval.ParsePluginRequest(three)
	require.ErrorIs(t, err, approval.ErrInvalid)
}

// TestDecodePluginResponse: the vectors' response is the JSON the page
// posts and decodes back; an unknown field or a missing one is refused.
func TestDecodePluginResponse(t *testing.T) {
	t.Parallel()
	vs := readPluginVectors(t)
	var want approval.PluginApprovalResponse
	require.NoError(t, json.Unmarshal(vs.Response, &want))

	body, err := json.Marshal(want)
	require.NoError(t, err)
	require.JSONEq(t, string(vs.Response), string(body), "the page posts the response JSON of the contract")
	got, err := approval.DecodePluginResponse(body)
	require.NoError(t, err)
	require.Equal(t, want, got)

	for name, bad := range map[string]string{
		"empty":          "",
		"an unknown key": strings.Replace(string(body), "{", `{"extra":1,`, 1),
		"no signature":   `{"approvalId":"0193b2c4-5d6e-7f80-9a1b-2c3d4e5f6a7d","credentialId":"AQ","authenticatorData":"AQ","clientDataJson":"AQ"}`,
		"no approval id": `{"credentialId":"AQ","authenticatorData":"AQ","clientDataJson":"AQ","signature":"AQ"}`,
		"a bad id":       `{"approvalId":"nope","credentialId":"AQ","authenticatorData":"AQ","clientDataJson":"AQ","signature":"AQ"}`,
		"padded base64":  `{"approvalId":"0193b2c4-5d6e-7f80-9a1b-2c3d4e5f6a7d","credentialId":"AQ==","authenticatorData":"AQ","clientDataJson":"AQ","signature":"AQ"}`,
	} {
		_, err := approval.DecodePluginResponse([]byte(bad))
		require.ErrorIs(t, err, approval.ErrInvalid, name)
	}
}

func TestVerifyPlugin(t *testing.T) {
	t.Parallel()
	v := readPluginVectors(t).Vectors[2]
	id := pluginID(t, v.Binding)
	person, err := passkeytest.New(passkey.Production)
	require.NoError(t, err)
	as, err := person.Sign(approval.Challenge(v.Binding), passkeytest.FlagsUPUV, nil)
	require.NoError(t, err)
	body, err := json.Marshal(approval.NewPluginApprovalResponse(id, as))
	require.NoError(t, err)
	resp, err := approval.DecodePluginResponse(body)
	require.NoError(t, err)

	count, err := approval.VerifyPlugin(v.Binding, person.Credential(), resp)
	require.NoError(t, err)
	require.Equal(t, uint32(1), count)

	other := strings.Replace(v.Binding, `"0.3.1"`, `"0.3.2"`, 1)
	_, err = approval.VerifyPlugin(other, person.Credential(), resp)
	require.ErrorIs(t, err, passkey.ErrRejected)

	moved := resp
	moved.ApprovalID = uuid.Must(uuid.NewV7())
	_, err = approval.VerifyPlugin(v.Binding, person.Credential(), moved)
	require.ErrorContains(t, err, "binding for")
}

// The engine relays only texts that follow the text rules: a plugin
// request's binding or settings that break them is refused before encoding.
func TestPluginFragmentRefusesTextsOutOfTheRules(t *testing.T) {
	t.Parallel()
	var v pluginVector
	for _, x := range readPluginVectors(t).Vectors {
		if x.Expect.Error == "" && (x.Expect.SettingsMatch == nil || *x.Expect.SettingsMatch) {
			v = x
			break
		}
	}
	require.NotEmpty(t, v.Binding)
	id := pluginID(t, v.Binding)
	_, err := approval.PluginRequest{ApprovalID: id, Binding: v.Binding, Settings: v.Settings}.Fragment()
	require.NoError(t, err)
	for name, req := range map[string]approval.PluginRequest{
		"binding": {ApprovalID: id, Binding: strings.Replace(v.Binding, `{"kind": `, `{"kind":`, 1), Settings: v.Settings},
		"line":    {ApprovalID: id, Binding: v.Binding, Settings: `{"a":1}`},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := req.Fragment()
			require.ErrorIs(t, err, approval.ErrInvalid)
			require.ErrorContains(t, err, name)
		})
	}
}
