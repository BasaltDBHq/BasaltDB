package approval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/core/linkcodec"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
	"github.com/basaltdbhq/basaltdb/internal/core/textrule"
	"github.com/basaltdbhq/basaltdb/internal/lib/strictjson"
)

// Plugin approvals (CONTRACT.md, Plugins, What a plugin approval binds and
// The plugin approval page): the binding text the guard builds for a plugin
// install or change, the settings text that travels beside it, the request
// a plugin approval link carries, and the code the page outputs. As for
// held writes, nothing here decides whether an approval counts: the guard
// does, in basalt_meta.submit_plugin_approval.

const (
	// KindPlugin is the binding kind of a plugin approval.
	KindPlugin = "PLUGIN"
)

// PluginBinding is the parsed binding text of a plugin approval, for the
// checks a relay makes. The text itself is what the passkey signs: never
// re-serialize it. The page derives what it shows from the text; this
// struct only names the keys, so an unknown one is refused.
type PluginBinding struct {
	Kind           string          `json:"kind"`
	ApprovalID     uuid.UUID       `json:"approvalId"`
	Store          BindingStore    `json:"store"`
	ExpiresAt      time.Time       `json:"expiresAt"`
	RequestedBy    string          `json:"requestedBy"`
	Agents         []string        `json:"agents"`
	Name           string          `json:"name"`
	Instance       string          `json:"instance"`
	Version        string          `json:"version"`
	ManifestSHA256 string          `json:"manifestSha256"`
	SettingsSHA256 string          `json:"settingsSha256"`
	Hooks          []string        `json:"hooks"`
	Roles          []string        `json:"roles,omitempty"`
	Egress         []string        `json:"egress"`
	Endpoint       json.RawMessage `json:"endpoint"`
	Isolation      json.RawMessage `json:"isolation,omitempty"`
	Signer         string          `json:"signer"`
	SignerKeyID    string          `json:"signerKeyId,omitempty"`
	Change         json.RawMessage `json:"change,omitempty"`
}

// ParsePluginBinding parses a plugin approval's binding text: the text
// rules, kind PLUGIN, no unknown key, an approval id, the store, every
// agent agent:<name>, and both hashes lowercase sha256 hex.
func ParsePluginBinding(text string) (PluginBinding, error) {
	if err := textrule.Check(text); err != nil {
		return PluginBinding{}, Invalid("plugin binding: %v", err)
	}
	var b PluginBinding
	if err := strictjson.Decode([]byte(text), &b); errors.Is(err, strictjson.ErrTrailingData) {
		return PluginBinding{}, Invalid("plugin binding has data after its end")
	} else if err != nil {
		return PluginBinding{}, Invalid("plugin binding: %v", err)
	}
	if b.Kind != KindPlugin {
		return PluginBinding{}, Invalid("binding kind %q is not a plugin approval", b.Kind)
	}
	if b.ApprovalID == uuid.Nil {
		return PluginBinding{}, Invalid("plugin binding has no approvalId")
	}
	if !isSHA256Hex(b.ManifestSHA256) || !isSHA256Hex(b.SettingsSHA256) {
		return PluginBinding{}, Invalid("plugin binding manifestSha256 and settingsSha256 must be lowercase sha256 hex")
	}
	if err := CheckStore(b.Store); err != nil {
		return PluginBinding{}, err
	}
	if err := CheckBasaltFields(text); err != nil {
		return PluginBinding{}, err
	}
	if !IsAgentName(b.RequestedBy) || len(b.Agents) == 0 || slices.ContainsFunc(b.Agents, func(a string) bool { return !IsAgentName(a) }) {
		return PluginBinding{}, Invalid("plugin binding names an agent that is not agent:<name>")
	}
	return b, nil
}

func isSHA256Hex(s string) bool {
	if len(s) != sha256.Size*2 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// SettingsHash is the lowercase hex sha256 of the settings text, a
// binding's settingsSha256.
func SettingsHash(settings string) string {
	sum := sha256.Sum256([]byte(settings))
	return hex.EncodeToString(sum[:])
}

// PluginRequest is a plugin approval request: what the engine's local
// pages serve at GET /api/v1/plugins/{approvalId}
// (api/plugin/approval/request.schema.json), and the two texts a long
// link carries.
type PluginRequest struct {
	ApprovalID    uuid.UUID       `json:"approvalId"`
	Binding       string          `json:"binding"`
	Settings      string          `json:"settings"`
	CredentialIDs []passkey.Bytes `json:"credentialIds,omitempty"`
}

// Check parses the binding and checks the request against it: the same
// approval, and the settings text hashes to settingsSha256. The page makes
// the same checks, and more, before it shows anything.
func (r PluginRequest) Check() (PluginBinding, error) {
	b, err := ParsePluginBinding(r.Binding)
	if err != nil {
		return PluginBinding{}, err
	}
	if b.ApprovalID != r.ApprovalID {
		return PluginBinding{}, Invalid("request is for plugin approval %s, binding for %s", r.ApprovalID, b.ApprovalID)
	}
	if SettingsHash(r.Settings) != b.SettingsSHA256 {
		return PluginBinding{}, Invalid("the settings text does not match the binding's settingsSha256")
	}
	if err := textrule.Check(r.Settings); err != nil {
		return PluginBinding{}, Invalid("plugin settings: %v", err)
	}
	return b, nil
}

// Fragment returns the link fragment (without '#') in format 2: exactly two
// texts, the binding and then the settings, and the database's credential
// ids (CONTRACT.md, Format 2).
// The engine relays only texts that follow the text rules (CONTRACT.md,
// Stores, Text rules): it refuses any other.
func (r PluginRequest) Fragment() (string, error) {
	if err := CheckTexts(r.Binding, []string{r.Settings}...); err != nil {
		return "", err
	}
	return linkcodec.EncodeRequest(r.Binding, []string{r.Settings}, r.CredentialIDs)
}

// URL returns the long plugin approval link on the pages at base:
// <base>/plugins/<approvalId>#2.<request>. Over the link budget,
// links.HashLink with links.PluginFile turns it into the hash link and its
// request file.
func (r PluginRequest) URL(base string) (string, error) {
	frag, err := r.Fragment()
	if err != nil {
		return "", err
	}
	return links.PluginApproval(base, r.ApprovalID) + "#" + frag, nil
}

// PluginApprovalResponse is what the plugin approval page outputs after the person
// signs (api/plugin/approval/response.schema.json), and the body of POST
// /api/v1/plugins/{approvalId}/approve.
type PluginApprovalResponse struct {
	ApprovalID uuid.UUID `json:"approvalId"`
	passkey.SignedAssertion
}

// Signed returns the approval id and the assertion.
func (r PluginApprovalResponse) Signed() (uuid.UUID, passkey.SignedAssertion) {
	return r.ApprovalID, r.SignedAssertion
}

// DecodePluginResponse decodes the signed response the plugin approval
// page posts (its JSON), strictly: an unknown field or a missing one is
// refused.
func DecodePluginResponse(raw []byte) (PluginApprovalResponse, error) {
	var r PluginApprovalResponse
	if err := DecodeSigned(raw, &r, "plugin approval response is missing a field"); err != nil {
		return PluginApprovalResponse{}, err
	}
	return r, nil
}
