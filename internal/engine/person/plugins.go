package person

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/passkey"
)

// The plugin methods (CONTRACT.md, Plugins, Plugin approval in service
// mode; api/plugin/approval/person.schema.json).
const (
	MethodPluginUploadBegin Method = "PLUGIN_UPLOAD_BEGIN"
	MethodPluginUploadPart  Method = "PLUGIN_UPLOAD_PART"
	MethodPluginOpen        Method = "PLUGIN_OPEN"
	MethodPluginList        Method = "PLUGIN_LIST"
	MethodPluginApprove     Method = "PLUGIN_APPROVE"
	MethodPluginDisable     Method = "PLUGIN_DISABLE"
	MethodPluginRemove      Method = "PLUGIN_REMOVE"
)

// CodePluginRefused is a plugin method refused, with a Reason.
const CodePluginRefused Code = "PLUGIN_REFUSED"

// pluginTimeout bounds a plugin method: each database within 15 seconds,
// in parallel, and the client waits up to 60 seconds.
const pluginTimeout = 60 * time.Second

// Refused is PLUGIN_REFUSED with reason.
func Refused(reason, message string) *Error {
	return &Error{Code: CodePluginRefused, Reason: reason, Message: message}
}

// Scope is the agents a plugin request may reach: nil for a person, who
// may name every agent; else the agents whose osUser is the peer's uid
// (SM-4).
type Scope map[string]bool

// Allows reports whether the scope reaches agent.
func (s Scope) Allows(agent string) bool { return s == nil || s[agent] }

// AllowsAll reports whether the scope reaches every one of agents.
func (s Scope) AllowsAll(agents []string) bool {
	for _, a := range agents {
		if !s.Allows(a) {
			return false
		}
	}
	return true
}

// PluginMethods serve the plugin methods; the engine implements them.
// Errors are *Error (PLUGIN_REFUSED with its reason, NOT_FOUND,
// INVALID_ARGUMENT, AGENT_NOT_ALLOWED), anything else is INTERNAL.
type PluginMethods interface {
	UploadBegin(ctx context.Context, uid uint32) (PluginUploadBeginResult, error)
	UploadPart(ctx context.Context, uid uint32, p PluginUploadPartParams) (PluginUploadPartResult, error)
	Open(ctx context.Context, uid uint32, scope Scope, p PluginOpenParams) (PluginOpenResult, error)
	List(ctx context.Context, scope Scope) (PluginListResult, error)
	Approve(ctx context.Context, p PluginApproveParams) (PluginApproveResult, error)
	Disable(ctx context.Context, scope Scope, p PluginEntryParams) (PluginEntryResult, error)
	Remove(ctx context.Context, scope Scope, p PluginEntryParams) (PluginEntryResult, error)
}

// PluginUploadBeginResult is PLUGIN_UPLOAD_BEGIN's result.
type PluginUploadBeginResult struct {
	UploadID       uuid.UUID `json:"uploadId"`
	ExpiresAt      time.Time `json:"expiresAt"`
	MaxPartBytes   int       `json:"maxPartBytes"`
	MaxUploadBytes int       `json:"maxUploadBytes"`
}

// PluginUploadPartParams are PLUGIN_UPLOAD_PART's params.
type PluginUploadPartParams struct {
	UploadID uuid.UUID `json:"uploadId"`
	Path     string    `json:"path"`
	Offset   int64     `json:"offset"`
	Data     string    `json:"data"`
}

// PluginUploadPartResult is PLUGIN_UPLOAD_PART's result.
type PluginUploadPartResult struct {
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// PluginSettings are an engine-kept entry's settings: no auth.
type PluginSettings struct {
	Config        json.RawMessage `json:"config,omitempty"`
	TimeoutMs     *int            `json:"timeoutMs,omitempty"`
	MinConfidence *float64        `json:"minConfidence,omitempty"`
}

// PluginOpenParams are PLUGIN_OPEN's params.
type PluginOpenParams struct {
	UploadID    *uuid.UUID      `json:"uploadId,omitempty"`
	Name        string          `json:"name"`
	Instance    string          `json:"instance"`
	Agents      []string        `json:"agents"`
	Settings    *PluginSettings `json:"settings,omitempty"`
	Executables []string        `json:"executables,omitempty"`
}

// PluginDatabase names a database as the commands show it.
type PluginDatabase struct {
	Host string `json:"host"`
	Name string `json:"name"`
}

// PluginOpenRefusal is an approval the engine could not open after the
// entry was written.
type PluginOpenRefusal struct {
	Reason  string `json:"reason"`
	Message string `json:"message"`
}

// PluginOpenedApproval is one database's approval.
type PluginOpenedApproval struct {
	Database     PluginDatabase     `json:"database"`
	Agents       []string           `json:"agents"`
	ApprovalID   *uuid.UUID         `json:"approvalId,omitempty"`
	ExpiresAt    *time.Time         `json:"expiresAt,omitempty"`
	BindingText  string             `json:"bindingText,omitempty"`
	SettingsText string             `json:"settingsText,omitempty"`
	Refused      *PluginOpenRefusal `json:"refused,omitempty"`
}

// PluginOpenResult is PLUGIN_OPEN's result.
type PluginOpenResult struct {
	Name      string                 `json:"name"`
	Instance  string                 `json:"instance"`
	Version   string                 `json:"version"`
	Narrowed  bool                   `json:"narrowed"`
	Approvals []PluginOpenedApproval `json:"approvals"`
}

// PluginListResult is PLUGIN_LIST's result.
type PluginListResult struct {
	Plugins []PluginListed `json:"plugins"`
	Problem string         `json:"problem,omitempty"`
}

// Sources of a listed entry.
const (
	SourceConfig = "CONFIG"
	SourceEngine = "ENGINE"
)

// Health of a listed entry: what the running engine knows of it.
const (
	// HealthReady: the engine started the entry and it answers.
	HealthReady = "READY"
	// HealthUnavailable: the engine started the entry and it does not
	// answer now.
	HealthUnavailable = "UNAVAILABLE"
	// HealthNotStarted: the engine has not started the entry (turned off,
	// not approved, refused at its check, or added since the engine last
	// read its entries).
	HealthNotStarted = "NOT_STARTED"
)

// PluginListed is one entry of PLUGIN_LIST.
type PluginListed struct {
	Name        string          `json:"name"`
	Instance    string          `json:"instance"`
	Source      string          `json:"source"`
	Enabled     bool            `json:"enabled"`
	Agents      []string        `json:"agents"`
	Version     string          `json:"version"`
	Signer      string          `json:"signer,omitempty"`
	SignerKeyID string          `json:"signerKeyId,omitempty"`
	Endpoint    json.RawMessage `json:"endpoint"`
	Isolation   json.RawMessage `json:"isolation,omitempty"`
	// Health is HealthReady, HealthUnavailable or HealthNotStarted.
	Health   string               `json:"health"`
	Approval PluginListedApproval `json:"approval"`
	// Serving is what the running engine serves of the entry, per agent:
	// the approval it is served on and whether the plugin answers READY.
	// Absent when it serves the entry to no agent.
	Serving []PluginServing `json:"serving,omitempty"`
}

// PluginListedApproval is an entry's approval state per listed agent.
type PluginListedApproval struct {
	Required bool                `json:"required"`
	Agents   []PluginAgentStatus `json:"agents"`
}

// PluginAgentStatus is one agent's newest approval of an entry.
type PluginAgentStatus struct {
	Agent      string     `json:"agent"`
	State      string     `json:"state"`
	ApprovalID *uuid.UUID `json:"approvalId,omitempty"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
}

// PluginServing is one agent an entry is served to.
type PluginServing struct {
	Agent      string     `json:"agent"`
	ApprovalID *uuid.UUID `json:"approvalId,omitempty"`
	Ready      bool       `json:"ready"`
}

// PluginApproveParams are PLUGIN_APPROVE's params: the decoded
// basalt-plugin.1. code.
type PluginApproveParams struct {
	ApprovalID uuid.UUID    `json:"approvalId"`
	Assertion  assertionDTO `json:"assertion"`
}

// PluginApproveResult is PLUGIN_APPROVE's result.
type PluginApproveResult struct {
	ApprovalID uuid.UUID `json:"approvalId"`
	Status     string    `json:"status"`
	ApprovedAt time.Time `json:"approvedAt"`
}

// PluginEntryParams name an entry: PLUGIN_DISABLE and PLUGIN_REMOVE.
type PluginEntryParams struct {
	Name     string `json:"name"`
	Instance string `json:"instance"`
}

// PluginEntryResult is PLUGIN_DISABLE's result (Enabled false) or
// PLUGIN_REMOVE's (Removed true).
type PluginEntryResult struct {
	Name     string `json:"name"`
	Instance string `json:"instance"`
	Enabled  *bool  `json:"enabled,omitempty"`
	Removed  *bool  `json:"removed,omitempty"`
}

// pluginMethod reports whether m is a plugin method.
func pluginMethod(m Method) bool {
	switch m {
	case MethodPluginUploadBegin, MethodPluginUploadPart, MethodPluginOpen, MethodPluginList,
		MethodPluginApprove, MethodPluginDisable, MethodPluginRemove:
		return true
	default:
		return false
	}
}

// handlePlugin answers a plugin method: no top-level agent, params decoded
// strictly, the peer's scope passed on. Without PluginMethods (a server
// that serves none) every one is UNKNOWN_METHOD.
func (s *Server) handlePlugin(ctx context.Context, uid uint32, req Request) Response {
	if s.plugins == nil {
		return Response{Error: &Error{Code: CodeUnknownMethod, Message: fmt.Sprintf("unknown method %q", req.Method)}}
	}
	if req.agentSet {
		return Response{Error: invalid(fmt.Errorf("%s names no top-level agent: the agents are in params", req.Method))}
	}
	var scope Scope
	if sc, isAgent := s.scopes[uid]; isAgent {
		scope = Scope(sc)
	}
	ctx, cancel := context.WithTimeout(ctx, pluginTimeout)
	defer cancel()
	s.log.Info("person socket", "method", req.Method, "peerUid", uid)
	out, err := s.dispatchPlugin(ctx, uid, scope, req)
	resp := result(out, err)
	if resp.Error != nil && resp.Error.Code == CodeInternal {
		s.log.Error("person socket: plugin call failed", "method", req.Method, "err", err)
	}
	return resp
}

func (s *Server) dispatchPlugin(ctx context.Context, uid uint32, scope Scope, req Request) (any, error) {
	p := s.plugins
	switch req.Method {
	case MethodPluginUploadBegin:
		if err := decodeStrict(req.Params, &emptyParams{}); err != nil {
			return nil, invalid(err)
		}
		return p.UploadBegin(ctx, uid)
	case MethodPluginUploadPart:
		var in PluginUploadPartParams
		if err := decodeRequired(req.Params, &in, "uploadId", "path", "offset", "data"); err != nil {
			return nil, err
		}
		return p.UploadPart(ctx, uid, in)
	case MethodPluginOpen:
		var in PluginOpenParams
		if err := decodeRequired(req.Params, &in, "name", "instance", "agents"); err != nil {
			return nil, err
		}
		return p.Open(ctx, uid, scope, in)
	case MethodPluginList:
		if err := decodeStrict(req.Params, &emptyParams{}); err != nil {
			return nil, invalid(err)
		}
		return p.List(ctx, scope)
	case MethodPluginApprove:
		var in PluginApproveParams
		if err := decodeRequired(req.Params, &in, "approvalId", "assertion"); err != nil {
			return nil, err
		}
		return p.Approve(ctx, in)
	case MethodPluginDisable, MethodPluginRemove:
		var in PluginEntryParams
		if err := decodeRequired(req.Params, &in, "name", "instance"); err != nil {
			return nil, err
		}
		if req.Method == MethodPluginDisable {
			return p.Disable(ctx, scope, in)
		}
		return p.Remove(ctx, scope, in)
	default:
		return nil, &Error{Code: CodeUnknownMethod, Message: fmt.Sprintf("unknown method %q", req.Method)}
	}
}

// decodeRequired decodes raw strictly into v and refuses it when a key of
// required is missing.
func decodeRequired(raw json.RawMessage, v any, required ...string) error {
	if err := decodeStrict(raw, v); err != nil {
		return invalid(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		return invalid(err)
	}
	for _, k := range required {
		if _, ok := keys[k]; !ok {
			return invalid(fmt.Errorf("params.%s is required", k))
		}
	}
	return nil
}

// NewPluginApproveParams are PLUGIN_APPROVE's params for a decoded code.
func NewPluginApproveParams(id uuid.UUID, a passkey.Assertion) PluginApproveParams {
	return PluginApproveParams{ApprovalID: id, Assertion: assertionFromDomain(a)}
}

// PasskeyAssertion is the relayed assertion.
func (p PluginApproveParams) PasskeyAssertion() passkey.Assertion { return p.Assertion.toDomain() }

// PluginUploadBegin asks PLUGIN_UPLOAD_BEGIN.
func (c Client) PluginUploadBegin(ctx context.Context) (PluginUploadBeginResult, error) {
	var out PluginUploadBeginResult
	err := c.call(ctx, "", MethodPluginUploadBegin, emptyParams{}, &out)
	return out, err
}

// PluginUploadPart asks PLUGIN_UPLOAD_PART.
func (c Client) PluginUploadPart(ctx context.Context, p PluginUploadPartParams) (PluginUploadPartResult, error) {
	var out PluginUploadPartResult
	err := c.call(ctx, "", MethodPluginUploadPart, p, &out)
	return out, err
}

// PluginOpen asks PLUGIN_OPEN.
func (c Client) PluginOpen(ctx context.Context, p PluginOpenParams) (PluginOpenResult, error) {
	var out PluginOpenResult
	err := c.call(ctx, "", MethodPluginOpen, p, &out)
	return out, err
}

// PluginList asks PLUGIN_LIST.
func (c Client) PluginList(ctx context.Context) (PluginListResult, error) {
	var out PluginListResult
	err := c.call(ctx, "", MethodPluginList, emptyParams{}, &out)
	return out, err
}

// PluginApprove asks PLUGIN_APPROVE.
func (c Client) PluginApprove(ctx context.Context, p PluginApproveParams) (PluginApproveResult, error) {
	var out PluginApproveResult
	err := c.call(ctx, "", MethodPluginApprove, p, &out)
	return out, err
}

// PluginDisable asks PLUGIN_DISABLE.
func (c Client) PluginDisable(ctx context.Context, p PluginEntryParams) (PluginEntryResult, error) {
	var out PluginEntryResult
	err := c.call(ctx, "", MethodPluginDisable, p, &out)
	return out, err
}

// PluginRemove asks PLUGIN_REMOVE.
func (c Client) PluginRemove(ctx context.Context, p PluginEntryParams) (PluginEntryResult, error) {
	var out PluginEntryResult
	err := c.call(ctx, "", MethodPluginRemove, p, &out)
	return out, err
}

// PluginFile is one file of a plugin to upload: its path in the copy and
// its bytes.
type PluginFile struct {
	Path string
	Data []byte
}

// PluginUpload begins an upload and sends files in parts of at most the
// engine's maxPartBytes, in order. It returns the upload's id for
// PLUGIN_OPEN.
func (c Client) PluginUpload(ctx context.Context, files []PluginFile) (uuid.UUID, error) {
	begun, err := c.PluginUploadBegin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	part := begun.MaxPartBytes
	if part <= 0 {
		return uuid.Nil, fmt.Errorf("the engine offers parts of %d bytes", part)
	}
	for _, f := range files {
		if len(f.Data) == 0 {
			// An empty file is one empty part at offset 0.
			if _, err := c.PluginUploadPart(ctx, PluginUploadPartParams{UploadID: begun.UploadID, Path: f.Path}); err != nil {
				return uuid.Nil, err
			}
			continue
		}
		for off := 0; off < len(f.Data); off += part {
			chunk := f.Data[off:min(off+part, len(f.Data))]
			if _, err := c.PluginUploadPart(ctx, PluginUploadPartParams{
				UploadID: begun.UploadID, Path: f.Path, Offset: int64(off), Data: base64.RawURLEncoding.EncodeToString(chunk),
			}); err != nil {
				return uuid.Nil, err
			}
		}
	}
	return begun.UploadID, nil
}
