package person

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/basaltdbhq/basaltdb/internal/guard"
	"github.com/basaltdbhq/basaltdb/internal/ledger"
	"github.com/basaltdbhq/basaltdb/internal/passkey"
	"github.com/basaltdbhq/basaltdb/internal/pgcatalog"
	"github.com/basaltdbhq/basaltdb/pkg/pagination"
)

// dialTimeout bounds connecting to the person socket.
const dialTimeout = 5 * time.Second

// Client calls the engine over the person socket at Path.
type Client struct {
	Path string
}

// call makes one request: dial, read the greeting, write the request, read
// the response. A socket that is missing or refuses the connection is
// ErrNotRunning; a greeting that refuses this OS user is ErrUIDNotAllowed.
func (c Client) call(ctx context.Context, agent string, m Method, params, out any) error {
	d := net.Dialer{Timeout: dialTimeout}
	conn, err := d.DialContext(ctx, "unix", c.Path)
	if err != nil {
		// Whatever the reason (no socket, nobody listening), the person
		// sees "not running" with the start command, never the OS error.
		return fmt.Errorf("%w (%s)", ErrNotRunning, c.Path)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	_ = conn.SetDeadline(time.Now().Add(RequestTimeout))
	r := bufio.NewReader(io.LimitReader(conn, maxResponseBytes))
	var g Greeting
	if err := readLine(r, &g); err != nil {
		return fmt.Errorf("%w (%s: no greeting)", ErrNotRunning, c.Path)
	}
	if !g.OK {
		return ErrUIDNotAllowed
	}
	raw, err := json.Marshal(params)
	if err != nil {
		return err
	}
	line, err := json.Marshal(Request{Method: m, Agent: agent, Params: raw})
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("send the request to the engine: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(methodTimeout(m) + RequestTimeout))
	var resp Response
	if err := readLine(r, &resp); err != nil {
		return fmt.Errorf("read the engine's answer: %w", err)
	}
	if resp.Error != nil {
		return resp.Error
	}
	dec := json.NewDecoder(bytes.NewReader(resp.Result))
	dec.UseNumber() // row values print as Postgres gave them
	return dec.Decode(out)
}

func readLine(r *bufio.Reader, v any) error {
	line, err := r.ReadBytes('\n')
	if err != nil && (len(line) == 0 || !errors.Is(err, io.EOF)) {
		return err
	}
	return json.Unmarshal(line, v)
}

// Pages is PAGES: the pages base URL and the engine's local pages origin.
func (c Client) Pages(ctx context.Context) (PagesDTO, error) {
	var out PagesDTO
	err := c.call(ctx, "", MethodPages, emptyParams{}, &out)
	return out, err
}

// Agent is the Ledger of agent name over this socket.
func (c Client) Agent(name string) *AgentClient {
	return &AgentClient{c: c, agent: name}
}

// AgentClient is the Ledger of one agent, asked of the engine.
type AgentClient struct {
	c     Client
	agent string
}

var _ Ledger = (*AgentClient)(nil)

// notFound turns the engine's NOT_FOUND into sentinel, as the same-user
// ledger call returns it.
func notFound(err, sentinel error) error {
	var we *Error
	if errors.As(err, &we) && we.Code == CodeNotFound {
		return sentinel
	}
	return err
}

// CheckHealth asks CHECK_HEALTH.
func (a *AgentClient) CheckHealth(ctx context.Context, opts ledger.HealthOptions) (ledger.Health, error) {
	var out healthDTO
	if err := a.c.call(ctx, a.agent, MethodCheckHealth, healthParamsFromDomain(opts), &out); err != nil {
		return ledger.Health{}, err
	}
	return out.toDomain(), nil
}

// ListChanges asks LIST_CHANGES.
func (a *AgentClient) ListChanges(ctx context.Context, p ledger.ChangeListParams) (pagination.Page[ledger.Change], error) {
	var out pageDTO[changeDTO]
	if err := a.c.call(ctx, a.agent, MethodListChanges, changeParamsFromDomain(p), &out); err != nil {
		return pagination.Page[ledger.Change]{}, err
	}
	return pagination.Page[ledger.Change]{Items: mapSlice(out.Items, changeDTO.toDomain), NextCursor: out.NextCursor}, nil
}

// ListAccess asks LIST_ACCESS.
func (a *AgentClient) ListAccess(ctx context.Context) (pgcatalog.Access, error) {
	var out accessDTO
	if err := a.c.call(ctx, a.agent, MethodListAccess, emptyParams{}, &out); err != nil {
		return pgcatalog.Access{}, err
	}
	return out.toDomain(), nil
}

// RowChanges asks ROW_CHANGES.
func (a *AgentClient) RowChanges(ctx context.Context, ids []uuid.UUID) (map[uuid.UUID][]ledger.RowChange, error) {
	var out rowChangesDTO
	if err := a.c.call(ctx, a.agent, MethodRowChanges, rowChangesParams{ChangeIDs: ids}, &out); err != nil {
		return nil, err
	}
	return out.toDomain(), nil
}

// ListPasskeys asks LIST_PASSKEYS.
func (a *AgentClient) ListPasskeys(ctx context.Context) ([]ledger.Passkey, error) {
	var out passkeysDTO
	if err := a.c.call(ctx, a.agent, MethodListPasskeys, emptyParams{}, &out); err != nil {
		return nil, err
	}
	keys := make([]ledger.Passkey, 0, len(out.Items))
	for _, d := range out.Items {
		k, err := d.toDomain()
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// FindApproval asks FIND_APPROVAL.
func (a *AgentClient) FindApproval(ctx context.Context, id uuid.UUID) (ledger.Approval, error) {
	var out approvalDTO
	if err := a.c.call(ctx, a.agent, MethodFindApproval, approvalIDParams{ApprovalID: id}, &out); err != nil {
		return ledger.Approval{}, notFound(err, ledger.ErrApprovalNotFound)
	}
	return ledger.Approval(out), nil
}

// SubmitApproval asks SUBMIT_APPROVAL.
func (a *AgentClient) SubmitApproval(ctx context.Context, id uuid.UUID, as passkey.Assertion) (time.Time, error) {
	var out submittedDTO
	err := a.c.call(ctx, a.agent, MethodSubmitApproval, submitApprovalParams{ApprovalID: id, Assertion: assertionFromDomain(as)}, &out)
	return out.ApprovedAt, err
}

// FindRevert asks FIND_REVERT.
func (a *AgentClient) FindRevert(ctx context.Context, id uuid.UUID) (ledger.Revert, error) {
	var out revertDTO
	if err := a.c.call(ctx, a.agent, MethodFindRevert, revertIDParams{RevertID: id}, &out); err != nil {
		return ledger.Revert{}, notFound(err, ledger.ErrRevertNotFound)
	}
	return out.toDomain(), nil
}

// PreviewRevert asks PREVIEW_REVERT.
func (a *AgentClient) PreviewRevert(ctx context.Context, s guard.RevertScope) ([]string, error) {
	var out previewDTO
	err := a.c.call(ctx, a.agent, MethodPreviewRevert, scopeParamsFromDomain(s, ""), &out)
	return out.Lines, err
}

// PrepareRevert asks PREPARE_REVERT.
func (a *AgentClient) PrepareRevert(ctx context.Context, s guard.RevertScope, intent string) (guard.PreparedRevert, error) {
	var out preparedDTO
	err := a.c.call(ctx, a.agent, MethodPrepareRevert, scopeParamsFromDomain(s, intent), &out)
	return guard.PreparedRevert(out), err
}

// ApplyRevert asks APPLY_REVERT.
func (a *AgentClient) ApplyRevert(ctx context.Context, id uuid.UUID, as passkey.Assertion) (guard.AppliedRevert, error) {
	var out guard.AppliedRevert
	err := a.c.call(ctx, a.agent, MethodApplyRevert, applyRevertParams{RevertID: id, Assertion: assertionFromDomain(as)}, &out)
	return out, err
}

// RescopeRevert asks RESCOPE_REVERT.
func (a *AgentClient) RescopeRevert(ctx context.Context, id uuid.UUID, runs []uuid.UUID, tables []string) (guard.PreparedRevert, error) {
	var out preparedDTO
	err := a.c.call(ctx, a.agent, MethodRescopeRevert, rescopeParams{RevertID: id, Runs: runs, Tables: tables}, &out)
	return guard.PreparedRevert(out), err
}

// RejectRevert asks REJECT_REVERT.
func (a *AgentClient) RejectRevert(ctx context.Context, id uuid.UUID, note string) (guard.RejectedRevert, error) {
	var out guard.RejectedRevert
	err := a.c.call(ctx, a.agent, MethodRejectRevert, rejectParams{RevertID: id, Note: note}, &out)
	return out, err
}

// ListRevertLines asks LIST_REVERT_LINES.
func (a *AgentClient) ListRevertLines(ctx context.Context, p ledger.RevertLineParams) (pagination.Page[ledger.RevertLine], error) {
	var out pageDTO[revertLineDTO]
	if err := a.c.call(ctx, a.agent, MethodListRevertLines, revertLineParamsFromDomain(p), &out); err != nil {
		return pagination.Page[ledger.RevertLine]{}, err
	}
	return pagination.Page[ledger.RevertLine]{
		Items:      mapSlice(out.Items, func(r revertLineDTO) ledger.RevertLine { return ledger.RevertLine(r) }),
		NextCursor: out.NextCursor,
	}, nil
}
