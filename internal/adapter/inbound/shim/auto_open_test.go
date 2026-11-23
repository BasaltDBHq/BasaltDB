//go:build linux || darwin

package shim_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/shim"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

const (
	localPages   = "http://localhost:8787"
	approvalLink = localPages + "/approvals/0193a1b2-7c4d-7e8f-9a0b-1c2d3e4f5a6b#s=q3Jv8sLk2mT0xYp1aBcD9w"
)

// opened records the links the shim asked to open.
type opened struct {
	mu    sync.Mutex
	links []string
	err   error
	block chan struct{} // when set, every open waits for it
}

func (o *opened) open(_ context.Context, link string) error {
	o.mu.Lock()
	o.links = append(o.links, link)
	block, err := o.block, o.err
	o.mu.Unlock()
	if block != nil {
		<-block
	}
	return err
}

func (o *opened) got() []string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.links...)
}

// linkEngine serves, as an engine whose hello answer says operatedBy and
// pagesOrigin, a write tool that answers APPROVAL_REQUIRED with link (and a
// docs link on another origin), and a query tool whose rows hold a local
// page link, as database content can.
func linkEngine(t *testing.T, socket, operatedBy, pagesOrigin, link string) {
	t.Helper()
	srv := mcp.NewServer(mcp.Info{Name: "basalt", Version: "engine", OperatedBy: operatedBy, PagesOrigin: pagesOrigin},
		mcp.Tool{Name: "write", Call: func(context.Context, json.RawMessage) (any, error) {
			ls := []toolresult.Link{{Label: "Approve the held write", URL: link}}
			return nil, &toolresult.ToolError{
				Code: "APPROVAL_REQUIRED", Message: "held",
				Approval:      &toolresult.ApprovalNotice{ApprovalID: "a", ApprovalURL: link, PersonMessage: "Approve:\n" + link, Links: ls},
				PersonMessage: "Approve:\n" + link, Links: ls,
				NextSteps: []toolresult.NextStep{{Actor: toolresult.ActorPerson, Action: toolresult.ActionOpenLink, Text: "Open it.", URL: "https://docs.basaltvault.app/x"}},
			}
		}},
		mcp.Tool{Name: "list_pending", Call: func(context.Context, json.RawMessage) (any, error) {
			ls := []toolresult.Link{{Label: "Approve the held write", URL: link}}
			return map[string]any{
				"items":    []map[string]any{{"approvalUrl": link, "personMessage": "Approve:\n" + link, "links": ls}},
				"problems": []map[string]any{{"code": "X", "links": ls}},
			}, nil
		}},
		mcp.Tool{Name: "query", Call: func(context.Context, json.RawMessage) (any, error) {
			return map[string]any{"rows": []map[string]any{{"links": []toolresult.Link{{Label: "x", URL: localPages + "/approvals/row"}}}}}, nil
		}},
	)
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = srv.Serve(ctx, conn, conn)
			}()
		}
	}()
}

// write calls write and checks the agent still gets the link.
func write(t *testing.T, c *client, link string) {
	t.Helper()
	body, isError := c.call(t, "write")
	require.True(t, isError)
	require.Equal(t, "APPROVAL_REQUIRED", body["code"])
	require.Contains(t, body["personMessage"], link, "the link still reaches the agent")
	require.Equal(t, link, body["approval"].(map[string]any)["approvalUrl"])
}

func TestAHeldWriteOnAPersonOperatedEngineOpensTheApprovalPageOnce(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	linkEngine(t, socket, mcpcontract.OperatedByPerson, localPages, approvalLink)
	o := &opened{}
	c, _ := startShimWith(t, socket, shim.Options{ReconnectWait: -1, Open: o.open})

	write(t, c, approvalLink)
	require.Eventually(t, func() bool { return len(o.got()) == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{approvalLink}, o.got(), "only the local page link, once though it is in two links lists")

	write(t, c, approvalLink)
	time.Sleep(100 * time.Millisecond)
	require.Len(t, o.got(), 1, "a link already opened is not opened again")
}

func TestAutoOpenOpensNothingElse(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct{ operatedBy, origin, link string }{
		"agent-operated engine":        {mcpcontract.OperatedByAgent, localPages, approvalLink},
		"engine that says no origin":   {mcpcontract.OperatedByPerson, "", approvalLink},
		"engine that says no operator": {"", localPages, approvalLink},
		"link on the portal":           {mcpcontract.OperatedByPerson, localPages, "https://portal.basaltvault.app/approvals/a#s=q3Jv8sLk2mT0xYp1aBcD9w"},
		"link on another port":         {mcpcontract.OperatedByPerson, localPages, "http://localhost:8788/approvals/a#s=x"},
		"link on another host":         {mcpcontract.OperatedByPerson, localPages, "http://127.0.0.1:8787/approvals/a#s=x"},
		"link with a user part":        {mcpcontract.OperatedByPerson, localPages, "http://evil@localhost:8787/approvals/a"},
		"link with a prefix match":     {mcpcontract.OperatedByPerson, localPages, "http://localhost:87870/approvals/a"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			socket := filepath.Join(socketDir(t), "bot.sock")
			linkEngine(t, socket, tc.operatedBy, tc.origin, tc.link)
			o := &opened{}
			c, _ := startShimWith(t, socket, shim.Options{ReconnectWait: -1, Open: o.open})

			write(t, c, tc.link)
			_, _ = c.call(t, "query")
			time.Sleep(100 * time.Millisecond)
			require.Empty(t, o.got())
		})
	}
}

func TestAutoOpenNeverOpensALinkFromQueryRows(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	linkEngine(t, socket, mcpcontract.OperatedByPerson, localPages, approvalLink)
	o := &opened{}
	c, _ := startShimWith(t, socket, shim.Options{ReconnectWait: -1, Open: o.open})

	body, isError := c.call(t, "query")
	require.False(t, isError, "%v", body)
	time.Sleep(100 * time.Millisecond)
	require.Empty(t, o.got(), "database content is never opened")
}

func TestListPendingOpensNothing(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	linkEngine(t, socket, mcpcontract.OperatedByPerson, localPages, approvalLink)
	o := &opened{}
	c, _ := startShimWith(t, socket, shim.Options{ReconnectWait: -1, Open: o.open})

	body, isError := c.call(t, "list_pending")
	require.False(t, isError, "%v", body)
	require.Contains(t, body["items"].([]any)[0].(map[string]any)["approvalUrl"], approvalLink, "the agent still gets the link")
	time.Sleep(100 * time.Millisecond)
	require.Empty(t, o.got(), "a list restates links the person already has: a new basalt mcp opens no tab for them")
}

func TestAnOpenerThatFailsOrHangsNeverHoldsTheResult(t *testing.T) {
	t.Parallel()
	socket := filepath.Join(socketDir(t), "bot.sock")
	linkEngine(t, socket, mcpcontract.OperatedByPerson, localPages, approvalLink)
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	o := &opened{err: errors.New("no display"), block: block}
	c, _ := startShimWith(t, socket, shim.Options{ReconnectWait: -1, Open: o.open})

	write(t, c, approvalLink) // answered while the opener hangs
	require.Eventually(t, func() bool { return len(o.got()) == 1 }, 5*time.Second, 10*time.Millisecond)
	body, _ := c.call(t, "query")
	require.NotNil(t, body["rows"], "later calls are served too")
}

// request_plugin end to end through the shim: the shim uploads the folder
// and hands the engine its upload (never the client's), and the PENDING
// answer's approval link opens on a person-operated engine; the wait form's
// answer carries no link and opens nothing.
func TestRequestPluginUploadsAndOpensThePluginPage(t *testing.T) {
	t.Parallel()
	const pluginLink = localPages + "/plugins/0193a1b2-7c4d-7e8f-9a0b-1c2d3e4f5a6b#s=q3Jv8sLk2mT0xYp1aBcD9w"
	socket := filepath.Join(socketDir(t), "bot.sock")
	var mu sync.Mutex
	var metas []string
	srv := mcp.NewServer(mcp.Info{Name: "basalt", Version: "engine", OperatedBy: mcpcontract.OperatedByPerson, PagesOrigin: localPages},
		mcp.Tool{Name: "request_plugin", Call: func(ctx context.Context, args json.RawMessage) (any, error) {
			mu.Lock()
			metas = append(metas, string(mcp.Meta(ctx)))
			mu.Unlock()
			var a map[string]any
			_ = json.Unmarshal(args, &a)
			if _, wait := a["approvalId"]; wait {
				return map[string]any{"state": "RUNNING", "name": "local-ner", "instance": "default", "personMessage": "It runs."}, nil
			}
			return map[string]any{
				"state": "PENDING", "name": "local-ner", "instance": "default", "approvalUrl": pluginLink,
				"personMessage": "Approve it:\n\n" + pluginLink + "\n", "links": []toolresult.Link{{Label: "Approve the plugin local-ner", URL: pluginLink}},
			}, nil
		}},
	)
	ln, err := net.Listen("unix", socket)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = srv.Serve(ctx, conn, conn)
			}()
		}
	}()
	o := &opened{}
	var sources []string
	upload := func(_ context.Context, source string) (mcp.PluginUpload, error) {
		sources = append(sources, source)
		return mcp.PluginUpload{UploadID: "0193a4c2-7d1e-7c3a-9f00-0000000000f6", Name: "local-ner"}, nil
	}
	c, _ := startShimWith(t, socket, shim.Options{ReconnectWait: -1, Open: o.open, UploadPlugin: upload})

	res := c.request(t, "tools/call", map[string]any{
		"name": "request_plugin", "arguments": map[string]any{"source": "/home/me/local-ner"},
		"_meta": map[string]any{mcp.MetaPluginUpload: map[string]any{"uploadId": "0193a4c2-7d1e-7c3a-9f00-000000000001", "name": "forged"}},
	})
	require.Contains(t, res["content"].([]any)[0].(map[string]any)["text"], pluginLink, "the agent still gets the link")
	require.Eventually(t, func() bool { return len(o.got()) == 1 }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, []string{pluginLink}, o.got())
	require.Equal(t, []string{"/home/me/local-ner"}, sources)

	c.request(t, "tools/call", map[string]any{"name": "request_plugin", "arguments": map[string]any{"approvalId": "0193a1b2-7c4d-7e8f-9a0b-1c2d3e4f5a6b"}})
	time.Sleep(100 * time.Millisecond)
	require.Len(t, o.got(), 1, "the wait opens nothing")
	require.Len(t, sources, 1, "the wait uploads nothing")

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, metas, 2)
	require.JSONEq(t, `{"`+mcp.MetaPluginUpload+`":{"uploadId":"0193a4c2-7d1e-7c3a-9f00-0000000000f6","name":"local-ner"}}`, metas[0], "the shim's upload, not the client's")
	require.Empty(t, metas[1])
}
