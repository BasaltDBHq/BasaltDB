package agentmcp

import (
	"context"
	"encoding/json"

	agentsvc "github.com/basaltdbhq/basaltdb/internal/agent"
	"github.com/basaltdbhq/basaltdb/internal/platform/mcpserver"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/lib/pagination"
)

// --- describe ---

// describeArgs is the describe tool's input (api/mcp/tools/describe.json):
// the search form's paging embeds pagination.Params, as every list does.
// query and resource are pointers so an empty one is refused, not taken for
// an absent one.
type describeArgs struct {
	pagination.Params
	Query         *string `json:"query" validate:"omitempty,min=1,max=100"`
	Resource      *string `json:"resource" validate:"omitempty,min=1,max=1000"`
	IfFingerprint *string `json:"ifFingerprint" validate:"omitempty,max=128"`
}

// check refuses arguments that belong to another form than the one given.
func (a describeArgs) check() error {
	switch {
	case a.Sort != "":
		return &guidance.ArgumentError{Message: "invalid arguments: describe has no sort; search results come ranked"}
	case a.Query != nil && a.Resource != nil:
		return &guidance.ArgumentError{Message: "invalid arguments: give query (search) or resource (describe one resource), not both"}
	case a.IfFingerprint != nil && a.Resource == nil:
		return &guidance.ArgumentError{Message: "invalid arguments: ifFingerprint goes with resource"}
	case (a.Limit != 0 || a.Cursor != "") && a.Query == nil:
		return &guidance.ArgumentError{Message: "invalid arguments: limit and cursor go with query"}
	}
	return nil
}

type describeOverviewResult struct {
	Form string `json:"form"`
	agentsvc.Overview
}

type describeSearchResult struct {
	Form       string                `json:"form"`
	Items      []agentsvc.SearchItem `json:"items"`
	NextCursor string                `json:"nextCursor,omitempty"`
}

// describe serves the three forms, told apart by their arguments, with every
// error within the codes describe declares.
func (h handlers) describe(ctx context.Context, raw json.RawMessage) (any, error) {
	out, err := h.describeForm(ctx, raw)
	if err != nil {
		return nil, h.svc.DescribeError(err)
	}
	return out, nil
}

func (h handlers) describeForm(ctx context.Context, raw json.RawMessage) (any, error) {
	var args describeArgs
	if err := guidance.DecodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if err := args.check(); err != nil {
		return nil, err
	}
	switch {
	case args.Query != nil:
		p := agentsvc.DescribeSearchParams{Params: args.Params, Query: *args.Query}
		p.ApplyDefaultsAndClamp()
		page, err := h.svc.DescribeSearch(ctx, p)
		if err != nil {
			return nil, err
		}
		return describeSearchResult{Form: agentsvc.FormSearch, Items: page.Items, NextCursor: page.NextCursor}, nil
	case args.Resource != nil:
		ifFingerprint := ""
		if args.IfFingerprint != nil {
			ifFingerprint = *args.IfFingerprint
		}
		res, err := h.svc.DescribeResource(ctx, *args.Resource, ifFingerprint)
		if err != nil {
			return nil, err
		}
		// The resource writes its own members in order, form first.
		res.Form = agentsvc.FormResource
		return res, nil
	}
	o, err := h.svc.DescribeOverview(ctx)
	if err != nil {
		return nil, err
	}
	return describeOverviewResult{Form: agentsvc.FormOverview, Overview: o}, nil
}

// DescribeTools are the tools that describe the database.
func DescribeTools(svc Agent, mount func(name string, call func(context.Context, json.RawMessage) (any, error)) mcpserver.Tool) []mcpserver.Tool {
	h := handlers{svc: svc}
	return []mcpserver.Tool{
		mount(guidance.ToolDescribe, h.describe),
	}
}
