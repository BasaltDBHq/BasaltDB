package mcpserver

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

type shapedTool struct {
	Name        string
	Description string
	InputSchema map[string]any
	Call        func(ctx context.Context, args json.RawMessage) (any, error)
}

func TestToolsFromCarriesTheFieldsAndMeta(t *testing.T) {
	t.Parallel()
	type key struct{}
	in := []shapedTool{{
		Name: "a", Description: "d", InputSchema: map[string]any{"type": "object"},
		Call: func(ctx context.Context, _ json.RawMessage) (any, error) { return ctx.Value(key{}), nil },
	}}
	withMeta := func(ctx context.Context, m json.RawMessage) context.Context {
		return context.WithValue(ctx, key{}, string(m))
	}
	tools := ToolsFrom(in, withMeta)
	require.Len(t, tools, 1)
	require.Equal(t, "a", tools[0].Name)
	require.Equal(t, "d", tools[0].Description)
	got, err := tools[0].Call(withMetaCtx(`{"k":1}`), nil)
	require.NoError(t, err)
	require.Equal(t, `{"k":1}`, got)

	plain := ToolsFrom(in, nil)
	got, err = plain[0].Call(context.Background(), nil)
	require.NoError(t, err)
	require.Nil(t, got)
}

func withMetaCtx(meta string) context.Context {
	return withMeta(context.Background(), json.RawMessage(meta))
}
