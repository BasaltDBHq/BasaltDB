package mcp_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/basaltdbhq/basaltdb/internal/adapter/inbound/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/toolresult"
)

func TestToolErrorAliasIsOneType(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", &toolresult.ToolError{Code: "X", Message: "m"})
	var got *mcp.ToolError
	require.True(t, errors.As(err, &got))
	require.Equal(t, "X", got.Code)
	require.Equal(t, toolresult.ActionStop, mcp.ActionStop)
}
