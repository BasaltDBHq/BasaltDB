package app

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

// A field agentHost leaves zero is an adapter the agent cannot reach: a nil
// function panics on first use, and a nil error value would turn the
// ledger's NOT_FOUND into an INTERNAL tool error. Every field must be set.
func TestAgentHostFillsEveryField(t *testing.T) {
	t.Parallel()
	h := reflect.ValueOf(agentHost())
	for i := range h.NumField() {
		require.False(t, h.Field(i).IsZero(), "agentHost leaves agent.Host.%s unset", h.Type().Field(i).Name)
	}
}
