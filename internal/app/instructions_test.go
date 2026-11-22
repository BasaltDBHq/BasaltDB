package engine_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	engine "github.com/basaltdbhq/basaltdb/internal/app"
)

// Soft ceiling (owner, 13 Nov): keep the server instructions to the core
// rules plus the docs link; details live in the docs.
func TestInstructionsStayShort(t *testing.T) {
	t.Parallel()
	const ceiling = 4000
	require.LessOrEqual(t, len(engine.Instructions), ceiling,
		"the instructions are %d characters; move detail to the docs", len(engine.Instructions))
}
