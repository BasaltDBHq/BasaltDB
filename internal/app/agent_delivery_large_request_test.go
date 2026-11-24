package app

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	mcpcontract "github.com/basaltdbhq/basaltdb/api/mcp"
	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// TestTooLargeMessagesKeepToTheirLimit: every REQUEST_TOO_LARGE message
// (local pages; the portal at most 15 MiB and over it; person-run and
// agent-operated; a hold and a revert) keeps to the personMessage limit,
// even with a long config path and saved flags.
func TestTooLargeMessagesKeepToTheirLimit(t *testing.T) {
	t.Parallel()
	longConfig := "/Users/alice/Library/Application Support/basalt/" + strings.Repeat("x", 60) + "/engine.json"
	what := "The revert of task " + uuid.NewString()
	for _, operatedBy := range []string{"", mcpcontract.OperatedByAgent} {
		for _, config := range []string{"", longConfig} {
			for _, base := range []string{links.DefaultLocal, links.Portal} {
				for _, cost := range []int64{2 << 20, 20 << 20} {
					s := operatedService(t, "linux", config, operatedBy, func(d *Deps) { d.Core.PagesBase = base })
					for _, isRevert := range []bool{false, true} {
						msg := s.delivery.TooLargeMessage(what, cost, time.Now(), isRevert)
						require.NoError(t, guidance.CheckPersonMessage(msg), "%s %s %s %d %v: %d characters", operatedBy, config, base, cost, isRevert, len(msg))
					}
				}
			}
		}
	}
}
