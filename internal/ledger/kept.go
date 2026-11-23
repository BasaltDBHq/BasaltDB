package ledger

import (
	"log/slog"

	"github.com/basaltdbhq/basaltdb/internal/core/action"
)

// KeptSetAside reads the pins agent set aside after reinstalls from its
// pin (chainpin.Pin.SetAside), for the reinstall notice. A pin that cannot
// be read is logged and adds nothing: the ledger still shows the notice.
func KeptSetAside(pins Pins, agent string, log *slog.Logger) func() []action.SetAside {
	return func() []action.SetAside {
		p, _, err := pins.Load(agent)
		if err != nil {
			log.Warn("read the kept copy of set-aside pins", "agent", agent, "err", err)
		}
		return p.SetAside
	}
}
