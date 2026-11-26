package status

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/guardmodel"
	"github.com/basaltdbhq/basaltdb/internal/core/passkey"
)

// HomeHealth is what the home page shows of the agent: the guard's state and
// how many passkeys can sign on the pages' origin, as status counts them. A
// read that fails is nil.
func (sc *Service) HomeHealth(ctx context.Context) (guard *guardmodel.Status, passkeys *int) {
	if st, err := sc.deps.Probe.GuardStatus(ctx); err == nil {
		guard = &st
	} else {
		sc.core.Log.Debug("home: read the guard", "err", err)
	}
	all, err := sc.deps.Passkeys.Passkeys(ctx)
	if err != nil {
		sc.core.Log.Debug("home: count passkeys", "err", err)
		return guard, nil
	}
	keys, _ := passkey.OnPagesOrigin(all, sc.core.PagesBase)
	n := len(keys)
	return guard, &n
}
