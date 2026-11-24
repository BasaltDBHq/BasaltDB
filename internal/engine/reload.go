package engine

import (
	"context"
	"errors"
)

// ErrReload is what Serve and Run return after they stopped to serve the
// config again: an agent's connect-only setup changed (the person confirmed
// its database, or basalt init --remote replaced the pending setup). The
// caller reads the config again and runs the engine anew, in this process.
var ErrReload = errors.New("the engine stopped to serve its config again")

// UpgradeOrReload is the restart's trigger: an upgraded binary (up, when
// set) or a reload asked for on reload. A reload closes reloading first,
// so RunWith returns ErrReload, not ErrRestart.
func UpgradeOrReload(up UpgradeFunc, reload <-chan struct{}, reloading chan struct{}) UpgradeFunc {
	return func(ctx context.Context) error {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		upgraded := make(chan error, 1)
		if up == nil {
			upgraded = nil
		} else {
			go func() { upgraded <- up(ctx) }()
		}
		select {
		case <-reload:
			close(reloading)
			// The watch ends before the next run watches the same binary.
			cancel()
			if upgraded != nil {
				if err := <-upgraded; err != nil {
					return nil // the cancel above: a reload, not an error
				}
			}
			return nil
		case err := <-upgraded:
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
