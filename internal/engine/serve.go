package engine

import (
	"context"
	"errors"
	"log/slog"
)

// BinaryRestart is how the engine restarts onto an upgraded binary: Upgrade
// says when (nil turns it off) and Exec runs the new binary in this process.
type BinaryRestart struct {
	Upgrade UpgradeFunc
	Exec    func() error
}

// ServeRestarting runs the engine and, each time it stops for an upgrade,
// runs the new binary in this process; each time it stops for a reload, it
// reads the config again and runs the engine anew. When that fails, this binary serves
// on, until the binary changes again. run is given when the engine restarts.
func ServeRestarting(ctx context.Context, run func(context.Context, Restart) error, r BinaryRestart, reload func() error, log *slog.Logger) error {
	for {
		err := run(ctx, Restart{Upgrade: r.Upgrade})
		if errors.Is(err, ErrReload) && ctx.Err() == nil {
			// Same binary, same process: the config is read again and the
			// engine serves anew. A config it cannot read now stops it.
			log.Info("serving the engine config again: an agent's setup changed")
			if err := reload(); err != nil {
				return err
			}
			continue
		}
		if !errors.Is(err, ErrRestart) || ctx.Err() != nil {
			// A stop that came during the restart wins: never run the new
			// binary after the engine was told to stop.
			return err
		}
		log.Info("restarting onto the upgraded binary")
		err = r.Exec()
		log.Error("could not run the upgraded binary; this one serves on", "err", err)
	}
}
