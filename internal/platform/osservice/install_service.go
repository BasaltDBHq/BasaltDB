package osservice

import (
	"context"
	"io"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// InstallService plans the service install of spec on this machine and
// applies it (only printing the steps on out for dryRun), each step's
// output on out and errw; a service manager step skipped where no service
// manager runs is no error (Settle).
func InstallService(ctx context.Context, spec servicespec.Spec, dryRun bool, out, errw io.Writer) error {
	sys := OSSystem{Stdout: out, Stderr: errw}
	steps, err := InstallPlan(ctx, sys, spec)
	if err != nil {
		return err
	}
	return Settle(Apply(ctx, sys, steps, dryRun, out), sys, spec.GOOS)
}
