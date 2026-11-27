package osservice

import (
	"context"

	"github.com/basaltdbhq/basaltdb/internal/core/servicespec"
)

// PluginInstallPlan is pluginInstallSteps for each of ps, after the base
// directories (on macOS after the log directory's steps too): the plugin
// part of service install, for the tests.
func PluginInstallPlan(ctx context.Context, sys System, h servicespec.PluginHost, ps []servicespec.PluginEntry) ([]Step, error) {
	if len(ps) == 0 {
		return nil, nil
	}
	steps, err := PluginBaseSteps(h.GOOS)
	if err != nil {
		return nil, err
	}
	var ids *idAllocator
	if h.GOOS == goosDarwin {
		if ids, err = newIDAllocator(ctx, sys); err != nil {
			return nil, err
		}
		// A Mac set up by an earlier install has the engine user's log
		// directory: plugin add and enable fix it as service install does,
		// so no separate step is needed before a plugin's log can be made.
		steps = append(darwinLogSteps(h.EngineUser), steps...)
	}
	more, err := pluginEntriesSteps(sys, h, ps, ids)
	if err != nil {
		return nil, err
	}
	return append(steps, more...), nil
}

// PluginRemoveSteps stop and delete exactly what pluginInstallSteps made for
// entry (name, instance), to clean up after a test that installed it: its unit, on macOS its log rule, its log and the
// one copy newsyslog moved aside, its socket directory and, when it exists,
// its OS user and group. Names come from the entry, never from a listing.
func PluginRemoveSteps(sys System, goos, name, instance string) ([]Step, error) {
	n, err := NamesFor(goos, name, instance)
	if err != nil {
		return nil, err
	}
	installed := sys.Exists(n.UnitPath)
	hasUser := sys.UserExists(n.User)
	if !installed && !hasUser && !sys.Exists(n.SocketDir) && !hasLog(sys, n) {
		// Nothing of this entry is on the machine (a remote entry).
		return nil, nil
	}
	var steps []Step
	if goos == goosDarwin {
		if installed {
			steps = append(steps, bootout("system/"+n.Unit))
		}
		// The rule before the log, so newsyslog never rotates a log being
		// removed.
		steps = append(steps,
			Step{Kind: StepRemove, Path: n.UnitPath},
			Step{Kind: StepRemove, Path: n.LogRule},
			Step{Kind: StepRemove, Path: n.Log},
			Step{Kind: StepRemove, Path: n.Log + rotatedSuffix},
		)
	} else {
		if installed {
			steps = append(steps, tryRun("systemctl", "disable", "--now", n.Unit))
		}
		steps = append(steps, Step{Kind: StepRemove, Path: n.UnitPath}, tryRun("systemctl", "daemon-reload"))
	}
	steps = append(steps, Step{Kind: StepRemoveTree, Path: n.SocketDir})
	if hasUser {
		if goos == goosDarwin {
			steps = append(steps,
				run("dscl", ".", "-delete", "/Users/"+n.User),
				run("dscl", ".", "-delete", "/Groups/"+n.User),
			)
		} else {
			// useradd --user-group made the group; userdel deletes it with
			// the user.
			steps = append(steps, run("userdel", n.User))
		}
	}
	return steps, nil
}

// hasLog reports whether a macOS entry's log, its moved copy or its rule is
// on the machine; a Linux entry has none.
func hasLog(sys System, n servicespec.PluginNames) bool {
	if n.Log == "" {
		return false
	}
	return sys.Exists(n.Log) || sys.Exists(n.Log+rotatedSuffix) || sys.Exists(n.LogRule)
}

// BreakingHelpers is config_epoch, for the test that runs it.
func BreakingHelpers() string { return breakingHelpers }
