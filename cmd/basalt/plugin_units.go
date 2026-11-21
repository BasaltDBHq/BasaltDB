package main

import (
	"errors"
	"fmt"
	"io"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/engine/config"
	"github.com/basaltdbhq/basaltdb/internal/engine/service"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// servicePluginHost is service.HostFor.
func servicePluginHost(cfg config.Config, goos, configPath, engineUser string) service.PluginHost {
	return service.HostFor(cfg, goos, configPath, engineUser)
}

// unitEntry is service.EntryFor.
func unitEntry(p config.Plugin, v plugin.Verified) (service.PluginEntry, bool) {
	return service.EntryFor(p, v)
}

// withPluginUnits is spec with cfg's plugin units: on install every local
// entry whose copy verifies, on uninstall every entry by name.
func withPluginUnits(spec service.Spec, cfg config.Config, install bool, warn io.Writer) service.Spec {
	h := servicePluginHost(cfg, spec.GOOS, spec.ConfigPath, spec.User)
	spec.StateDir, spec.SocketDir, spec.CredentialFiles = h.StateDir, h.SocketDir, h.CredentialFiles
	if install {
		spec.Plugins = serviceUnitEntries(cfg, spec.GOOS, spec.ConfigPath, warn)
	} else {
		spec.Plugins = serviceUnitNames(cfg)
	}
	return spec
}

// serviceUnitEntries are cfg's local entries whose installed copies verify,
// for basalt service install and uninstall. An entry that fails is left
// out with a line on warn: the engine refuses it too (PLUGIN_NOT_TRUSTED),
// and uninstall still removes its unit by name.
func serviceUnitEntries(cfg config.Config, goos, configPath string, warn io.Writer) []service.PluginEntry {
	if len(cfg.Plugins) == 0 {
		return nil
	}
	dir := filepath.Dir(configPath)
	root, rootErr := plugin.Root(plugin.ModeService, goos, dir)
	trust, trustErr := plugin.NewTrustStore(plugin.ModeService, goos, dir)
	var out []service.PluginEntry
	for _, p := range cfg.Plugins {
		k := p.Key()
		if rootErr != nil || trustErr != nil {
			fmt.Fprintf(warn, "basalt: plugin %s: its service unit is left as it is: the plugin directory cannot be read\n", k)
			continue
		}
		v, err := plugin.Verify(root, k, p.ManifestSHA256, trust, plugin.ModeService)
		if err != nil {
			fmt.Fprintf(warn, "basalt: plugin %s: its service unit is left as it is: %s\n", k, terminalText(verifyFailure(err)))
			continue
		}
		if e, ok := unitEntry(p, v); ok {
			out = append(out, e)
		}
	}
	return out
}

// verifyFailure names the failed check of a verification in fixed words.
func verifyFailure(err error) string {
	if ve, ok := err.(*plugin.VerifyError); ok { //nolint:errorlint // Verify returns it unwrapped
		return plugin.VerifyFailure(ve)
	}
	return "it could not be verified"
}

// serviceUnitNames are cfg's entries by name only, for uninstall: their
// units, directories and users are removed whether or not their copies
// still verify.
func serviceUnitNames(cfg config.Config) []service.PluginEntry {
	out := make([]service.PluginEntry, 0, len(cfg.Plugins))
	for _, p := range cfg.Plugins {
		k := p.Key()
		out = append(out, service.PluginEntry{Name: k.Name, Instance: k.Instance})
	}
	return out
}

// engineUserOf is the engine's OS user: the owner of its config directory,
// which basalt service install gives it.
func engineUserOf(configPath string) (string, error) {
	uid, err := rootTrustedOwner(filepath.Dir(configPath))
	if err != nil {
		return "", err
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", err
	}
	return u.Username, nil
}

// unitAction is what a basalt plugin command does to an entry's service
// unit in service mode.
type unitAction int

const (
	unitWrite  unitAction = iota // write the unit; start it when enabled
	unitStop                     // stop it and keep it
	unitRemove                   // stop it and delete it, its directory and its user
)

// applyUnit runs action for entry p (verified as v, nil for unitStop and
// unitRemove) on the service manager, in service mode only. engine.json is
// already written: on failure the person is told to run basalt service
// install, which writes every unit again.
func (e *pluginEnv) applyUnit(action unitAction, p config.Plugin, v *plugin.Verified) error {
	if !e.cfg.Service() {
		return nil
	}
	k := p.Key()
	sys := e.c.host.System(e.c.stderr, e.c.stderr)
	var steps []service.Step
	var err error
	switch action {
	case unitWrite:
		entry, local := unitEntry(p, *v)
		if !local {
			// A remote entry has no unit; one left from a local endpoint goes.
			steps, err = service.PluginRemoveSteps(sys, e.c.goos, k.Name, k.Instance)
			break
		}
		var engineUser string
		if engineUser, err = engineUserOf(e.configPath); err != nil {
			break
		}
		h := servicePluginHost(e.cfg, e.c.goos, e.configPath, engineUser)
		steps, err = service.PluginInstallPlan(e.c.ctx, sys, h, []service.PluginEntry{entry})
	case unitStop:
		steps, err = service.PluginStopSteps(e.c.goos, k.Name, k.Instance)
	case unitRemove:
		steps, err = service.PluginRemoveSteps(sys, e.c.goos, k.Name, k.Instance)
	}
	if err == nil && len(steps) > 0 {
		fmt.Fprintf(e.c.stderr, "basalt: plugin %s's service unit:\n", k)
		err = service.Settle(service.Apply(e.c.ctx, sys, steps, false, e.c.stderr), sys, e.c.goos)
	}
	if err != nil {
		return fmt.Errorf("plugin %s: engine.json was changed, but its service unit was not: %w. "+
			"Run sudo basalt service install to set up every plugin's unit again", k, err)
	}
	return nil
}

// checkAgentOSUser refuses an agent's OS user that is the engine's own
// user or is in the engine's group (named as the engine's user): that
// group reaches every plugin socket in service mode, and the engine's
// config directory. When the group does not exist yet (the install makes
// it), no one is in it. A lookup that fails otherwise refuses.
func checkAgentOSUser(osUser, engineUser string) error {
	return checkAgentOSUserWith(osUser, engineUser, user.LookupGroup, osUserGroups)
}

func checkAgentOSUserWith(osUser, engineUser string, lookupGroup func(string) (*user.Group, error),
	groups func(string) ([]string, error),
) error {
	if strings.HasPrefix(osUser, "basalt-plugin-") || strings.HasPrefix(osUser, "_basalt-plugin-") {
		return fmt.Errorf("%w: --os-user %s is named as a plugin's OS user; Basalt keeps those names for plugins", errUsage, osUser)
	}
	if osUser == engineUser {
		return fmt.Errorf("%w: --os-user %s is the engine's own OS user; give the agent an OS user of its own", errUsage, osUser)
	}
	g, err := lookupGroup(engineUser)
	var unknown user.UnknownGroupError
	if errors.As(err, &unknown) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the engine's group %s cannot be looked up, so --os-user %s cannot be checked: %w", engineUser, osUser, err)
	}
	gids, err := groups(osUser)
	if err != nil {
		return fmt.Errorf("the groups of --os-user %s cannot be read, so it cannot be checked: %w", osUser, err)
	}
	if slices.Contains(gids, g.Gid) {
		return fmt.Errorf("%w: --os-user %s is in the engine's group %s, which reaches plugin sockets and the engine's config; "+
			"take it out of that group or give the agent another OS user", errUsage, osUser, engineUser)
	}
	return nil
}

// osUserGroups are an OS user's group ids, its primary group included.
func osUserGroups(name string) ([]string, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	gids, err := u.GroupIds()
	if err != nil {
		return nil, err
	}
	return append(gids, u.Gid), nil
}

// checkUserClash refuses entry k when another entry of cfg would run as the
// same OS user on Linux or macOS (a shortened user name matched): two
// entries never share a user, a socket or a directory.
func (e *pluginEnv) checkUserClash(cfg config.Config, k plugin.EntryKey) error {
	keys := make([]plugin.EntryKey, 0, len(cfg.Plugins))
	for _, p := range cfg.Plugins {
		keys = append(keys, p.Key())
	}
	if o := service.UserClash(k.Name, k.Instance, keys); o != nil {
		return fmt.Errorf("plugin %s would run as the same OS user as plugin %s; nothing was written. Add it with another --instance", k, *o)
	}
	return nil
}
