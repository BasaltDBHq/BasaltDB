package main

import (
	"errors"
	"fmt"
	"io"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/basaltdbhq/basaltdb/internal/app"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"

	"github.com/basaltdbhq/basaltdb/internal/config"
	"github.com/basaltdbhq/basaltdb/internal/core/pluginmodel"
	"github.com/basaltdbhq/basaltdb/internal/plugin"
)

// servicePluginHost is service.HostFor.
func servicePluginHost(cfg config.Config, goos, configPath, engineUser string) app.OSPluginHost {
	return app.OSHostFor(cfg, goos, configPath, engineUser)
}

// unitEntry is service.EntryFor.
func unitEntry(p config.Plugin, v pluginmodel.Verified) (app.OSPluginUnit, bool) {
	return app.OSEntryFor(p, v)
}

// withPluginUnits is spec with cfg's plugin units: every local entry whose
// copy verifies.
func withPluginUnits(spec app.OSSpec, cfg config.Config, warn io.Writer) app.OSSpec {
	h := servicePluginHost(cfg, spec.GOOS, spec.ConfigPath, spec.User)
	spec.StateDir, spec.SocketDir, spec.CredentialFiles = h.StateDir, h.SocketDir, h.CredentialFiles
	spec.Plugins = serviceUnitEntries(cfg, spec.GOOS, spec.ConfigPath, warn)
	return spec
}

// serviceUnitEntries are cfg's local entries whose installed copies verify,
// for basalt service install. An entry that fails is left out with a line
// on warn: the engine refuses it too (PLUGIN_NOT_TRUSTED).
func serviceUnitEntries(cfg config.Config, goos, configPath string, warn io.Writer) []app.OSPluginUnit {
	if len(cfg.Plugins) == 0 {
		return nil
	}
	dir := filepath.Dir(configPath)
	root, rootErr := plugin.Root(pluginmodel.ModeService, goos, dir)
	trust, trustErr := plugin.NewTrustStore(pluginmodel.ModeService, goos, dir)
	var out []app.OSPluginUnit
	for _, p := range cfg.Plugins {
		k := p.Key()
		if rootErr != nil || trustErr != nil {
			fmt.Fprintf(warn, "basalt: plugin %s: its service unit is left as it is: the plugin directory cannot be read\n", k)
			continue
		}
		v, err := plugin.Verify(root, k, p.ManifestSHA256, trust, pluginmodel.ModeService)
		if err != nil {
			fmt.Fprintf(warn, "basalt: plugin %s: its service unit is left as it is: %s\n", k, cli.TerminalText(verifyFailure(err)))
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
	if ve, ok := err.(*pluginmodel.VerifyError); ok { //nolint:errorlint // Verify returns it unwrapped
		return plugin.VerifyFailure(ve)
	}
	return "it could not be verified"
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
		return fmt.Errorf("%w: --os-user %s is named as a plugin's OS user; Basalt keeps those names for plugins", cli.ErrUsage, osUser)
	}
	if osUser == engineUser {
		return fmt.Errorf("%w: --os-user %s is the engine's own OS user; give the agent an OS user of its own", cli.ErrUsage, osUser)
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
			"take it out of that group or give the agent another OS user", cli.ErrUsage, osUser, engineUser)
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
