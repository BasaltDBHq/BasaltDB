package main

import (
	"fmt"
	"io"
	"path/filepath"

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
			fmt.Fprintf(warn, "basalt: plugin %s: its service unit is left as it is: %s\n", k, cli.TerminalText(plugin.BasaltVerifyFailure(err)))
			continue
		}
		if e, ok := unitEntry(p, v); ok {
			out = append(out, e)
		}
	}
	return out
}
