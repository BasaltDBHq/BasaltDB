package stepcatalogtest

// PluginErrorKeys are the CaseKeys of the error cases the plugin package runs
// on its own step builders (see RevertErrorKeys).
func PluginErrorKeys() []string {
	const tool = "request_plugin"
	keys := make([]string, 0, 17)
	for _, reason := range []string{"AGENT_OPERATED", "SAME_USER_MODE", "NO_LOCAL_PAGES", "NO_PORTAL_LINK"} {
		keys = append(keys, CaseKey("PLUGIN_REFUSED", reason, tool))
	}
	for _, reason := range []string{
		"AGENT_NOT_ALLOWED", "BAD_MANIFEST", "NOT_TRUSTED", "UNKNOWN_AGENT", "UNSAFE_PATH", "TOO_MANY_PENDING", "GUARD_OUTDATED",
		"DATABASE_UNREACHABLE", "NAME_TAKEN", "CONFIG_ENTRY", "TOO_LARGE", "TOO_MANY_UPLOADS", "ENGINE_IS_ROOT",
	} {
		keys = append(keys, CaseKey("PLUGIN_REFUSED", reason, tool))
	}
	return sorted(keys...)
}

// PluginResultKeys are the result cases the plugin package runs.
func PluginResultKeys() []string {
	return sorted(
		"request_plugin|APPROVED",
		"request_plugin|ENDED",
		"request_plugin|NARROWED",
		"request_plugin|REMOVED",
		"request_plugin|REQUESTED",
		"request_plugin|RUNNING",
		"request_plugin|WAIT_ENDED",
	)
}
