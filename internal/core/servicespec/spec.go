package servicespec

// Spec is what the unit runs.
type Spec struct {
	// GOOS is linux or darwin.
	GOOS string
	// Binary is the absolute path of the basalt binary.
	Binary string
	// ConfigPath is the engine config file.
	ConfigPath string
	// User is the OS user the engine runs as.
	User string
	// Files are written mode 0600, owned by User, before the service
	// starts: the engine config and an agent's credential from basalt init.
	Files []File
	// MemoryMB is the engine's pii.maxMemoryMB; 0 is the default. The unit
	// limits the engine's memory from it, so pressure throttles or stops
	// only the engine's own OS user (M5.1 plan, section 5).
	MemoryMB int
	// Plugins are the config's local plugin entries: install makes each
	// one's OS user, socket directory and unit, uninstall removes them.
	Plugins []PluginEntry
	// StateDir and SocketDir are the engine's, from its config (the
	// defaults when empty), and CredentialFiles every agent's and plugin's
	// credential file: a plugin's unit makes them inaccessible.
	StateDir, SocketDir string
	CredentialFiles     []string
}

// File is one file the install writes for the engine.
type File struct {
	Path    string
	Content []byte
}
