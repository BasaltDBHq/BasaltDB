package pluginmodel

// UnitPlan is what a service engine expects of one local entry's OS unit:
// the unit file it would write for the entry, where it is installed, and the
// OS user and socket the unit runs it under.
type UnitPlan struct {
	// File is the unit file's expected content, byte for byte.
	File string
	// Unit is the unit's name (systemd unit, launchd label); UnitPath is the
	// unit file or the launch daemon's plist.
	Unit, UnitPath string
	// User is the entry's OS user; Socket is the socket the unit hands the
	// plugin.
	User, Socket string
}
