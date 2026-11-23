package guidance

// CrashStatus is status.crash: the newest saved crash report.
type CrashStatus struct {
	ID      string `json:"id"`
	Time    string `json:"time"`
	Version string `json:"version"`
	Command string `json:"command"`
	// Path is the report's file; the person can read it.
	Path string `json:"path"`
	// IssueURL is the pre-filled GitHub new-issue link, within the link
	// budget; left out when it cannot fit; the person submits the issue. Nothing is sent by basalt.
	IssueURL string `json:"issueUrl,omitempty"`
}

// AccessStatus is status.access: the tables the agent's role can read and
// write. A list is cut at maxAccessTables names; Truncated says so.
type AccessStatus struct {
	Read      []string `json:"read"`
	Write     []string `json:"write"`
	Truncated bool     `json:"truncated,omitempty"`
}

// PluginHealth is one entry of status.plugins: a plugin entry served to the
// agent and whether it is ready.
type PluginHealth struct {
	Name     string `json:"name"`
	Instance string `json:"instance"`
	Health   string `json:"health"`
	// Problem is the problem code of an entry that is not ready.
	Problem string `json:"problem,omitempty"`
}
