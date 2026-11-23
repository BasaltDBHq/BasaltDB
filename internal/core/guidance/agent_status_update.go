package guidance

// UpdateInfo is the update field of status and of describe's overview: the
// newer release and what the agent tells the person.
type UpdateInfo struct {
	Current  string `json:"current"`
	Latest   string `json:"latest"`
	Security bool   `json:"security"`
	URL      string `json:"url"`
	// Message starts WARNING: or SECURITY UPDATE: and is meant to be
	// relayed to the person.
	Message string `json:"message"`
}
