package agent

import (
	"os"
)

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

// updateInfo is the Service's newer release, or nil.
func (s *Service) updateInfo() *UpdateInfo {
	if s.deps.Status.Update == nil {
		return nil
	}
	n := s.deps.Status.Update()
	if n == nil {
		return nil
	}
	info := NewUpdateInfo(*n, executablePath(), s.deps.Status.UpdateMessage)
	return &info
}

// NewUpdateInfo is the update field for notice n, with the message for
// the binary at exe, as message words it.
func NewUpdateInfo(n UpdateNotice, exe string, message func(n UpdateNotice, exe string) string) UpdateInfo {
	return UpdateInfo{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL, Message: message(n, exe)}
}

// UpdateNotice is the text the MCP server appends to a connection's first
// tool result: the update notice for the agent, "" when none.
func (s *Service) UpdateNotice() string {
	if u := s.updateInfo(); u != nil {
		return u.Message
	}
	return ""
}

// executablePath is this binary's path, for the Homebrew hint; "" when
// unknown.
func executablePath() string {
	p, _ := os.Executable()
	return p
}
