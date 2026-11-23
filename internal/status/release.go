package status

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// UpdateInfo is the Service's newer release, or nil.
func (sc *Service) UpdateInfo() *guidance.UpdateInfo {
	if sc.deps.Update == nil {
		return nil
	}
	n := sc.deps.Update()
	if n == nil {
		return nil
	}
	info := newUpdateInfo(*n, executablePath(), sc.deps.UpdateMessage)
	return &info
}

// newUpdateInfo is the update field for notice n, with the message for
// the binary at exe, as message words it.
func newUpdateInfo(n ReleaseNotice, exe string, message func(n ReleaseNotice, exe string) string) guidance.UpdateInfo {
	return guidance.UpdateInfo{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL, Message: message(n, exe)}
}

// UpdateNotice is the text the MCP server appends to a connection's first
// tool result: the update notice for the agent, "" when none.
func (sc *Service) UpdateNotice() string {
	if u := sc.UpdateInfo(); u != nil {
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
