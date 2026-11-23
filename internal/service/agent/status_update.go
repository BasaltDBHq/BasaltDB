package agent

import (
	"os"

	"github.com/basaltdbhq/basaltdb/internal/core/guidance"
)

// updateInfo is the Service's newer release, or nil.
func (sc *statusKeeper) updateInfo() *guidance.UpdateInfo {
	if sc.deps.Update == nil {
		return nil
	}
	n := sc.deps.Update()
	if n == nil {
		return nil
	}
	info := NewUpdateInfo(*n, executablePath(), sc.deps.UpdateMessage)
	return &info
}

// NewUpdateInfo is the update field for notice n, with the message for
// the binary at exe, as message words it.
func NewUpdateInfo(n UpdateNotice, exe string, message func(n UpdateNotice, exe string) string) guidance.UpdateInfo {
	return guidance.UpdateInfo{Current: n.Current, Latest: n.Latest, Security: n.Security, URL: n.URL, Message: message(n, exe)}
}

// UpdateNotice is the text the MCP server appends to a connection's first
// tool result: the update notice for the agent, "" when none.
func (sc *statusKeeper) UpdateNotice() string {
	if u := sc.updateInfo(); u != nil {
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
