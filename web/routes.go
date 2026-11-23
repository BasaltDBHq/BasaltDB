package web

import "github.com/basaltdbhq/basaltdb/internal/core/links"

// PageRoute is a page the engine serves at a RESTful path. ID routes take
// one uuid after Path (/approvals/<id>); the others are exactly Path. The
// portal's static host must rewrite the same paths to the same files:
// _redirects, which a test checks against PageRoutes.
type PageRoute struct {
	Path string
	ID   bool
	File string
}

// PageRoutes are the pages, in the order they are registered.
var PageRoutes = []PageRoute{
	{Path: links.ApprovalsPath, ID: true, File: "approve/index.html"},
	{Path: links.RevertsPath, ID: true, File: "revert/index.html"},
	// The plugin approval page: the same fragments as the approval page
	// (#2., #s=, #h=).
	{Path: links.PluginsPath, ID: true, File: "plugin/index.html"},
	{Path: links.RegisterPath, File: "register/index.html"},
}

// PortalRoutes are pages only the portal serves: the connect page
// (CONTRACT.md, The connect page), where the connect service runs a setup
// code. The engine embeds its file, so basalt portal verify checks it, but
// never serves it: the connect service allows only the portal.
var PortalRoutes = []PageRoute{
	{Path: links.ConnectPath, File: "connect/index.html"},
}

// PortalPages are every page the portal serves: PageRoutes, then
// PortalRoutes.
func PortalPages() []PageRoute {
	return append(append([]PageRoute{}, PageRoutes...), PortalRoutes...)
}
