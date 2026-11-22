// Package web embeds the approval, revert and passkey registration pages,
// so the engine can serve them itself (CONTRACT.md, Local pages). The
// tests (*.test.mjs) are not embedded.
package web

import "embed"

// Files are the pages: approve/, revert/, plugin/ (the plugin approval
// page), setup/ (the local setup page; on the portal it asks for nothing),
// register/, connect/ (the portal's connect page), the
// portal's home page and not-found page (index.html, 404.html: static, no
// script), lib/*.js, style.css, and the Geist fonts with their license
// (fonts/, SIL OFL 1.1). The engine embeds connect/, index.html and
// 404.html for basalt portal verify but never serves them.
//
//go:embed index.html 404.html approve/index.html revert/index.html plugin/index.html register/index.html connect/index.html setup/index.html lib/*.js style.css fonts/*.woff2 fonts/OFL.txt
var Files embed.FS
