// Package web embeds the approval, revert and passkey registration pages,
// so the engine can serve them itself (CONTRACT.md, Local pages). The
// tests (*.test.mjs) are not embedded.
package web

import "embed"

// Files are the pages: approve/, revert/, plugin/ (the plugin approval
// page), register/, passkeys/, engines/ (the portal's pin page), the
// portal's home page and not-found page (index.html, 404.html: static, no
// script), lib/*.js, style.css, and the Geist fonts with their license
// (fonts/, SIL OFL 1.1). The engine embeds engines/, index.html and 404.html
// for basalt portal verify but never serves them.
//
//go:embed index.html 404.html approve/index.html revert/index.html plugin/index.html register/index.html passkeys/index.html engines/index.html lib/*.js style.css fonts/*.woff2 fonts/OFL.txt
var Files embed.FS
