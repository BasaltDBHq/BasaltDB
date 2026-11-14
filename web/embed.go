// Package web embeds the approval, revert and passkey registration pages,
// so the engine can serve them itself (CONTRACT.md, Local pages). The
// tests (*.test.mjs) are not embedded.
package web

import "embed"

// Files are the pages: approve/, revert/, register/, passkeys/, lib/*.js,
// style.css, and the Geist fonts with their license (fonts/, SIL OFL 1.1).
//
//go:embed approve/index.html revert/index.html register/index.html passkeys/index.html lib/*.js style.css fonts/*.woff2 fonts/OFL.txt
var Files embed.FS
