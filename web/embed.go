// Package web embeds the approval, revert and passkey registration pages,
// so the engine can serve them itself (CONTRACT.md, Local pages). The
// tests (*.test.mjs) are not embedded.
package web

import "embed"

// Files are the pages: approve/, revert/, register/, passkeys/, lib/*.js, style.css.
//
//go:embed approve/index.html revert/index.html register/index.html passkeys/index.html lib/*.js style.css
var Files embed.FS
