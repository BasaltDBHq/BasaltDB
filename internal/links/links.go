// Package links builds the links to the approval, revert and passkey
// registration pages (CONTRACT.md, Pages; owner decisions, Decided Nov 12).
// The pages live at one base URL: the engine's local pages
// (http://localhost:8787) by default until hosting exists, or the hosted
// console. Every link has the same RESTful path shape on both.
package links

import (
	"strings"

	"github.com/google/uuid"
)

const (
	// HostedConsole is the hosted pages' origin (not live yet). Its
	// passkeys use RP ID basaltvault.app, which never changes.
	HostedConsole = "https://console.basaltvault.app"
	// Portal is the hosted pages' origin of an agent-operated engine and of
	// basalt init --remote (CONTRACT.md, Who operates the engine; CO-8).
	// Same RP ID as HostedConsole; renaming the console to it is its own
	// change.
	Portal = "https://portal.basaltvault.app"
	// DefaultLocal is the engine's local pages, the default base until
	// hosting exists.
	DefaultLocal = "http://localhost:8787"
)

// DefaultBudget is the longest long link, in characters of the whole URL,
// the engine hands an agent as the way to open a page (engine.json
// linkBudget, CONTRACT.md, The link budget; owner decision VC-30).
const DefaultBudget = 1800

// Page paths, the same on the local pages and the hosted console.
const (
	ApprovalsPath = "/approvals/"
	RevertsPath   = "/reverts/"
	RegisterPath  = "/passkeys/register"
	// CheckPath and ForgetPath are the passkey management page (M4.1):
	// which passkeys a device has, and forgetting a removed one.
	CheckPath  = "/passkeys/check"
	ForgetPath = "/passkeys/forget"
)

// Approval is the approval page of a held write: <base>/approvals/<id>.
func Approval(base string, id uuid.UUID) string {
	return trim(base) + ApprovalsPath + id.String()
}

// Revert is the revert page of a prepared revert: <base>/reverts/<id>.
func Revert(base string, id uuid.UUID) string {
	return trim(base) + RevertsPath + id.String()
}

// Register is the passkey registration page: <base>/passkeys/register.
func Register(base string) string {
	return trim(base) + RegisterPath
}

// Check is the passkey check page: <base>/passkeys/check.
func Check(base string) string {
	return trim(base) + CheckPath
}

// Forget is the page that forgets a removed passkey: <base>/passkeys/forget.
func Forget(base string) string {
	return trim(base) + ForgetPath
}

func trim(base string) string {
	return strings.TrimSuffix(base, "/")
}
