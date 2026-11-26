package setup

import (
	"errors"
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
)

// ErrUsage marks a usage error of basalt init --remote: a flag or an agent
// name it cannot take. The CLI answers it as its own usage error.
var ErrUsage = errors.New("usage")

// ChooseVault is the vault choice for an engine whose pages base is
// pagesURL: --vault when given, else the default (on with
// --operated-by=agent on the portal's pages, off otherwise, as with
// --dev-local-pages). --vault=on needs the portal's
// pages: a passkey on any other origin cannot sign on the portal, and the
// engine never dials out for them, so it is a usage error (ErrUsage).
// defaultWhy says why the default is off.
func ChooseVault(given VaultMode, operatedBy OperatedBy, pagesURL, defaultWhy string) (VaultChoice, error) {
	if given == VaultModeOn && pagesURL != links.Portal {
		return VaultChoice{}, fmt.Errorf("%w: --vault=on needs the portal's pages (%s), and these are %s: "+
			"a passkey registered there cannot sign on the portal, so the engine would not use the Vault", ErrUsage, links.Portal, pagesURL)
	}
	if operatedBy == OperatedByAgent && pagesURL == links.Portal {
		return VaultChoice{Given: given, Def: VaultModeOn, Why: "default for --operated-by=agent; --vault=off to turn it off"}, nil
	}
	return VaultChoice{Given: given, Def: VaultModeOff, Why: defaultWhy}, nil
}
