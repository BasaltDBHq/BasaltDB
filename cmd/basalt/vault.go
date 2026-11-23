package main

import (
	"fmt"

	"github.com/basaltdbhq/basaltdb/internal/core/links"
	"github.com/basaltdbhq/basaltdb/internal/platform/cli"
	"github.com/basaltdbhq/basaltdb/internal/setup"
)

// flagVault is --vault on basalt init, init --remote and service install.
const flagVault = "vault"

// flagVaultDefault is service install's vault for a config that has none:
// init passes it instead of --vault when the person gave none.
const flagVaultDefault = "vault-default"

// chooseVault is the vault choice for an engine whose pages base is
// pagesURL: --vault when given, else the default (on with
// --operated-by=agent on the portal's pages, off otherwise, as with
// --dev-local-pages). --vault=on needs the portal's
// pages: a passkey on any other origin cannot sign on the portal, and the
// engine never dials out for them, so it is a usage error (exit 2).
// defaultWhy says why the default is off.
func chooseVault(given setup.VaultMode, operatedBy OperatedBy, pagesURL, defaultWhy string) (setup.VaultChoice, error) {
	if given == setup.VaultModeOn && pagesURL != links.Portal {
		return setup.VaultChoice{}, fmt.Errorf("%w: --vault=on needs the portal's pages (%s), and these are %s: "+
			"a passkey registered there cannot sign on the portal, so the engine would not use the Vault", cli.ErrUsage, links.Portal, pagesURL)
	}
	if operatedBy == OperatedByAgent && pagesURL == links.Portal {
		return setup.VaultChoice{Given: given, Def: setup.VaultModeOn, Why: "default for --operated-by=agent; --vault=off to turn it off"}, nil
	}
	return setup.VaultChoice{Given: given, Def: setup.VaultModeOff, Why: defaultWhy}, nil
}
