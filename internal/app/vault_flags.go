package app

// flagVault is --vault on basalt init, init --remote and service install.
const flagVault = "vault"

// flagVaultDefault is service install's vault for a config that has none:
// init passes it instead of --vault when the person gave none.
const flagVaultDefault = "vault-default"

// flagDevLocalPages is init's and service install's development exception.
const flagDevLocalPages = "dev-local-pages"
