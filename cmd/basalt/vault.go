package main

// flagVault is --vault on basalt init, init --remote and service install.
const flagVault = "vault"

// flagVaultDefault is service install's vault for a config that has none:
// init passes it instead of --vault when the person gave none.
const flagVaultDefault = "vault-default"
