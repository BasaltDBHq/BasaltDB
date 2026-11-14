# Contributing to BasaltDB

Thanks for wanting to help. BasaltDB is open source under the [Apache License 2.0](LICENSE). Every contribution also requires agreeing to the Contributor Licence Agreement below.

## How we work

- Read [AGENTS.md](AGENTS.md) first; it holds the code, SQL, testing and review rules.
- The wire rules every surface follows are in [CONTRACT.md](CONTRACT.md). A change to a surface updates it in the same PR.
- Follow [Conventional Commits](https://www.conventionalcommits.org/) for commits and PR titles: `type(scope): message`.
- Include tests for new behaviour. Guard and ledger tests run against a real Postgres.
- Run `make ci` before opening a PR against `master`. Do not rebase or force-push shared branches; merge the base in.

## Contributor Licence Agreement (CLA)

By opening a pull request you grant Iman Tumorang (the licensor) a perpetual, worldwide, non-exclusive, royalty-free, irrevocable licence to use, copy, modify, create derivative works of, sublicense, and distribute your contribution, including in:

- BasaltDB (this repository), currently under Apache-2.0;
- **Basalt Vault** and other official Basalt products, whatever their licence;
- official binaries, hosted services, and documentation.

You also grant the right to **relicense** the contribution, including under a licence other than Apache-2.0 for future versions of BasaltDB. Versions already released under Apache-2.0 stay available under Apache-2.0. You represent that you have the right to grant this licence, and that your contribution is your original work or you have permission to submit it.

If you cannot grant these rights, do not open a PR.
