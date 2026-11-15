# Security policy

## Supported versions

BasaltDB is in alpha. Only the latest release and the latest commit on `master` are supported. Older releases are not patched: a fix lands on `master` and ships with the next release.

## Reporting a vulnerability

Do not open a public issue or pull request for a security problem.

Report it privately through GitHub: open the [Security tab](https://github.com/BasaltDBHq/BasaltDB/security) of this repository and choose **Report a vulnerability**. Only the maintainers can see the report.

If you cannot use GitHub, write to [ask@basaltvault.app](mailto:ask@basaltvault.app). Say only that you have a security report, without the details, and we will arrange a private channel.

Include what you can:

- what is affected (engine, guard, CLI, a portal page, or the vault channel protocol) and the commit or version;
- steps or a proof of concept that reproduce it;
- what an attacker gains (for example: approving or reverting without the person's passkey, reading or altering a session, writing around the guard);
- any fix you have in mind.

Never put a real credential or someone else's data in a report. Use a throwaway database.

## What is in scope

- **Engine:** the MCP server, the SQL classifier, link and session handling, and how the engine stores and uses the agent's scoped credential.
- **Guard:** everything installed in `basalt_meta` (roles, grants, triggers, ledger, and the functions that check passkey signatures), including any way for an agent to write, approve or revert around it.
- **CLI:** the `basalt` command, including `init`, and anything that leaks or stores the admin credential or a secret.
- **Portal pages:** the approval, revert and passkey pages, including the handling of link secrets in the URL fragment.
- **Vault channel protocol:** the handshake, frame format, link tokens and keys described in [CONTRACT.md](CONTRACT.md) (Vault channel), and the engine's side of the connection to the relay. A relay that can read, alter, replay or forge a session is in scope.

Out of scope: problems in Postgres itself, in your own deployment or network setup, social engineering of a person, and findings that need an attacker who already holds the person's passkey or the admin credential.

## What to expect

BasaltDB is maintained by a small team, so these are targets, not guarantees.

- We acknowledge a report within 5 business days.
- We give a first assessment (confirmed, needs more detail, or not a vulnerability) within 14 days.
- We keep you updated while a fix is built, and tell you when it lands.
- We credit you in the fix if you want that. Tell us if you prefer not to be named.

Please give us a reasonable time to fix the problem before you disclose it, and we will agree on a date with you. We will not take action against anyone who reports in good faith and follows this policy.
