# Deploy the portal on Cloudflare Pages

The portal is the static copy of the approval, revert and passkey pages (`web/`) served at `https://portal.basaltvault.app`. There is no server code, no database and no accounts. A passkey made on the portal belongs to the `basaltvault.app` relying party, so the host has to be locked down: whoever can change these files can change what a person signs.

**Known gap until the domain rename lands.** `web/lib/codec.js` currently accepts only `console.basaltvault.app` as the hosted origin (`HOSTED_CONSOLE`), so the pages will not work end to end on `portal.basaltvault.app` until the domain rename task changes it. Deploying this headers file and the project before then is fine, but do not point people at the portal yet.

Design: [chat-only operator, section 5](redesign/specs/2026-11-12-chat-only-operator.md#5-the-portal-cloudflare-pages).

## What gets served

- Everything under `web/`: `approve/`, `revert/`, `register/`, `passkeys/`, `lib/*.js`, `style.css`.
- `web/_headers` sets the same headers the engine's own pages send (`internal/websec`): `Content-Security-Policy: default-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff`, and `.js` as `text/javascript`.
- The policy allows scripts, styles and `fetch` from the page's own origin only. The pages have no inline scripts, inline styles or event handlers, and a test (`go test ./internal/websec`) fails if one is added or if `_headers` drifts from the engine's headers.
- The `*.test.mjs` files under `web/lib` are served too. They are harmless static text.

## 1. Lock down the accounts first

Do this before creating the project.

1. Turn on 2FA (a hardware key or authenticator app, not SMS) on the **Cloudflare** account that will own the project and the domain.
2. Turn on 2FA on the **GitHub** account(s) with write access to this repository, and on the GitHub organization (require 2FA for members).
3. Add a branch protection rule (or ruleset) for `master`: pull request required, no force pushes, no deletions, applies to admins.
4. Keep the number of people who can change DNS or the Pages project to the minimum, each with 2FA.

## 2. Create the Pages project

In the Cloudflare dashboard: Workers & Pages, Create, Pages, Connect to Git.

1. Install the Cloudflare Pages GitHub app on `BasaltDBHq/BasaltDB` **only** (choose "Only select repositories", never "All repositories"), and pick that repository.
2. Project name: `basalt-portal` (any name works; it only decides the `*.pages.dev` address).
3. Production branch: `master`.
4. Framework preset: None. Build command: leave empty. Build output directory: `web`.
5. Save and deploy.

Then in the project settings, Builds and deployments:

- Turn **off** preview deployments for non-production branches (set "Branch control" to None for preview), so only `master` ever builds.
- Do not add environment variables or secrets. Nothing needs them.

## 3. Custom domain

1. Project, Custom domains, Set up a custom domain: `portal.basaltvault.app`.
2. Let Cloudflare create the CNAME to `<project>.pages.dev` (the `basaltvault.app` zone has to be on this Cloudflare account).
3. Wait until the domain shows Active and the certificate is issued.
4. Do not add a second custom domain. The engine accepts one portal origin only.

## 4. Lock the DNS

- Enable DNSSEC for the `basaltvault.app` zone and add the DS record at the registrar.
- Turn on the registrar lock (transfer lock) for the domain, with 2FA on the registrar account.
- Add a CAA record so only the certificate authorities you use can issue for `basaltvault.app`.
- If the plan has it, restrict who can edit the zone (Cloudflare account members, roles least privilege).
- Do not leave dangling records pointing at services you no longer use.

## 5. Ignore `*.pages.dev`

Cloudflare also serves the project at `<project>.pages.dev`, plus a URL per deployment. Those are **not page origins**. A passkey made there would not belong to `basaltvault.app`, and the engine's compiled-in origin list will refuse them (that list does not exist yet; it arrives with the domain rename task, so until then nothing in the engine rejects a `*.pages.dev` link). Never put one in a link, a doc or a chat message. Optionally add a Cloudflare redirect rule from the `*.pages.dev` host to `https://portal.basaltvault.app`.

## 6. Verify

```sh
curl -sI https://portal.basaltvault.app/approve/ | grep -iE 'content-security-policy|x-frame-options|referrer-policy'
curl -sI https://portal.basaltvault.app/lib/codec.js | grep -i content-type
```

Expected: the three headers above on pages, and `content-type: text/javascript` on modules. Open `/passkeys/` in a browser and confirm the console shows no CSP violations.

## Changing the portal

A change goes in by pull request to `master` and deploys from there. Roll back by reverting the commit on `master` (or promoting an earlier deployment in the Cloudflare dashboard). If the account is ever in doubt, rotate the Cloudflare credentials, review the deployment history and the DNS records, and tell people to re-register their passkeys.
