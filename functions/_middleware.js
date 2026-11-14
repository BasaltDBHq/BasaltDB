// Cloudflare Pages Functions middleware for the portal (docs/deploy-portal.md):
// the per-person connect-src of the DIRECT transport. The logic and its tests
// are in web/edge/portal.js; web/_routes.json limits it to the pages that need it.
export { onRequest } from "../web/edge/portal.js";
