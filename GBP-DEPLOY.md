# Public GBP re-consent route (review before deploy)

Start: /google/gbp/start. Registered callback must be exactly:
https://oauth.mash.org.il/google/gbp/callback
The bare /google/gbp path is not a callback. Keep all existing redirect URIs.

Target client is Instinct GBP Runner, public client ID
216606794484-pptm2u9sru96oero7qo9i6flglatr46d.apps.googleusercontent.com,
not the off-limits Mash GBP Connector.

Prior setup reporting dated September 19, 2026 lists only
http://localhost:8080/callback for this client. This is historical metadata,
not current-console verification or user permission. A console operator must
verify current registration and add the exact callback above if absent. The
original setup operator had console access; present access is unverified.
Yaniv or an agent with his authorized Google Cloud console access can make the
additive change. This PR makes no console changes.

Deployment needs existing GBP_CLIENT_SECRET as a Worker secret and a new,
independent random STATE_SIGNING_KEY_GBP secret. The public client ID and pinned
redirect are included in wrangler vars. Do not copy secrets through chat, logs,
patches or files. No shared signing key and no change to other providers.

Only business.manage is requested. PKCE S256 and provider/browser-bound state
are isolated from YouTube. Exact existing iLEAD resource GET verifies access
before a refresh-token page is shown. Bearer tokens are in headers, not URLs.
New GBP outbound requests reject redirects and bound successful JSON to 64 KiB.
Provider errors show fixed stages and numeric HTTP status, never provider text.

Like the existing reviewed routes, this Worker does not store or forward tokens.
The verified refresh token is displayed once to the consenting user's browser,
with no-store/no-referrer/frame protection. User must deposit it in the vault
GBP OAuth Refresh Token through an actual secure vault request, never chat or a
screenshot. Only after the user completes consent and deposits the token may
a separately authorized secret-transfer step replace GBP_REFRESH_TOKEN.
This PR does not perform that step or update the existing client credentials.

Do not enable Workers request/body/tail logging. Confirm the live deployment and
route config before sharing a start link. Rendered page inspection remains a
post-deploy check; offline tests alone do not establish live readiness.

No publishing, queue/grant changes, reconcile dispatches, daily activation,
Google console edits, deployment or secret mutations happen in this PR.
