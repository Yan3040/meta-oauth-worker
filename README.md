# meta-oauth-callback

Multi-provider OAuth callback worker for oauth.mash.org.il (Cloudflare Workers,
Custom Domain). Providers: Meta Facebook (IIAI page), Instagram, Threads,
Google YouTube. Each provider has isolated routes, signing key, app secret, and a
browser-bound consumable state cookie. Tokens are rendered once to the owner's
browser and are never logged or stored.

## Migration note (2026-09-28)
This worker has never been deployed: oauth.mash.org.il carries no live traffic,
so no consent flow is in flight and there is nothing to migrate. The state format
is provider-bound and browser-bound from the first deploy; no legacy format is
accepted. The previous single-purpose draft (facebook-only, cookie-less state)
was never live and is superseded without a compatibility path.

## Deploy
1. Attach the Custom Domain oauth.mash.org.il to this worker under the owning
   Cloudflare account (verify the attachment shows Active before sharing links).
2. Set the 8 secrets (4 app secrets + 4 state signing keys) listed in the file header.
3. Register each provider's callback URI in its app console (add only; remove nothing).
4. Run `node --test test/` locally before any deploy.
