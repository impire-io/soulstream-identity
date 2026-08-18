# Quickstart: The Grants Broker

## Declare a resource (deployment act)

`grants.json`:

```json
[{
  "Name": "github",
  "AuthURL": "https://github.com/login/oauth/authorize",
  "TokenURL": "https://github.com/login/oauth/access_token",
  "ClientID": "<oauth app client id>",
  "ClientSecret": "<oauth app secret>",
  "Scopes": ["repo"],
  "RedirectURI": "https://<your-shell>/grants/callback"
}]
```

Serve with it:

```sh
soulstream-identity serve --context my-ctx \
  --grants-catalog grants.json
```

Embedding: set `embed.Options.GrantResources` instead — same shapes.

The deployment's represented-user scope template grows one line
(the D25 duty — without it the ops are unreachable, which is the point):

```
identity.{{account-subject()}}.{{name()}}.grants.>
```

## Link, use, revoke (persona acts, own prefix only)

Through `client/`: `GrantLinkStart("github")` → open the URL, consent →
`GrantLinkComplete(linkID, code)` → `GrantAccessToken("github")` serves a
short-lived token on every call; `GrantRevoke("github")` ends it.

On behalf (D33): the subject mints once per run —
`MintDelegation(subject, actor, resources, scopes, ttl)` (one
sign.record; the persona key materializes on first touch) — and the
actor calls `GrantAccessOnBehalf(resource, subject, delegation)` on its
own connection. Anyone else presenting that delegation is refused.

## The real-provider runbook (SC-005, human step)

Closes the research residue from hq episode 0104 (Bar 2 ran on the Dex
stand-in; one real provider confirms the shape). A human act — app
registration needs a browser and an account — never a gate test.

**GitHub (preferred: its refresh tokens rotate, which exercises D31 for
real).**

1. github.com → Settings → Developer settings → OAuth Apps → New. Set
   the callback to a URL you control (any https page is fine — the code
   arrives as `?code=…&state=…` in the address bar). **Enable "Expire
   user authorization tokens"** on the app — without it GitHub returns
   no refresh token and the broker refuses the link by design
   (offline-scope refusal at `link.complete`).
2. Catalog: `AuthURL https://github.com/login/oauth/authorize`,
   `TokenURL https://github.com/login/oauth/access_token`, the app's
   client id + secret, `RedirectURI` = the callback, no `RevokeURL`
   (GitHub does not speak RFC 7009 — custody deletion alone is the
   revocation decision there, named honestly).
3. `soulstream-identity grant link --as <acct>/<you> --resource github`
   → open the URL, authorize, copy `code` from the redirect.
4. `… grant link --link-id <id> --code <code>` → linked.
5. `… grant access --resource github` **twice**: both print a token, the
   second rides the rotated line (GitHub rotates the refresh token on
   every redemption — a stale line would refuse here).
6. `… grant revoke --resource github`, then `grant access` again →
   refuses with grant-not-found.

**Google (alternative; refresh token is stable, not rotating).** Bake
the offline ask into the catalog's AuthURL — `LinkStart` preserves
existing query parameters:
`https://accounts.google.com/o/oauth2/v2/auth?access_type=offline&prompt=consent`,
`TokenURL https://oauth2.googleapis.com/token`,
`RevokeURL https://oauth2.googleapis.com/revoke`.

Record the run's date and provider below when done:

- [x] SC-005 run: provider **github** (GitHub App, "expire user
      authorization tokens" on), date **2026-08-18**, by **Daan
      (calmera)**. Observed: link → custody; first access served an
      8-hour expiring token and `api.github.com/user` answered as the
      linked account; second access **rotated the line** (D31's
      discipline live against a real provider); revoke deleted custody
      and the next access refused, the refusal audited. The Bar 2
      residue from hq episode 0104 is closed.
