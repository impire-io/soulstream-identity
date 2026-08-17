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

Register a GitHub OAuth app (or Google client), fill the catalog, link
one persona, call access twice (the second rides the rotated line),
revoke, confirm the next access refuses. Record the run in the feature's
checklist before landing.
