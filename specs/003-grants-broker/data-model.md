# Data Model: The Grants Broker

All custody records rest sealed `xkv1` to the deployment's first key in
the `SOULIDENTITY_GRANTS` bucket (D31 — its own domain; the key vault is
untouched). Names follow the vault grammar; revisions are JetStream KV's.

| Record | Name | Sealed body | Lifecycle |
|---|---|---|---|
| Grant | `grant/<persona>/<resource>` | `{refresh_token, scopes?, linked_at}` | created/replaced by link.complete (CAS over any prior revision); rotated by access (CAS, successor before return); deleted by revoke |
| Link | `link/<persona>/<link_id>` | `{resource, verifier, expires}` | created by link.start (10m expiry); spent (deleted) by link.complete before redemption — single-use |

Never stored: delegations (presented per call, verified against the D26
directory), access tokens (returned once, cached nowhere at rest).

Wire types (mirrored in `client/grants.go`):

- `grants.link.start` `{resource}` → `{authorize_url, link_id}`
- `grants.link.complete` `{link_id, code}` → `{}`
- `grants.access` `{resource, on_behalf_of?, delegation_payload?,
  delegation_sig?}` → `{access_token, expires_at?}`
- `grants.list` `{}` → `{grants: [{resource, scopes?, linked_at}]}`
- `grants.revoke` `{resource}` → `{}`

Delegation payload (base64 JSON, signed by the subject's persona key):
`{subject, actor, resources, scopes?, issued_at, expires_at}` — RFC 3339
UTC times.
