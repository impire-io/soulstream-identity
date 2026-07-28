# What declared shape maps an external credential to an identity — for API tokens now and Entra later?

**State:** active
**Started:** 2026-07-28

## Abstract

The last research gate on M4. The operator's scoping (2026-07-28): **API
tokens are the first authn backend, Entra/OIDC comes later.** API tokens
carry no claims — so the trap this topic exists to avoid is designing a
token-shaped backend now and a claims-shaped one later as two machines. The
question is the one declared shape both share: credential validation on one
side, identity resolution on the other, with all *policy* (role, personas,
admin) staying in the registry — the D12 reversal condition watches exactly
this boundary. A decisive answer completes the auth-callout design
(D19–D21) up to the Entra specifics.

## The question

**What is the declared configuration shape that maps a validated external
credential to a registry identity** — such that the API-token backend
(first) and a claims-bearing issuer (Entra, later) are the same shape with
different validators, and no policy ever lives in the credential store?

## Pre-registered bars

- **Bar 1 — one shape, two backends.** The shape is written out with every
  field named: `validate(credential) → external subject` and
  `resolve(external subject) → (account, user)`, with role/personas/admin
  remaining registry rows only. Pass: the API-token backend is the
  degenerate case (subject = the token record's declared identity), an
  Entra/OIDC validator slots in as issuer allow-list + claim-path → subject
  rules **without changing the resolve side** [mechanism-argument
  permitted], and no field of the credential store duplicates a registry
  column. Fail: the token record carries permissions, personas, or roles —
  a second policy source.
- **Bar 2 — the token backend proven end to end.** On the callout rig from
  journey 0008: a high-entropy API token whose KV record is keyed by
  digest; the issuer validates by digest lookup, resolves the declared
  (account, user), checks the registry row exists, and mints the scoped
  user JWT with the row's role key; an unknown token is refused. The KV
  bucket never holds the plaintext token (raw-value check). All
  [measured].
- **Bar 3 — revocation.** Deleting the token record refuses the *next*
  connection attempt [measured]. The behavior of already-open connections
  is recorded honestly — including what bounds their lifetime (issued-JWT
  expiry) and what M4 must therefore set.

## Reversal condition

D12's registered watch, inherited as this topic's own: if the mapping
accumulates per-user exceptions — token records (or, later, claim rules)
growing fields that override registry columns (observable: any
permission/persona/role field appearing in the credential store's schema)
— claims-derived authorization demotes to a bootstrap convenience and the
registry stays the sole policy source. Separately: if, when the Entra
research runs, its claims cannot be expressed as issuer allow-list +
claim-path → subject rules (observable: the Entra design needing to change
the resolve side), the "one shape" conclusion is refuted and the backends
get honestly separate designs.

## Verdict

<Empty until graduation. Filled by /research-graduate: PASS/FAIL per bar with the
honest numbers, each load-bearing claim tagged [measured] / [mechanism-argument]
/ [judgment].>
