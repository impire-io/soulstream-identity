# How does a client with only an external credential reach the server so callout can fire?

**State:** active
**Started:** 2026-07-28

## Abstract

Auth callout is M4's front door (D4 rung 3, D12's second lane): SoulIdentity
validates an external credential — an API token, an Entra/OIDC JWT — and
issues an ephemeral NATS user JWT. But callout only runs once a connection
attempt reaches the server, and in operator mode every connection must
present *something* the server accepts far enough to fire the callout. This
topic names that something — sentinel creds, a bearer user JWT, or
token-in-password — and proves the full loop end to end against self-hosted
NATS. It is the second half of D11's reversal condition: if no carrier
works, the NATS-native surface's bootstrap story fails for external
identities.

## The question

For a **self-hosted, operator-mode** NATS server (SoulIdentity's deployment
class): **by which exact mechanism does a client carrying only an external
credential connect so that the auth-callout issuer receives it** — and what
does the client hold, what is public, what is secret?

## Pre-registered bars

- **Bar 1 — the carrier map.** For each candidate carrier — (a) sentinel
  creds plus the token/password connect option, (b) a bearer user JWT,
  (c) bare token/username-password with no creds — a verdict on whether it
  delivers the external credential to the callout issuer in operator mode.
  Pass: every carrier's verdict carries `[measured]` (spike) or
  `[mechanism-argument]` (server source), at least one carrier works, and
  the map states for the working carrier exactly what the client holds and
  which parts are public vs secret. Fail: verdicts by documentation hearsay
  alone.
- **Bar 2 — the end-to-end proof.** Against a self-hosted operator-mode
  server with a callout account: a client holding only the public sentinel
  artifact and an external API token connects; the issuer (a spike callout
  service) validates the token, issues an ephemeral user JWT for the
  client's own key into the target account with role permissions; the
  connection round-trips a message within scope **and** an out-of-scope
  publish draws a server permissions violation; the external identity is
  attributable in the issued JWT or issuer log. All [measured].
- **Bar 3 — the refusal path.** Same setup, invalid token: the connection
  is refused at connect time with an authorization error and the issuer
  records the refusal [measured]. A callout that admits on validation
  failure, or fails open when the issuer is down, is a bar failure.

## Reversal condition

If no carrier lets an external-credential client reach a self-hosted
operator-mode server so callout fires (observable: Bar 2 unachievable with
every carrier in the map), the second half of D11's reversal condition
fires: the NATS-native surface has no external-identity bootstrap, and a
pre-connection surface returns as a new D-decision. Separately: if the
sentinel artifact proves secret-equivalent — possession alone grants realm
access beyond triggering callout (observable: a sentinel-only connection
admitted with usable permissions when the issuer refuses or is absent) —
the "sentinel is public" assumption is refuted and M4's design must give
sentinel distribution a custody story.

## Verdict

<Empty until graduation. Filled by /research-graduate: PASS/FAIL per bar with the
honest numbers, each load-bearing claim tagged [measured] / [mechanism-argument]
/ [judgment].>
