# Research: The Grants Broker

This feature's research ran as soul-hq topic `outbound-identity-grants`
(pre-registered bars, measured 2026-08-17, graduated the same night):
episode `soul-hq/04-JOURNEY/0104-ecosystem-outbound-identity-grants.md`,
design `soul-hq/02-DESIGN/soulstream-identity/grants.md` (D30–D34).

The measured facts this implementation stands on:

- Isolation is the transport's: a persona publishing to another's grants
  subject dies as a server publish permission violation; the broker's
  delivery log showed the victim's subject reached it exactly once
  [measured, operator-mode rig].
- Rotation custody: 3/3 provider rotations CAS-persist; an 8-way
  concurrent double-refresh under `-race` loses nothing; Dex-semantics
  reuse windows behave as retries [measured, Dex v2.44.0 + fake].
- Delegation: 1 allowed path vs 4 refusal classes, all audited naming
  both personas; a stolen validly-signed delegation refuses as an actor
  mismatch against the server-proven caller [measured].
- The key vault cannot custody rotating secrets (Create-only seam,
  closed kinds, derive-requires-public-half) — hence the second custody
  domain [measured, code map].

Named residue: one real-provider confirmation (SC-005) — a human act.
