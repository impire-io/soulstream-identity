# Episode 0006 — Design review: seeds from the environment, no v1, D15 taught back (2026-07-28)

The operator reviewed the NATS-surface design (episode 0005) the day it was
written and amended it in three places, before any build:

**The xkey seeds are deployment-supplied configuration, not files the
service writes** (amends D13, D17). Both `SX…` seeds arrive as environment
variables (flag accepted), minted once by operator keygen tooling into the
deployment's secret store. Custody moves to the secret manager the
deployment already trusts with `service.creds`; read-only and secretless
hosts — the class D13's original reversal condition named — are served
without re-opening the keychain/KMS rows; the service now writes no key
material to disk at all. Recorded honestly: the process environment is
readable by the same principal set as the `0600` file was
[mechanism-argument], and the flag form is weaker (argv is world-visible in
common process tables) — env var is the documented default. A fail-fast
rule joins the design: a first key that cannot open an already-populated
bucket refuses to serve, so a mis-supplied seed cannot double-seal a vault.
Journey 0004's measurements stand — seal/unseal mechanics and
ciphertext-only storage are unaffected by how the seed enters the process.

**No `v1` in the subject space** (amends D14). Operations live at
`soulidentity.<account>.<user>.<op>`; versioning machinery before a single
consumer exists was speculation (constitution III). The wire-contract
one-way door is answered when it actually closes: a breaking change after
consumers freeze the contract gets a new prefix as its escape; until M2
lands the space may change freely. The envelope's `v` field went with it —
JSON field extensibility is the envelope's evolution story.

**D15 survived teach-back.** The operator's restatement confirmed the
publish-permission proof and pinned its cross-account extension: an export
of the service's subject space declaring `account_token_position` forces
the importing account's public key into the subject, server-enforced — the
same principal property across account boundaries [mechanism-argument].
(The restatement said `account_token_seq`; the server's config field is
`account_token_position` — recorded with the correct name.) Extension path,
not M3 scope: the first cross-account consumer triggers the account token's
move to the account public key, before the contract freezes.

Reversal condition: none beyond those carried in the amended decisions —
D13's (a deployment class that cannot hold the secret re-opens
keychain/KMS) and D15's (a JWT class that cannot express the prefix
template forces in-envelope caller authentication) transfer unchanged to
the amended shapes.

Trail: [`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md)
(D14–D17 amended in place),
[`../02-DESIGN/agent.md`](../02-DESIGN/agent.md) (D13 amendment); episodes
0004–0005 unchanged as the pre-review record.
