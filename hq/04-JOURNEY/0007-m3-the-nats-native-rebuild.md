# Episode 0007 — M3: the NATS-native rebuild ships (2026-07-28)

The walking skeleton's contract moved onto its real transport: the service
now answers over NATS request/reply on the caller's own subject prefix, the
vault seals into a KV bucket, and the socket era ended by deletion. Built in
one pass against the reviewed design (episodes 0005–0006); all four
measured gate criteria pass in the end-to-end proof, and `make check` is
green with the operator-mode e2e in the suite.

**What the gate measured** (client/e2e_test.go, embedded operator-mode
server with JetStream) [measured]:

1. An unauthorized act-as request — a registered identity asking to sign as
   a persona it was not allowed — is refused with the refusal in the audit
   log, principal named.
2. An account-privileged observer subscribed to the service's whole subject
   space captures daan's signing request and finds a sealed envelope only:
   no canonical bytes, no body fields.
3. The vault's KV stream on the broker's disk holds no plaintext seed and
   no record shape, proven against a plaintext positive control planted in
   a second bucket (the journey-0004 method, now in the automated suite).
4. A caller using another identity's subject prefix draws a server-side
   permissions violation and times out; the audit log shows the request
   never reached the service — D15 working as designed: the scoped signing
   key's template (`soulidentity.{{account-subject()}}.{{name()}}.>`)
   expanded server-side into exactly the caller's own prefix.

**What the build surfaced** (design propagated in the same change):

- *The socket's trust model had no successor for management.* Over NATS any
  authenticated identity reaches its own prefix, so "who may import keys
  and declare identities" became a real policy question the design hadn't
  answered. D18 answers it: an `admin` flag on registry rows (additive,
  operator-declared for the first row — which is also what keeps the
  bootstrap non-circular). An admins-list-in-config alternative was
  rejected as a second policy source beside the registry [judgment].
- *The account token was already the account public key.* The D15 amendment
  from episode 0006 assumed name tokens and a future grammar migration; the
  registry has keyed accounts by public key since milestone 1, so the
  `account_token_position` extension needs export configuration only.
  Corrected in the design doc — an assumption refuted by reading the code.
- *Act-as needed a binding.* Record signing now requires the
  `persona/<persona>` vault-name convention, so the registry's persona
  grant and the vault key are the same fact; signing outside the convention
  is refused.
- User names are subject tokens now: the registry additionally refuses
  `.`, `*`, `>` in them.

**What retired by deletion**: `internal/agent` (the HTTP-over-socket
surface), the client's socket transport, `NATSOption`, `DefaultSocket`, the
`sign/nonce` op, the vault's file keystore, and `vault.SignNonce`. The
client's `SignRecord` now takes the persona name rather than a raw vault
key name — the act-as surface, not the storage layout, is the API. New
since M1: `soulidentity keygen`, `--as` principal flags, NATS-context
connections (orbit natscontext), and the deployment-supplied seeds
(`SOULIDENTITY_FIRST_KEY`, `SOULIDENTITY_SURFACE_KEY`) per the episode-0006
amendment.

Reversal condition: none of its own — a completed build; the direction
decisions it realizes carry theirs (D15's prefix-inexpressible JWT class,
D18's second-boolean smell, D13's secretless-host class), all unchanged.

Trail: [`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md)
(D14–D18 as built), [`../02-DESIGN/agent.md`](../02-DESIGN/agent.md) (D2,
milestone-1 section), `client/e2e_test.go` (the measured gate), README and
roadmap in the same change.
