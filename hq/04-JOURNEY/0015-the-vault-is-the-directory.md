# Episode 0015 — The vault is the directory: ephemeral users, keys on first touch (2026-07-29)

Episode 0014's trust path was **refuted by the operator hours after it was
recorded**: the proof had wired soulstream's persona directory — published
per-user profiles, a "profile-publication duty" for the future node — and
the operator called it what it was: the registry pattern D25 deleted,
resurrected one layer up. The model, stated at full strength: identity
truth lives in the deployment's IAM (Entra); **users are ephemeral, minted
from the credential they present**; no per-user provisioning act may be
required anywhere in this stack.

The clarifying question that sharpened it — *why persona keys at all, if
identity comes from the token?* — got the honest answer taught back and
confirmed: an access token carries **no user key** (its signature is the
IdP's, over claims, expiring within the hour), so it cannot press a seal
on record bytes, and a signature chained to it would die at every expiry
[mechanism-argument]. A persona key is therefore not identity — it is a
**capability artifact**, the durable stamp for records that must prove
themselves outside the connection; soulstream's unsigned "testimony"
needs no key at all, and the operator confirmed signing is wanted ("I
like that we are sure about who produced a message"), with the sealed-
communication key to follow the same pattern when D9's sealed topics land
— decided as the pattern now, built then.

D26 is the shape both points meet in: **the caller's own persona key
materializes inside the vault on first touch** (`sign.record` or
`keys.public` naming `persona/<own user>`), generated in-process,
owner-bound to the server-proven principal — the `GenerateUserKey`
pattern extended, import remaining the bring-your-own path; and
**`keys.public` is the open directory read** — the vault that custodies
the keys IS the realm's key directory, so readers build verification
keyrings from the identity plane and no profile store exists. The
`PersonaSigner` keeps fail-fast by checking the owner binding
client-side. Re-proven end to end [measured]: the M2 rig now performs
**zero per-user acts** — the operator's provisioning is one team key and
one minted credential; daan's key materializes at `PersonaSigner`
construction; the reader's keyring is one `keys.public` answer; announce,
baseline, and turn read `SigVerified` (`unknown-key` without the keyring,
the negative control); and the key the reader trusted is byte-identical
to the key the signer materialized. Unit-proven beside it [measured]:
materialization is idempotent and stable across touches, a second
account's same-named claimant refuses (first owner wins — D26's named
cost), and a non-persona key never answers the directory read.

What it closed: the "profile-publication duty" recorded in 0014 is dead —
the node builds keyrings from the identity plane and publishes nothing
per user. What it taught: the registry instinct returns in disguises
(list → row → profile store), and the test for every future one is the
operator's sentence — *would this require an act per user?*

Reversal condition: a consumer whose persona name cannot equal its user
name (observable: a consumer blocked on the materialization rule,
recorded as an issue) reopens persona naming; enumeration-shaped
`keys.public` traffic in the audit log reopens the read gate; both as new
D-decisions (D26).

Trail: `hq/02-DESIGN/nats-surface.md` (D26 added), `hq/02-DESIGN/agent.md`
(D6 amendment extended to first-use generation); `internal/vault`
(`GeneratePersonaKey`), `internal/service` (materialize-on-touch,
`keys.public` opened), `client/` (`PersonaSigner` owner check
client-side), `e2e/m2_gate_test.go` (the registry-free rig); committed as
the episode's change-set on `main`.
