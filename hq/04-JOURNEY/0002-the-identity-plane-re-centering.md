# Episode 0002 — The identity-plane re-centering (2026-07-28)

The maintainer rejected the genesis framing. "An ssh-agent for personas" — a
local daemon behind a Unix socket, growing a TCP listener later — is not what
SoulIdentity is for. The mission, restated in his own words and recorded
here: SoulIdentity is **the identity plane of the Soulstream ecosystem** —
the representation of identity for humans and agents — delivered as a
**service on NATS** with end-to-end encrypted request/reply (xkeys sealing
payloads, nkeys authenticating callers). It holds the account signing keys
so users can be minted and represented — the case that matters most being an
outside-world identity (an Entra/OIDC principal, an API token) that must
exist inside NATS with the right identity and permissions. Signing keys live
in a KV with xkey envelope encryption at rest, as the named next storage
backend [judgment — direction call, maintainer's].

Most of the stated vision turned out to already be in the design — minting
from vault-held account signing keys (D4 rung 2, shipped), external-identity
bridging via auth callout with pluggable backends (D4 rung 3), audited
act-as (D6), pluggable storage (D10) — but as later rungs, not the point.
What genuinely changed: the **topology** (NATS-native surface instead of the
planned TCP-plus-tokens listener — the caller's NATS identity is the
principal, no parallel credential scheme inside an identity project
[mechanism-argument]) and the **center of gravity** (callout promoted from
ceiling to flagship front door). The working agreement ran in order: the
adversarial pass argued the other side at full strength before the decision
— the bootstrap problem (a client cannot reach a NATS-hosted oracle to sign
the nonce of the very connection it is establishing [mechanism-argument]),
NGS callout availability (open, now research-gated), and the laptop case —
and its residue is recorded inside D11. Teach-back was satisfied in the
originating direction: the maintainer stated the vision unprompted; the
assistant's role was the opposing argument.

Refuted and reversed, honestly: D1 is demoted from "the native seam" to the
local one — nonce signing only works over a non-NATS transport, so on the
primary surface the connection story is durable minted creds or callout. The
planned M3 TCP listener is dropped entirely, replaced by the NATS service
surface. The socket is not deprecated: it remains the bootstrap and laptop
rung (D8), the one surface reachable before any NATS connection exists. And
one claim is kept honest in D10: envelope encryption *relocates* the root
secret (the unwrapping xkey), it does not eliminate it — the first-key story
gates the KV backend.

What it opened: constitution 1.1.0 (Technology Constraints redefined;
Principles I–IV untouched — custody without possession and
server-as-verifier survive the re-centering intact, arguably strengthened by
xkey E2E), a rewritten vision, D11, a restructured roadmap (M3 = NATS
service surface, M4 = callout front door, M5 = KV-backed vault, M6 =
attestation), and three research questions before their milestones: the
sentinel-credential flow, the first-key story, and the NGS verdict — the
latter two halves of D11's reversal condition. Nothing was built in this
change; it is a genesis amendment, docs only.

Reversal condition: if, by the time the first external consumer needs
external-identity onboarding, auth callout cannot be enabled on the
deployment class consumers actually run (the NGS research verdict
[measured]) or a sentinel-credential onboarding of an external identity
cannot pass an end-to-end proof [measured], the NATS-native surface demotes
to an optional mode and the local socket returns to the primary surface —
recorded identically in D11.

Trail: [`../00-GENESIS/vision.md`](../00-GENESIS/vision.md) (rewritten),
[`../00-GENESIS/constitution.md`](../00-GENESIS/constitution.md) (1.1.0),
[`../02-DESIGN/agent.md`](../02-DESIGN/agent.md) (D1, D4, D8, D10 amended;
D11 new), [`../03-IMPLEMENTATION/ROADMAP.md`](../03-IMPLEMENTATION/ROADMAP.md)
(M3–M6, research questions); this change (single commit with the amendment).
