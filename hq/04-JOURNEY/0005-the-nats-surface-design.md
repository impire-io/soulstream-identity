# Episode 0005 — The NATS-surface design: the principal is the subject (2026-07-28)

With the first-key story decided (episode 0004), M3's remaining gate was its
design doc. Written the same day:
[`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md), four new
decisions (D14–D17) on top of the re-centered direction (D11/D12), wire
bodies deliberately unchanged from milestone 1 — the transport and the
principal change, the contract does not.

The load-bearing one is **D15 — the principal is the subject, and the
server enforces it**: operations live at
`soulidentity.v1.<account>.<user>.<op>`, and the claim is trustworthy
because a caller's JWT (scoped signing key template or callout-issued
permissions) only allows publishing on its own prefix. No signature inside
the envelope, no parallel token check — the server's publish-permission
enforcement *is* the caller authentication, which is constitution II applied
to SoulIdentity's own front door [mechanism-argument]. This is what turns
act-as (D6) from declared into enforced. Argued against at full strength in
the doc: lax deployment permissions collapse the proof — answered as "that
deployment has lost transport authorization everywhere, and a second
verifier would rebuild the identity plane inside its own API"; the duty is
loud deployment docs, not a gate.

The rest: **D14** versions the subject space (`v1`) with two open ops
(`status`, `xkey` discovery); **D16** specifies the sealed envelope
(plaintext outer `{v, xkey, data}`, `xkv1` ciphertext bodies both ways,
errors sealed too) with an honest replay analysis — replayed `import` is
refused as overwrite, replayed `mint` yields a duplicate the attacker
cannot read, judged acceptable for M3 [judgment]; **D17** splits the
surface xkey from the first key (domain separation, independent rotation
lifecycles) [mechanism-argument]. The vault-on-KV section carries journey
0004's measured mechanics into normative text; the registry stays a local
file in M3 (declared config, not secret — constitution III). No migration
tooling: milestone 1 shipped unreleased, the file backend retires by
deletion [judgment].

What it opened: M3 is now buildable without guessing — subjects, envelope,
key files, bucket layout, and five measurable acceptance criteria including
the D15 proof (a caller on another identity's prefix is refused by the
server, never reaching the service).

Reversal condition: D15's, recorded at decision time — a deployment class
whose JWTs cannot express the per-user publish prefix (the NGS research is
the first place this could surface, observable as a blocked consumer issue)
forces a caller-authentication mechanism inside the envelope as a new
D-decision.

Trail: [`../02-DESIGN/nats-surface.md`](../02-DESIGN/nats-surface.md);
design index, roadmap M3 gate note, and orientation pointers updated in the
same change.
