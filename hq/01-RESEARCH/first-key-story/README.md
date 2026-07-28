# Where does the first key live once envelope encryption relocates the root secret?

**State:** active
**Started:** 2026-07-28

## Abstract

M3 puts the vault on NATS KV with xkey envelope encryption at rest (D10):
every stored seed is ciphertext, sealed to an unwrapping xkey. That does not
eliminate the root secret — it relocates it, and this topic names its new home
honestly, as the roadmap demands. The same bootstrap moment must also produce
the service's own connection credential (the creds-file bypass, D12), because
a fresh deployment owns neither. A decisive answer unlocks the M3 design doc;
without it the KV backend cannot be specified beyond hand-waving.

## The question

For the NATS-KV vault backend's envelope encryption: **where does the
unwrapping xkey live, how does a fresh deployment obtain it, and how are the
service's own bypass creds provisioned** — stated so that the location of the
root secret, and who can read it, is explicit?

## Pre-registered bars

- **Bar 1 — the candidate table.** Every candidate home for the unwrapping
  xkey (at minimum: plaintext local file `0600`, OS keychain, passphrase-derived
  key, external KMS/transit) is assessed against the same five criteria:
  at-rest exposure, fresh-deployment bootstrap, unattended restart,
  backup/rotation story, dependency footprint. Pass: the table is complete,
  every cell carries an evidence tag (`[measured]` where a spike ran,
  `[mechanism-argument]` otherwise), and the recommendation states in plain
  words where the root secret now lives and which processes/users can read it.
  Fail: any candidate scores well by pushing the secret somewhere the table
  doesn't examine.
- **Bar 2 — the mechanics proof.** A spike (scratchpad script, local
  `nats-server -js`) proves the chosen shape end to end: generate the
  unwrapping xkey, seal vault records into a KV bucket, kill and restart the
  process, unseal using the key obtained through the chosen home — with zero
  human input at restart. Pass: the round-trip decrypt succeeds after restart
  **and** a raw read of the KV entries shows ciphertext only (no plaintext
  seed bytes findable) [measured]. Fail: restart needs interactive input, or
  any plaintext key material is observable in the bucket.
- **Bar 3 — the bootstrap runbook.** From nothing — no data dir, no KV
  bucket, no service creds — the documented steps produce: the service's own
  NATS creds, the first key in its chosen home, and an initialized (empty)
  vault. Each step names its actor (operator-human vs service-automatic).
  Pass: the runbook is executed end to end once in the spike environment
  [measured], and no step requires transmitting the root secret through a
  channel the table in Bar 1 didn't account for.

## Reversal condition

If the candidate table shows that every viable home reduces to "a plaintext
secret readable by the same principals who can read the KV bucket" — i.e.
envelope encryption adds a moving part without changing who can obtain the
seeds — then D10's KV-envelope shape should be reconsidered (encryption at
rest may belong to the storage/disk layer, not the application), and M3's
design must not proceed on the envelope assumption unamended.

## Verdict

<Empty until graduation. Filled by /research-graduate: PASS/FAIL per bar with the
honest numbers, each load-bearing claim tagged [measured] / [mechanism-argument]
/ [judgment].>
