# Episode 0004 — The first-key story: a local file, named honestly (2026-07-28)

The research question gating M3: once the vault moves to NATS KV with xkey
envelope encryption at rest (D10), where does the unwrapping xkey live, how
does a fresh deployment obtain it, and how are the service's own bypass creds
provisioned? Opened as `first-key-story` with three pre-registered bars,
investigated and graduated to design (D13) the same day. All three bars
passed.

**Bar 1 (candidate table) — PASS.** Four homes — local `0600` file, OS
keychain, passphrase-derived, external KMS/transit — against five criteria:
at-rest exposure, fresh-deploy bootstrap, unattended restart,
backup/rotation, dependency footprint. The keychain fails headless
deployments (secret-service needs an unlocked session keyring)
[mechanism-argument]; passphrase-derivation fails unattended restart by
construction, or degrades into the file candidate with extra steps
[mechanism-argument]; KMS/transit is a genuine at-rest upgrade but its own
credential must live on the service host — the root secret one indirection
later — and it is a new external system under constitution III for an
*initial* backend [judgment]. The winner is the local file, stated without
euphemism: **the root secret is a plaintext xkey seed file on the service
host, readable by the service user and root — the same trust class as the
`service.creds` file beside it.** The envelope's gain is elsewhere: broker
disks, replicas, and backups never hold plaintext seeds.

**Bar 2 (mechanics proof) — PASS [measured].** A spike with separate
processes per step, against nats-server 2.12.4 in operator mode (memory
resolver, file-backed JetStream): three real user-key records sealed with
nkeys' `xkv1` self-sealed envelope into a KV bucket; the broker killed and
restarted from its store; a fresh process — holding only `first-key.xk` and
`service.creds` — unsealed all three and re-derived the correct public keys
with zero human input. The ciphertext-only check ran with a positive
control: one record deliberately stored unsealed was findable in the
JetStream block files, the three sealed ones were not, anywhere in the
store. The control earned its place by catching a broken first measurement —
the platform grep skips binary matches without `-a`, so the naive leak check
"passed" vacuously. A negative result needs a positive control before it
counts.

**Bar 3 (bootstrap runbook) — PASS [measured].** From nothing — no data
dir, no bucket, no creds — to operational in two operator acts (provision
realm artifacts including the service's creds file; start the server) and
one automatic service act (mint `first-key.xk` at `0600`, refuse overwrite;
create the bucket on first connect). The first key is generated on the
service host and never crosses a machine boundary; the creds file is the
only artifact that does, and it is the same artifact any NATS service
deployment already moves.

Nothing was refuted; the topic's registered reversal condition was checked
and not triggered: the principals who can read the KV bucket (broker
operators, JetStream disk, replicas, backups, account-credential holders)
are not the principals who can read the first-key file (service user and
root on one host) [mechanism-argument] — envelope encryption genuinely
changes who can obtain seeds, and is not a moving part for its own sake.

What it opened: D13 records the decision (with the rotation walk named as
an operation); M3's design doc is unblocked — the KV backend can now be
specified without hand-waving about its root secret. First-key rotation
(mint new xkey, stream re-seal) is named but not automated in M3.

Reversal condition: if a deployment class emerges where the service host
cannot hold a `0600` file (observable: a deployment blocked on read-only or
secretless hosts, recorded as an issue), the keychain/KMS rows of the
candidate table re-open as the home for that class — the table's cells are
written so that argument can be re-had honestly.

Trail: `hq/02-DESIGN/agent.md` (D13, D10 amendment);
`hq/01-RESEARCH/first-key-story/` in git history (pre-registration e054688 →
investigation 8fd3bd3 → removed at graduation); spike in the session
scratchpad, its shape recorded in the topic JOURNEY.
