# first-key-story — investigation journey

Topic opened 2026-07-28. Entries append below as the investigation happens.

## 2026-07-28 — orientation: the primitives exist and are already dependencies

nkeys v0.4.16 (already in go.mod) carries the full xkey surface:
`CreateCurveKeys()` / `FromCurveSeed()` for `SX…` curve seeds,
`Seal(plaintext, recipientPub)` / `Open(ciphertext, senderPub)` over nacl box
with an auto-generated nonce and an `xkv1` version header [measured — read
the vendored source, `xkeys.go`]. Self-sealing (recipient = own public key)
is the at-rest shape: one keypair both seals and opens. No new dependency is
needed for the envelope; the KV client rides nats.go v1.52.0's `jetstream`
package, also already present.

## 2026-07-28 — Bar 1: the candidate table

Five criteria against four candidate homes for the unwrapping xkey:

| Candidate | At-rest exposure | Fresh-deploy bootstrap | Unattended restart | Backup / rotation | Dependency footprint |
|---|---|---|---|---|---|
| **Local file `0600` beside the creds file** | Readable by the service user and root on the service host — the same principal set that can already read `service.creds` sitting next to it [mechanism-argument] | One automatic service act on first start [measured, spike] | Yes — zero human input [measured, spike] | File copy; rotation = mint new xkey, stream re-seal all records [mechanism-argument] | Zero — nkeys is already a dependency [measured] |
| **OS keychain** | Protected by the login keychain when unlocked | Per-OS tooling (macOS `security`/cgo; Linux secret-service over DBus) | Fails headless: secret-service needs an unlocked session keyring; server deployments have none [mechanism-argument] | Opaque, per-OS export formats | High — platform-conditional code paths for the *initial* backend [judgment] |
| **Passphrase-derived (argon2id)** | Nothing at rest — the strongest cell in the table | Human present at first start | **Fails by construction**: a human at every restart, or the passphrase lands in a file — which reduces this row to the local-file row with extra steps [mechanism-argument] | Passphrase custody is a human problem | Low code, high operations [mechanism-argument] |
| **External KMS / Vault transit** | Genuine upgrade: secret never on the service disk, access audited and revocable [mechanism-argument] | Root-secret recursion: the KMS credential must live on the service host — it *becomes* the first key, one indirection later [mechanism-argument] | Yes, but adds the KMS to the service's availability equation | KMS-managed | Heavy: a new external system under constitution III for an initial backend [judgment] |

**Recommendation (Bar 1 pass):** the local `0600` file, named honestly —
*the root secret is a plaintext xkey seed file on the service host, readable
by the service user and root: exactly the trust class of the service's own
creds file beside it.* Envelope encryption's gain is not local-host
protection; it is that the KV bucket — which lives on broker disks, gets
replicated, and lands in broker backups — never holds plaintext. Keychain
and KMS/transit remain later backends on the D10 ladder. No candidate scored
well by hiding the secret somewhere unexamined; the KMS recursion is the
table's proof of that discipline.

## 2026-07-28 — Bar 2: the mechanics spike, and the grep that lied

Spike (`scratchpad/spike/`, subcommands `provision`/`init`/`seal`/`unseal`,
each a separate process) against `nats-server` v2.12.4 in operator mode with
a memory resolver and file-backed JetStream:

- `init` minted a curve xkey into `first-key.xk`, `0600`, 58 bytes [measured].
- `seal` generated three real NATS user seeds, sealed each record
  (the vault's `stored{}` JSON shape) to the xkey's own public key, and put
  the ciphertext in KV bucket `SOULIDENTITY_VAULT` [measured].
- Broker killed and restarted from its store dir; a **fresh** `unseal`
  process read only `first-key.xk` + `service.creds`, opened all three
  records, and re-derived each seed's public key correctly — zero human
  input at restart [measured].
- **Ciphertext-only, with a positive control:** one record was deliberately
  stored *unsealed* in a `CONTROL` bucket. The first grep of the store dir
  found nothing — *including the control* — which exposed the method, not
  the system: this platform's grep skips binary matches without `-a`. With
  `grep -ra` the control's plaintext seed is findable in
  `KV_CONTROL/msgs/1.blk` (method proven able to detect a leak), and all
  three sealed seeds are absent everywhere outside the control bucket
  [measured]. The vault stream's block shows the `xkv1` envelope header
  followed by ciphertext.

Without the positive control, the broken grep would have "passed" the leak
check on an unmeasured method. Recorded as a standing lesson: a negative
result needs a positive control before it counts.

## 2026-07-28 — Bar 3: the bootstrap runbook, executed from nothing

From an empty directory — no data dir, no KV bucket, no creds — to
operational, executed once end to end [measured]:

1. **Operator (human, once per deployment):** `provision` — mint
   operator/system/service-account JWTs, write `server.conf` (memory
   resolver, JetStream on) and `service.creds`. In a real realm this is the
   realm operator issuing one user credential for the service; the creds
   file is the only artifact that crosses a machine boundary.
2. **Operator (human):** start `nats-server -c server.conf`.
3. **Service (automatic, first start):** mint the xkey → `first-key.xk`
   (`0600`), refuse to overwrite if present; create the KV bucket on first
   connect. The root secret is generated *on* the service host and never
   leaves it — no step transports it, so no channel outside Bar 1's table
   exists.

Two human acts, both operator-side realm provisioning that any NATS service
needs anyway; everything key-related is service-automatic.

## 2026-07-28 — the reversal condition, checked

The registered reversal: "every viable home reduces to a plaintext secret
readable by the same principals who can read the KV bucket." **Not
triggered** [mechanism-argument]: the KV bucket is readable by broker-side
principals — broker operators, JetStream disk, replicas, backups, and any
holder of account-scoped credentials — while `first-key.xk` is readable only
by the service user and root on the service host. The principal sets differ,
so the envelope genuinely changes who can obtain seeds; it is not a moving
part for its own sake.

Open follow-on (not this topic's question): rotation of the first key is a
re-seal stream walk; the design doc should name it as an operation even if
M3 ships without automating it.
