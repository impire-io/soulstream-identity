# Episode 0019 — Soulfold: the default IdP is a sibling, the refusal holds (2026-08-02)

The question arrived wearing the project's own name. Soulstream
deployments without an Entra tenant have no human login story — the
token lane admits, but it is not a sign-in — so the operator proposed a
pocket-id-shaped default: passkey-first, self-hosted, OIDC, bundled with
the ecosystem, replaceable by Entra/Auth0/any provider. And since the
project is called SoulIdentity, should it also *be* that provider? The
vision's refusal list answers in as many words ("we implement none of
them ourselves"), so the proposal was, honestly, a motion to amend it.

The refusal held, and not on sentiment. The load-bearing boundary is the
seam, not the repo [mechanism-argument]: D23's validator is one pinned
issuer, JWKS discovery, RS256 — it cannot tell providers apart, and that
indistinguishability is what keeps identity truth in the deployment's
IAM and the mint free of a second truth source. An in-process IdP
invites exactly the shortcuts that would kill it: validation that skips
OIDC, a user store sharing buckets with the vault, a special-cased
issuer URL. The decision: the default IdP is a **sibling project —
soulfold** (`github.com/impire-io/soulfold`), a NATS-native, embeddable,
passkey-first OIDC provider whose store is JetStream KV and whose front
door is necessarily HTTP — WebAuthn is origin-bound and OIDC is
discovery plus redirects; no NATS-native passkey ceremony exists
[mechanism-argument]. The callout issuer treats soulfold identically to
Entra: issuer URL, JWKS, D24's exactly-one-roles-claim rule, no
precedence, no side-channel. "Default" is distribution-level wiring —
`--oidc-issuer` points at the bundled soulfold, and replacing it stays a
config change.

Two premises died on the way. "Pocket-id is Node.js" is out of date:
since v1 it is a Go API server with the SvelteKit UI compiled static —
one binary, SQLite/Postgres underneath (per its own documentation). But
the conclusion survives the correction: it is an application, not a
library; nothing about it mounts into a parent binary the way D29's
`embed.Run` does, and its store is SQL, not the deployment's JetStream.
Second, the survey found no embeddable Go passkey-IdP library to adopt
[judgment]; what exists are building blocks — zitadel/oidc v3 (a
certified OP *library* with caller-supplied storage) and go-webauthn
(the maintained FIDO2 backend) — which makes soulfold a
storage-and-surface project, not a protocol one. Scope named honestly:
the OP and WebAuthn layers are a fraction of pocket-id; the user
lifecycle and admin surface are most of its value, and will be most of
soulfold's work [judgment].

What it opened here: D23 pins a single issuer, so a deployment running
soulfold *beside* a second external issuer needs multi-issuer dispatch —
named in the design doc's pending list, not built (constitution III).
The name cleared collision checks: soulpass reads as soulbound-token
territory in web3, soulgate is a company filing to list, soulbook is
multiply taken; soulfold was clean — and the fold is literally the
vision's phrase, "who belongs".

Reversal condition: any privileged path between soulfold and the callout
issuer — a validation that skips OIDC, a shared bucket, a special-cased
issuer URL (observable: a soulfold-aware branch in issuer code) — makes
soulfold a de-facto internal IdP and re-opens the vision's refusal.
Separately, an embeddable Go passkey-IdP library appearing upstream
re-opens build-vs-adopt until soulfold's OP layer is consumer-proven.

Trail: `hq/00-GENESIS/vision.md` (refusal bullet: tested-and-held
pointer), `hq/02-DESIGN/auth-callout.md` (pending: multi-issuer
dispatch); sources: pocket-id.org, github.com/zitadel/oidc,
github.com/go-webauthn/webauthn; committed as this episode's change-set
on `main`.
