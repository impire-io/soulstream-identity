# SoulIdentity — project instructions

The identity plane of the Soulstream ecosystem: the representation of
identity for humans and agents — identity vault, signing oracle, NATS
credential minting — as a NATS-only service with xkey-sealed E2E
request/reply on the caller's own subject prefix (server-enforced principal,
D15). Connections are creds-file bypass or auth callout — SoulIdentity is
the callout issuer (API tokens first, D19–D22); the vault rides NATS KV,
sealed to a deployment-supplied first key.
Module `github.com/impire-io/soulidentity`, Go 1.26.

**How this project is run lives in `hq/` — read [`AGENTS.md`](AGENTS.md)
first** (orientation order + the non-negotiables), then hold decisions against
`hq/00-GENESIS/`. Where things stand: `hq/04-JOURNEY/README.md`. The plan:
`hq/03-IMPLEMENTATION/ROADMAP.md`. The design with its D-numbered decisions
(cited from code comments): `hq/02-DESIGN/` (D1–D13 in `agent.md`, D14–D18
in `nats-surface.md`, D19–D22 in `auth-callout.md`).

Conventions:

- Quality gate before every commit: `make check` (fmt, tidy, build, test,
  lint) — all green, none skipped; `make test` includes `internal/hqlint` and
  the operator-mode e2e proof.
- Sign every commit. Push after landing with CI green.
- `client/` is the public consumer surface (the Soulstream MCP node imports
  it); its types mirror the agent's JSON wire contract — change them
  together.
- Custody without possession: no API returns secrets; the creds export is the
  one named escape. Keep in-process key material inside `internal/vault`.
- The journey duty: every landed milestone, concluded research topic, or
  load-bearing decision gets an episode in `hq/04-JOURNEY/` in the same
  change (`/journey-log`; research via `/research-graduate`).
