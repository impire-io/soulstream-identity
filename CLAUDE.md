# SoulIdentity — project instructions

An ssh-agent for personas: identity vault, signing oracle, NATS credential
minting for the Soulstream ecosystem. Module
`github.com/impire-io/soulidentity`, Go 1.26.

**How this project is run lives in `hq/` — read [`AGENTS.md`](AGENTS.md)
first** (orientation order + the non-negotiables), then hold decisions against
`hq/00-GENESIS/`. Where things stand: `hq/04-JOURNEY/README.md`. The plan:
`hq/03-IMPLEMENTATION/ROADMAP.md`. The design with its D-numbered decisions
(cited from code comments): `hq/02-DESIGN/agent.md`.

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
