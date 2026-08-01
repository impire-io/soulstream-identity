# Episode 0018 — The embed seam: the serve assembly becomes public (2026-08-01)

M2's second consumer arrived with a measurement instead of a request:
soulnode's `single-binary-composition` research ran all three of its
pre-registered bars against this repo and found the one wall — every
provisioning act works through the public `client` in-process, but the
*serve assembly* (vault + sealed surface + callout issuer) exists only
inside `cmdServe`, so an embedding consumer must supervise the binary or
name its module under this repo's path to make `internal/` imports legal
[measured, soulnode's topic journal; soulstream's remote-mcp-node
experiment rode the same dodge first]. The operator's direction was
explicit: the downstream projects expose the right constructs. D29 landed
in `../02-DESIGN/agent.md` and feature `specs/002-embed-seam/` shipped the
seam the same day, through the full spec-kit flow.

The shape, as decided and built: one public package, `embed`, exposing one
type and one function — `Run(ctx, Options) error`, value-only options, no
internal type crossing the boundary. Custody unchanged (the seeds stay
deployment-supplied strings, D13); `client/` stays the consumer surface
while `embed/` is the operator surface; provisioning stays on the sealed
wire — no in-process admin API exists or arrives. `cmd/soulidentity serve`
now parses flags, owns its connections, and delegates assembly to
`embed.Run`: one assembly, two entrypoints, drift structural rather than
disciplinary. Net code in `cmdServe`: negative.

The proof is compiler-grade, not review-grade: the new gate module
`e2e/embedgate/` carries a module path *outside* this repo's namespace
(`soulidentity.invalid/embedgate`), so an `internal/` import is a compile
error — the toolchain enforces SC-001, closing the exact hole the
namespace dodge exploits. The gate provisions a full operator-mode callout
ceremony in pure `server.Options` (the fourth consumer-position copy of
the ceremony — accepted duplication, research R4), assembles the plane
through `embed.Run`, provisions through public `client` only, and proves
the M4 admission shape: token-lane admission with the server-asserted
principal, invalid-token refusal, revoked-token refusal, `callout REFUSED`
in the audit [measured, `make test` — the gate rides the Makefile beside
`e2e/`].

One finding was refuted on the way: the first gate run failed its shutdown
assertion — `Drain()` on a subscription *initiates* the drain and Run was
returning while the server still served the surface [measured, the failing
assertion]. The contract was strengthened rather than the test weakened:
`Run` now drains its subscriptions and flush-confirms the server processed
the unsubscribes before returning, so "Run returned" means "the surface is
silent" while the caller's connections live on untouched. The existing e2e
gates (M3 sealed surface, M4 callout, M2 cross-service) pass uncached and
unmodified with the daemon serving through the seam [measured].

What it opened: soulnode can delete its namespace dodge for the serve
assembly and consume `embed` + `client` public-only; the remote MCP node
gets the same seam for free when it graduates. The remaining M2 half (the
node holding one pooled connection per user, no node-held creds) is
unchanged by this episode and stays with soulstream's remote-node feature.

Reversal condition: D29's, restated — an embedding consumer that genuinely
needs config-by-*type* (its own token store or validator; observable: a
consumer forking `embed` or re-riding the namespace dodge to inject a
type, recorded as an issue) reopens the options shape toward exposing the
internal interfaces deliberately.

Trail: D29 in [`../02-DESIGN/agent.md`](../02-DESIGN/agent.md);
`specs/002-embed-seam/` (spec, research R1–R6, data model, contract,
quickstart, tasks); `embed/embed.go`; `e2e/embedgate/`;
`cmd/soulidentity/main.go`; Makefile. Commits: the `002-embed-seam`
branch, merged to main 2026-08-01.
