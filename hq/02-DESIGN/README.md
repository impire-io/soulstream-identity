# 02-DESIGN — the normative design

What SoulIdentity *is*, functional-level: capabilities, seams, configuration
surfaces, acceptance criteria. Load-bearing decisions carry D-numbers with
their reasoning, so future changes argue against the real reasons. Behavioral
changes made during implementation propagate back here — these docs describe
the system as it is.

| Document | What it covers |
|---|---|
| [`agent.md`](agent.md) | The agent: vault, registry, oracle, mint — decisions D1–D13 and the milestone-1 shape |
| [`nats-surface.md`](nats-surface.md) | The NATS surface (M3): subject space, server-enforced principal, sealed envelope, KV vault — decisions D14–D17 |

Future documents arrive by research graduation (see
[`../01-RESEARCH/README.md`](../01-RESEARCH/README.md)) or design propagation
from landed work; the roadmap names the expected ones (auth callout with
claims-derived authorization, attestation issuance, sealing keys).
