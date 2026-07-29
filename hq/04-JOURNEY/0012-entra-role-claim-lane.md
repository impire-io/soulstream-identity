# Episode 0012 — The Entra lane: role == team, no mapping store (2026-07-29)

The deferred Entra/OIDC backend (D22's "later") landed as the callout's
second lane — and the first work driven through the newly enabled speckit
flow (spec → clarify → plan → tasks → implement, feature
`specs/001-entra-oidc-backend/`; the speckit constitution is a projection
of `00-GENESIS`, hq authoritative). The load-bearing decision came from
the maintainer in the clarification session and **refuted the design's own
sketch**: D22 had sketched declared team rules
`(issuer, team-claim) → {account, role, personas}` as a fallback behind
the registry row; the maintainer rejected the rule table — the role value
in the token *is* the team name. What made that shape complete was one
recorded fact, not a new store: the vault's account-signing-key record now
carries its **account binding** (required at import), because a mintable
JWT needs `IssuerAccount` and the OIDC lane has no registry row to supply
it [mechanism-argument]. Both lanes now converge on the same declared team
objects; membership stays where each lane's custodian manages it.

Built and measured on the operator-mode rig with a local OIDC stub
(`internal/oidcstub`; a real tenant is a manual runbook, never in the
gate): admission through the sealed callout leg with server-enforced team
scope and `lane=oidc issuer/subject/team/display` attribution; the
nine-row refusal matrix (wrong audience, expired, bad signature, wrong
issuer, roles absent, undeclared team, ambiguous teams, HS256, `none`)
refusing with generic wire errors and specific audit reasons; JWKS
unreachable refusing — never admitting — with no-restart recovery, and
provider key rotation absorbed via unknown-kid refetch; the `sit_` lane
byte-identical under dispatch-by-shape, `eyJ` refusing early when the
lane is unconfigured; zero per-person state for the external subject
[measured]. The honest cost is the **revocation asymmetry**, accepted
without a mitigation knob: role removal propagates in token lifetime +
one callout TTL — on the 5 s-TTL rig the cached token re-admitted 5.2 s
after connect while the role-stripped fresh token refused [measured].
One guard the build surfaced: with bindings required, the AUTH issuer key
would itself qualify as a team; the issuer excludes its own signing key
from team resolution [measured].

What it taught: the smallest shape won twice — first the catalog beat the
rule table, then team-existence beat the catalog; and the account binding
belongs on the key because it is a fact about the key, not policy. What
it opened: Entra against a real tenant (the runbook in the feature's
`quickstart.md`), and the still-open `ngs-capabilities` question is
untouched by this lane.

Reversal condition: any per-user or per-subject entry proposed for
claims-path configuration, or admin/personas derived from any claim
(observable: a mapping exception accumulating in config or a claims-path
mint carrying either), demotes claims-derived authorization to a
bootstrap convenience and returns the registry to sole policy source
(D24, restating D22's watch).

Trail: `hq/02-DESIGN/auth-callout.md` (D22 amended, D23–D24 added);
`specs/001-entra-oidc-backend/` (spec, research, data model, contracts,
quickstart, tasks); commits `870160f` (speckit enablement), `9c9d7b3`
(spec), `1fe010a` (clarifications), `f76cd83` (plan), `29ab1d2` (tasks),
`47facfd` (the lane), `e06ef41` (proofs) on branch `001-entra-oidc-backend`.
