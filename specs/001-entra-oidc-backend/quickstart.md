# Quickstart: Entra ID lane

Phase 1 of [plan.md](plan.md). Two parts: the rig (automated, in
`make test`) and the real-tenant runbook (manual, never in the gate —
spec FR-011).

## Part 1 — the rig (what the e2e automates)

1. Operator-mode `nats-server` in process: operator, SYS, AUTH (external
   authorization + xkey + allowed accounts), APP (JetStream + scoped signing
   key) — the M4 pattern (`client/callout_e2e_test.go`).
2. `internal/oidcstub` up: discovery + JWKS, RS256, Entra-v2.0-shaped
   claims.
3. Service + issuer started with `--oidc-issuer <stub URL>`
   `--oidc-audience <test client id>`; teams imported with their account
   binding (`ImportKey(name, kind, seed, account)`).
4. Stub issues tokens per scenario; assertions per the six bars (spec
   SC-001…SC-007).

Run: `make test` (rides `go test ./...`; also part of `make check`).

## Part 2 — real-tenant runbook (manual)

Verifies the R3 token facts against a live tenant; freeze redacted claim
sets as stub fixtures if they differ.

1. **App registration** (Entra admin center → App registrations → New):
   single tenant. Note the **Application (client) ID** → this is
   `--oidc-audience`. Note the **Directory (tenant) ID** → the issuer is
   `https://login.microsoftonline.com/<tenant-id>/v2.0` → `--oidc-issuer`.
2. **Token version**: Manifest → set `"requestedAccessTokenVersion": 2`.
3. **App roles**: App roles → Create: display name free; **value = the team
   name exactly** (e.g. `engineering`); allowed member types: Users/Groups
   and Applications (for app-only daemons).
4. **Assignment required**: Enterprise applications → the app → Properties
   → "Assignment required?" = Yes. Then Users and groups → assign users (or
   groups) to their team's app role; for daemons, assign the client's
   service principal to the role (app-only).
5. **Get a delegated token** (human): e.g. device code —
   `az login --tenant <tenant-id> --scope api://<client-id>/.default` or
   MSAL; decode the access token (jwt.io or `jq -R 'split(".")[1] |
   @base64d | fromjson'`) and confirm: `iss` matches the issuer, `aud` =
   client ID, `ver` = "2.0", `oid` present, `roles` = ["<team>"].
6. **Get an app-only token** (daemon): client credentials against
   `https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token` with
   scope `api://<client-id>/.default`; confirm the same claims with the
   service principal's `oid`.
7. **Import the team** into the vault with its account binding; start the
   service with the two OIDC flags; connect with sentinel creds +
   `nats.Token(<access token>)`.
8. **Verify**: admission with `lane=oidc` attribution in the audit; an
   out-of-scope publish denied by the server; remove the role assignment,
   confirm refusal after the cached token expires (the accepted bound:
   token lifetime + one callout TTL).

**Durable home note**: when this feature lands, this runbook's substance
graduates into the design docs / implementation docs with the merge; the
spec folder is not the long-term home.
