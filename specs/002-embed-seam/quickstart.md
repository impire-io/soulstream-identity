# Quickstart — hosting the identity plane in your process

You hold live NATS connections (perhaps to a server embedded in the same
process). You want the identity plane — the sealed service surface and,
optionally, the callout issuer — running in-process, no `internal/`
imports, no child binary.

```go
import (
    "context"

    siembed "github.com/impire-io/soulidentity/embed" // alias: stdlib has an embed too
)

// ncService: a connection on the service's account (you own it).
// ncCallout: a connection on the AUTH account (optional; enables admission).
err := siembed.Run(ctx, siembed.Options{
    Conn:        ncService,
    CalloutConn: ncCallout,
    FirstKey:    os.Getenv("SOULIDENTITY_FIRST_KEY"),
    SurfaceKey:  os.Getenv("SOULIDENTITY_SURFACE_KEY"),
    CalloutKey:  os.Getenv("SOULIDENTITY_CALLOUT_KEY"),
    AuthAccount: authAccountPub, // A… (required with CalloutConn)
})
// Run blocks until ctx ends, then drains its subscriptions.
// Your connections are yours: drain/close them after Run returns.
```

Provisioning is not part of this surface and never will be (custody):
import keys, create tokens, and mint the sentinel over the wire with
`github.com/impire-io/soulidentity/client`, exactly as an operator does —
an embedding process simply does it over its own loopback/in-process
connection.

## The proof

`e2e/embedgate/` is a consumer-position module whose import path sits
*outside* this repository's namespace — the Go toolchain itself forbids it
`internal/` imports. It provisions a full operator-mode ceremony, assembles
the plane through `embed.Run`, and proves the M4 admission shape: a
sentinel + valid `sit_` token is admitted with server-asserted attribution;
an invalid token is refused; a revoked token is refused; the refusals are
in the audit log.

```sh
make check          # includes: cd e2e/embedgate && go test ./...
```

The daemon is the same assembly:

```sh
soulidentity serve …   # unchanged flags/env — cmdServe now calls embed.Run
```
