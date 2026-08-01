# Contract — the public `embed` package

**Import path**: `github.com/impire-io/soulidentity/embed`
**Consumers**: any process hosting the identity plane in-process
(soulnode is the named first consumer); `cmd/soulidentity serve` is the
in-repo reference consumer.

## Surface

```go
package embed

// Options describes an assembly of the identity plane, by value.
// See data-model.md for field semantics, defaults, and validation.
type Options struct {
    Conn         *nats.Conn
    CalloutConn  *nats.Conn
    VaultBucket  string
    TokenBucket  string
    FirstKey     string
    SurfaceKey   string
    CalloutKey   string
    AuthKeyName  string
    AuthAccount  string
    CalloutTTL   time.Duration
    Prefix       string
    OIDCIssuer   string
    OIDCAudience string
    Logger       *slog.Logger
}

// Run assembles and serves the identity plane until ctx ends, then drains
// what it started and returns ctx.Err(). Construction errors (validation,
// vault verification, bucket creation, OIDC discovery) return before
// anything serves.
func Run(ctx context.Context, o Options) error
```

That is the whole surface: one type, one function. No type from
`internal/` appears in it (`*nats.Conn`, `time.Duration`, `*slog.Logger`
only).

## Guarantees

1. **Custody**: the package accepts seeds as strings, holds them only in
   process memory, writes no key material anywhere, returns none
   (constitution I; D13 as amended).
2. **Ownership**: the caller's connections are never dialed, closed, or
   drained by the package; on shutdown the package drains only its own
   subscriptions (research R2).
3. **Parity**: behavior equals the daemon's — same vault verification
   fail-fast, same callout enablement rule, same admission / refusal /
   revocation semantics, same "service serving" / "callout issuer
   serving" log lines (research R6). The daemon itself runs through this
   function, so drift is structural, not disciplinary.
4. **No mutation surface**: provisioning (key import, tokens, sentinel)
   stays on the sealed wire through `client/` (FR-006).

## Error contract

- Nil `Conn`, empty `FirstKey`/`SurfaceKey`, invalid `Prefix`: error
  naming the field, nothing started.
- `CalloutConn` without `AuthAccount` (or callout-dependent options
  without `CalloutConn`): error naming the missing half.
- Exactly one of `OIDCIssuer`/`OIDCAudience`: error naming the rule.
- Wrong `FirstKey`: the vault-verification refusal, before serving.
- After serving: `Run` returns only when ctx ends (`ctx.Err()`), or when
  a fatal serve-time failure surfaces from the assembly.

## Compatibility

- Adding fields to `Options` is backward-compatible (zero values keep
  today's behavior); removing or retyping fields is a breaking change.
- The package never gains provisioning or key-returning methods without a
  new D-decision (D29's reversal condition names the one pressure that
  could reopen the shape).
