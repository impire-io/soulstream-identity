// The compiler-proof consumer-position gate for the embed seam (002, D29):
// this module's path sits OUTSIDE github.com/impire-io/soulstream-identity, so the
// Go toolchain itself refuses any internal/ import — SC-001's zero-internal
// claim is checked by the compiler, not by review. The .invalid TLD is the
// RFC-reserved never-resolves name: this module is never tagged, never
// published, and exists only to run `go test` here.
module soulstream-identity.invalid/embedgate

go 1.26.2

require (
	github.com/impire-io/soulstream-core v0.10.0
	github.com/impire-io/soulstream-identity v0.0.0
	github.com/nats-io/jwt/v2 v2.8.2
	github.com/nats-io/nats-server/v2 v2.14.3
	github.com/nats-io/nats.go v1.52.0
	github.com/nats-io/nkeys v0.4.16
)

require (
	github.com/antithesishq/antithesis-sdk-go v0.7.0-default-no-op // indirect
	github.com/coreos/go-oidc/v3 v3.20.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gowebpki/jcs v1.0.1 // indirect
	github.com/klauspost/compress v1.19.1 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/synadia-io/orbit.go/natscontext v0.1.3 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace github.com/impire-io/soulstream-identity => ../..
