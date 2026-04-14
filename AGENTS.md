# AGENTS.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Development commands
- `go build ./...` builds the library and the example binaries.
- `go test ./...` runs the full test suite across all packages.
- `go test . -run TestName -count=1` runs a single test in the root `saml` package.
- `go test ./samlsp -run TestName -count=1` or `go test ./xmlenc -run TestName -count=1` runs a focused test in a subpackage.
- `go test ./... -run TestName -count=1` is useful when you know the test name but not the package.
- `golangci-lint run` matches CI linting. `.github/workflows/lint.yml` pins golangci-lint `v1.64.5`, and `.golangci.yml` enforces `gofmt`, `goimports`, and broader static analysis.
- `go generate ./...` regenerates `saml.go` from `README.md`; only do this after changing the top-level package documentation in `README.md`.

## Architecture
- The root `saml` package is the protocol engine. `schema.go` and `metadata.go` define the XML model and metadata types; `service_provider.go` and `identity_provider.go` implement the main SP/IDP flows; `service_provider_signed.go` handles redirect-query signing and signature verification.
- The core package supports both service-provider and identity-provider roles directly. The helper packages are convenience layers on top of those core types rather than separate implementations.
- `samlsp` is the high-level service-provider adapter for Go web apps. `new.go` translates `Options` into a configured `saml.ServiceProvider`, while `middleware.go` owns `/saml/metadata` and `/saml/acs`, starts authentication, validates assertions, creates sessions, and redirects back to the original URL.
- `samlsp` is intentionally interface-driven. The main extension points are `RequestTracker`, `SessionProvider`, and `SessionCodec`. The default behavior is cookie-based: pending auth requests are tracked via RelayState-indexed cookies and authenticated sessions are stored as JWT-backed cookies signed with the SP key.
- `samlidp` is a minimal in-process identity provider used as a reference implementation and for tests/manual experimentation. `Server` wires the core `saml.IdentityProvider` into HTTP endpoints for metadata, SSO, login, and CRUD-style management of services, users, sessions, and shortcuts.
- Persistence in `samlidp` is abstracted behind the `Store` interface. `MemoryStore` is the default/simple implementation, and the server itself satisfies the core package’s `SessionProvider` and `ServiceProviderProvider` interfaces by projecting stored users and service metadata into SAML behavior.
- `xmlenc` is the encrypted-assertion subsystem. Cipher suites, RSA key transport, and digest algorithms are registered through package init hooks in `cbc.go`, `gcm.go`, `pubkey.go`, and `digest.go`. Changes here usually need end-to-end assertions/tests because the registry is consumed indirectly by the core SP/IDP code.
- `testsaml` is a small test-helper package for decoding redirect-bound requests and responses into raw protocol payloads.
- Tests are fixture-heavy. `testdata/` contains serialized metadata, requests, responses, certificates, and expected HTML/XML outputs that many tests compare directly, so wire-format changes often require fixture updates or careful fixture review.
- `example/` contains runnable end-to-end demos: `example/service.go` and `example/trivial/trivial.go` show SP-side usage, and `example/idp/idp.go` shows a sample IDP built on `samlidp`.
