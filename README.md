# Better Auth Device Attestation

`@grablair/better-auth-device-attestation` is a Better Auth plugin for binding
authentication grants to evidence from a genuine application instance. The first
provider will support Apple App Attest; Android Play Integrity is planned behind
the same provider contract.

The first alpha is under active implementation and is not ready to publish. See
the [complete design](docs/design.md) for the API, protocol, storage model,
security invariants, Better Auth integration, and delivery plan.

## Status

- Public API: implemented as an unstable alpha
- Apple App Attest: attestation and assertion verification implemented
- Better Auth OAuth Provider integration: challenge, grant, DPoP binding, and
  credential lifecycle implemented
- Android Play Integrity: planned after the Apple implementation stabilizes
- npm publishing: intentionally disabled with `private: true`

The implementation currently includes strict CBOR and authenticator-data
parsing, Apple-root-pinned certificate validation, nonce/key/App ID/environment
checks, production distribution policy, assertion counters, one-time Better Auth
verification values, permanent user binding, and safe diagnostics. The test
suite includes Apple's official attestation validation fixture.

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md). Security reports must follow
[SECURITY.md](SECURITY.md) and must not be filed as public issues.

## License

[MIT](LICENSE)
