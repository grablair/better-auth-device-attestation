# Better Auth Device Attestation

`@grablair/better-auth-device-attestation` is a Better Auth plugin for binding
authentication grants to evidence from a genuine application instance. The first
provider will support Apple App Attest; Android Play Integrity is planned behind
the same provider contract.

The repository is in its design phase and is not ready to publish. See the
[complete design](docs/design.md) for the proposed API, protocol, storage model,
security invariants, Better Auth integration, and delivery plan.

## Status

- Public API: design in progress
- Apple App Attest: planned for `0.1`
- Better Auth OAuth Provider integration: planned for `0.1`
- Android Play Integrity: planned after the Apple implementation stabilizes
- npm publishing: intentionally disabled with `private: true`

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md). Security reports must follow
[SECURITY.md](SECURITY.md) and must not be filed as public issues.

## License

[MIT](LICENSE)
