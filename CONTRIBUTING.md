# Contributing

The project is currently design-first. Before implementing a substantial API or
protocol change, open an issue describing the use case, threat boundary, and
compatibility impact.

Development uses Node.js 20 or newer and pnpm 11:

```sh
pnpm install
pnpm check
```

Pull requests should include focused tests, avoid undocumented Better Auth
internals, preserve generic database-adapter compatibility, and update
`docs/design.md` when they change a documented contract.

Do not include real attestation objects, assertions, challenges, key
identifiers, DPoP proofs, credentials, or production request bodies in fixtures,
issues, logs, or pull requests.
