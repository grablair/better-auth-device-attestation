# Contributing

The project is currently design-first. Before implementing a substantial API or
protocol change, open an issue describing the use case, threat boundary, and
compatibility impact.

Development uses Node.js 20 or newer and pnpm 10.34.5:

```sh
pnpm install
pnpm check
pnpm package:check
```

Run `pnpm test:postgres` with `DATABASE_URL` set when changing persistence,
atomic transitions, schema behavior, or Better Auth adapter integration.

Pull requests should include focused tests, avoid undocumented Better Auth
internals, preserve generic database-adapter compatibility, and update
`docs/design.md` when they change a documented contract.

Do not include real attestation objects, assertions, challenges, key
identifiers, DPoP proofs, credentials, or production request bodies in fixtures,
issues, logs, or pull requests.
