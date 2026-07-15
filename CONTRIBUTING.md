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

Run `pnpm test:postgres` against the standard Better Auth PostgreSQL test
service (`user:password@localhost:5432/better_auth`) when changing persistence,
atomic transitions, schema behavior, or Better Auth adapter integration. The
ordinary suite runs the same contract through Better Auth's default SQLite test
instance on Node.js 22.5 and newer. The Kysely development dependency remains
pinned to `0.28.17` while the supported Better Auth 1.7 prerelease test helper
imports migration constants from Kysely's pre-0.29 root entrypoint.

Pull requests should include focused tests, avoid undocumented Better Auth
internals, preserve generic database-adapter compatibility, and update
`docs/design.md` when they change a documented contract.

Do not include real attestation objects, assertions, challenges, key
identifiers, DPoP proofs, credentials, or production request bodies in fixtures,
issues, logs, or pull requests.
