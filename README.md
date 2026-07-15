# Better Auth Device Attestation

`@grablair/better-auth-device-attestation` binds Better Auth authorization
grants to evidence from a genuine application instance. The initial provider
implements Apple App Attest registration and assertion verification. Android
Play Integrity is planned behind the provider boundary after the Apple flow is
stable.

> [!WARNING] This package is an unpublished alpha. Its API and database schema
> may change, and `private: true` intentionally prevents accidental npm
> publication.

## What it provides

- a Better Auth server plugin and inferred client plugin;
- one-time registration and assertion challenges;
- Apple-root-pinned App Attest certificate and assertion verification;
- persistent credential keys, monotonic counters, user binding, and tombstones;
- short-lived grants bound to OAuth, PKCE, resource, nonce, and DPoP inputs;
- optional Better Auth OAuth Provider enforcement;
- explicit App Attest distribution-metadata policy;
- safe structured diagnostics that exclude authentication material;
- an asynchronous callback for untrusted App Attest receipts.

The plugin does not replace user authentication. It adds application-instance
assurance to a Better Auth flow.

## Requirements

- Node.js 20 or newer for the runtime;
- Better Auth `1.7.0-rc.1` through the supported 1.7 prerelease range;
- `@better-auth/oauth-provider` when OAuth enforcement is used;
- a database adapter that implements Better Auth 1.7 atomic verification-value
  consumption and guarded increments.

The Better Auth 1.7 CLI currently requires Node.js 22.12 or newer for schema
generation even when the deployed server runs Node.js 20.

## Installation

The package is not published yet. Development from this repository uses:

```sh
pnpm install
pnpm check
```

After the first public release, installation will be:

```sh
pnpm add @grablair/better-auth-device-attestation
```

## Server configuration

Create one composition for each Better Auth instance. Do not reuse the same
composition across multiple `betterAuth()` calls.

```ts
import { betterAuth } from "better-auth";
import { oauthProvider } from "@better-auth/oauth-provider";
import {
  appAttest,
  createDeviceAttestation,
} from "@grablair/better-auth-device-attestation";

const allowedBuilds = new Set(["42", "43"]);

const attestation = createDeviceAttestation({
  providers: [
    appAttest({
      applications: [
        {
          // Apple App ID: Team ID followed by the bundle identifier.
          appId: "TEAMID.com.example.mobile",
          environment: "production",
          extensions: {
            // Use "required" once every supported distributed build emits the
            // Apple distribution extensions.
            presence: "if-present",
            // 2 is TestFlight and 4 is the App Store.
            allowedValidationCategories: [2, 4],
            // Apple reports CFBundleVersion, not CFBundleShortVersionString.
            validateBundleVersion: (version) => allowedBuilds.has(version),
          },
        },
      ],
    }),
  ],
  purposes: {
    credentialRegistration: {
      challengeTtlSeconds: 120,
      unboundCredentialTtlSeconds: 86_400,
      expiredCredentialRetentionSeconds: 604_800,
      maxActiveUnboundCredentialsPerApplication: 10,
    },
    oauthAuthorization: {
      protectedClientIds: ["mobile-app"],
      challengeTtlSeconds: 120,
      grantTtlSeconds: 300,
      requireDpopJkt: true,
    },
  },
  diagnostics: {
    report(event) {
      telemetry.warn("Device attestation rejected", event);
    },
  },
});

export const auth = betterAuth({
  plugins: [
    attestation.serverPlugin,
    oauthProvider(
      attestation.protectOAuthProvider({
        loginPage: "/login",
        consentPage: "/consent",
      }),
    ),
  ],
});
```

Production and development applications must be separate entries with their
matching environment. Configuring a development application never causes its
evidence to match a production application.

## Database schema

The server plugin contributes a `deviceAttestationCredential` model through
Better Auth's plugin schema contract. Generate your application schema after
adding the plugin:

```sh
npx auth@rc generate
```

Review and apply the generated migration using the workflow for your adapter.
The schema stores a hashed credential lookup key, SPKI public key while active,
the full unsigned 32-bit assertion counter and validation category, user
binding, lifecycle status, and the last accepted distribution metadata. Provider
application identities are limited to 255 characters so indexed schema output
remains portable across supported adapters. Raw App Attest evidence, receipts,
challenges, key identifiers, DPoP proofs, and OAuth credentials are not stored
in this model.

Model and field-name overrides are not supported by the current alpha.

## Client configuration

The client plugin provides Better Auth endpoint inference and contains no native
Apple implementation:

```ts
import { createAuthClient } from "better-auth/client";
import { deviceAttestationClient } from "@grablair/better-auth-device-attestation/client";

export const authClient = createAuthClient({
  plugins: [deviceAttestationClient()],
});
```

The application supplies the native App Attest bridge. Transport encodings are:

| Value                               | Encoding                             |
| ----------------------------------- | ------------------------------------ |
| App Attest key identifier           | Canonical padded base64              |
| Attestation object or assertion     | Canonical padded base64              |
| Returned `clientData`               | Unpadded base64url                   |
| Returned challenge and grant tokens | Opaque strings; do not decode or log |

## Native protocol

### Register an App Attest key

1. Generate an App Attest key and persist its key identifier in platform-secure
   storage.
2. Call `POST /device-attestation/challenge` with `operation: "register"`,
   `purpose: "credential-registration"`, the provider, App ID, and key ID.
3. Decode the returned `clientData`, hash those bytes with SHA-256, and pass the
   hash to Apple's `attestKey` operation.
4. Call `POST /device-attestation/verify` with the challenge token, same key ID,
   and attestation object.
5. Preserve the key ID after `registered-unbound` is returned. Registration does
   not create an OAuth grant.

### Authorize with an assertion

1. Create the OAuth PKCE challenge and non-exportable DPoP key before requesting
   the assertion challenge.
2. Call `POST /device-attestation/challenge` with `operation: "assert"`,
   `purpose: "oauth-authorization"`, and the exact OAuth binding.
3. Hash the returned `clientData` and pass it to Apple's `generateAssertion`
   operation.
4. Verify the assertion through `POST /device-attestation/verify`.
5. Add the returned grant as `device_attestation` and the same DPoP thumbprint
   as `dpop_jkt` on the authorization request.
6. Redeem the code with the matching PKCE verifier and DPoP private key.

Challenges and grants are short-lived and single-use. A failed or interrupted
attempt obtains a new challenge; clients must never retry the same evidence with
the same token concurrently.

Ordinary refreshes and protected API requests use Better Auth's DPoP binding and
do not generate new App Attest assertions.

## Default limits

| Setting                          |            Default |
| -------------------------------- | -----------------: |
| Registration challenge           |        120 seconds |
| Assertion challenge              |        120 seconds |
| Attestation grant                |        300 seconds |
| Unbound credential lifetime      |           24 hours |
| Expired unbound retention        |             7 days |
| Maximum evidence                 |            128 KiB |
| Challenge endpoint rate limit    | 30 requests/minute |
| Verification endpoint rate limit | 20 requests/minute |

`maxActiveUnboundCredentialsPerApplication` has no default limit in the alpha;
hosts should configure it according to their account and recovery flows.

## Distribution metadata

When extensions are present, the plugin strictly parses
`apple_bundle_version_01` as a string and `apple_validation_category_01` as an
unsigned 32-bit value. The latter accepts Apple's four-byte little-endian
representation and a safe numeric representation for decoder compatibility.

`presence: "required"` rejects evidence without the metadata. Use `"if-present"`
only as an explicit rollout policy for distributed clients that predate the
extensions; malformed or partial metadata is rejected under both policies.

## Receipts

An App Attest receipt remains opaque and untrusted even after the synchronous
attestation succeeds. The optional callback may enqueue it for independent Apple
fraud-risk processing, but its result does not alter the current login. Callback
failures do not weaken or replace the cryptographic verification result. Never
log receipt bytes.

## Diagnostics

The diagnostic callback receives only:

- provider and operation;
- stable failure stage and reason;
- retryability;
- bounded structural measurements when available.

It never receives evidence, assertions, challenges, key identifiers, public
keys, receipt bytes, OAuth codes, DPoP proofs or thumbprints, credentials, or
request bodies. Client responses use stable generic Better Auth error codes and
do not expose internal failure reasons.

## Credential lifecycle

- Newly registered credentials are active but unbound.
- The first accepted protected authorization permanently binds the credential to
  that Better Auth user.
- Assertion counters advance through a guarded atomic database update.
- Expired, retired, counter-exhausted, and user-deleted credentials cannot be
  reactivated.
- User deletion preserves a revoked tombstone so the same provider key cannot
  transfer to another account.

Authenticated users can list and retire their own credentials through the
inferred Better Auth endpoints. Credential retirement does not yet revoke an
already-issued OAuth token family; hosts must retain their existing token
revocation workflow until Better Auth exposes a documented association hook.

## Development and validation

```sh
pnpm check
pnpm test:coverage
pnpm test:postgres
pnpm package:check
```

Plugin integration tests use Better Auth's published `getTestInstance()` helper.
The ordinary suite runs the shared adapter contract against its default
in-memory SQLite database on Node.js 22.5 and newer; Node.js 20 continues to run
the runtime-compatible parser, provider, lifecycle, type, and package suites.
The PostgreSQL CI lane runs the same adapter contract against Better Auth's
standard PostgreSQL test service. SQLite/Kysely and PostgreSQL/Kysely are the
currently verified database combinations; other adapters remain unverified until
they pass the same contract.

See [docs/design.md](docs/design.md) for the architecture, security invariants,
protocol rationale, release criteria, and future Android design.

## Security

Report vulnerabilities through GitHub private vulnerability reporting as
described in [SECURITY.md](SECURITY.md). Do not put real evidence, assertions,
challenges, key identifiers, DPoP material, credentials, receipts, or production
request bodies in issues or fixtures.

## License

[MIT](LICENSE)
