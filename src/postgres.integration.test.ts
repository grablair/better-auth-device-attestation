import { betterAuth } from "better-auth";
import type { StoredAuthorizationQuery } from "@better-auth/oauth-provider";
import { Pool } from "pg";
import { describe, expect, it } from "vitest";

import { decodeBase64Strict } from "./encoding/base64.js";
import { createDeviceAttestation } from "./plugin.js";
import { sha256 } from "./protocol/crypto.js";
import type {
  DeviceAttestationProvider,
  OAuthAuthorizationBinding,
  OAuthProviderTokenContext,
  StoredAttestationCredential,
} from "./types.js";

const DATABASE_URL = process.env.DATABASE_URL;
const APP_ID = "TEAMID.com.example.postgres";
const KEY_ID = Buffer.alloc(32, 0x71);
const PUBLIC_KEY = Buffer.alloc(91, 0x72).toString("base64");
const UINT32_MAX = 0xffff_ffff;

describe.skipIf(!DATABASE_URL)("PostgreSQL adapter contract", () => {
  it("atomically consumes challenges and grants and guards a UInt32 counter", async () => {
    const pool = new Pool({ connectionString: DATABASE_URL });
    const assertionBarrier = twoPartyBarrier();
    const provider = mockProvider(assertionBarrier);
    const diagnosticReasons: string[] = [];
    const composition = createDeviceAttestation({
      providers: [provider],
      purposes: {
        credentialRegistration: {
          challengeTtlSeconds: 120,
          unboundCredentialTtlSeconds: 3600,
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
          diagnosticReasons.push(`${event.stage}:${event.reason}`);
        },
      },
    });
    const auth = betterAuth({
      baseURL: "http://localhost:3000",
      secret: "postgres-test-secret-at-least-thirty-two-characters",
      database: pool,
      plugins: [composition.serverPlugin],
    });
    const binding = oauthBinding();
    const verifyRegistration = (challengeToken: string) =>
      auth.api.verifyDeviceAttestation({
        body: {
          challengeToken,
          keyId: KEY_ID.toString("base64"),
          evidence: Buffer.from("registration").toString("base64"),
        },
      });
    const createAssertionChallenge = () =>
      auth.api.createDeviceAttestationChallenge({
        body: {
          provider: provider.id,
          applicationId: APP_ID,
          operation: "assert",
          keyId: KEY_ID.toString("base64"),
          purpose: "oauth-authorization",
          binding,
        },
      });
    const verifyAssertion = (challengeToken: string) =>
      auth.api.verifyDeviceAttestation({
        body: {
          challengeToken,
          keyId: KEY_ID.toString("base64"),
          evidence: Buffer.from("assertion").toString("base64"),
        },
      });

    try {
      const context = await auth.$context;
      await context.runMigrations();

      const registrationChallenge =
        await auth.api.createDeviceAttestationChallenge({
          body: {
            provider: provider.id,
            applicationId: APP_ID,
            operation: "register",
            keyId: KEY_ID.toString("base64"),
            purpose: "credential-registration",
          },
        });
      const registrationAttempts = await Promise.allSettled([
        verifyRegistration(registrationChallenge.challengeToken),
        verifyRegistration(registrationChallenge.challengeToken),
      ]);
      expect(
        registrationAttempts.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);

      const credential =
        await context.adapter.findOne<StoredAttestationCredential>({
          model: "deviceAttestationCredential",
          where: [{ field: "applicationId", value: APP_ID }],
        });
      if (!credential) {
        expect.fail(
          "Expected PostgreSQL registration to persist a credential.",
        );
      }
      expect(Number(credential.validationCategory)).toBe(UINT32_MAX);
      await context.adapter.update({
        model: "deviceAttestationCredential",
        where: [{ field: "id", value: credential.id }],
        update: { counter: 0x7fff_ffff },
      });

      const firstChallenge = await createAssertionChallenge();
      const secondChallenge = await createAssertionChallenge();
      const assertionAttempts = await Promise.allSettled([
        verifyAssertion(firstChallenge.challengeToken),
        verifyAssertion(secondChallenge.challengeToken),
      ]);
      const successfulAssertions = assertionAttempts.filter(
        (
          result,
        ): result is PromiseFulfilledResult<{
          grantToken: string;
          expiresAt: Date;
          credentialState: "asserted";
        }> => result.status === "fulfilled",
      );
      const assertionFailures = assertionAttempts
        .filter(
          (result): result is PromiseRejectedResult =>
            result.status === "rejected",
        )
        .map((result) =>
          result.reason instanceof Error
            ? `${result.reason.name}: ${result.reason.message}`
            : String(result.reason),
        );
      expect(
        successfulAssertions,
        [...assertionFailures, ...diagnosticReasons].join("\n"),
      ).toHaveLength(1);
      expect(
        assertionAttempts.filter((result) => result.status === "rejected"),
      ).toHaveLength(1);

      const advanced =
        await context.adapter.findOne<StoredAttestationCredential>({
          model: "deviceAttestationCredential",
          where: [{ field: "id", value: credential.id }],
        });
      expect(Number(advanced?.counter)).toBe(0x8000_0000);

      const user = await context.adapter.create<{
        id: string;
        name: string;
        email: string;
        emailVerified: boolean;
        createdAt: Date;
        updatedAt: Date;
      }>({
        model: "user",
        data: {
          name: "PostgreSQL User",
          email: "postgres@example.com",
          emailVerified: true,
          createdAt: new Date(),
          updatedAt: new Date(),
        },
      });
      const protectedOAuth = composition.protectOAuthProvider({
        loginPage: "/login",
        consentPage: "/consent",
        customTokenResponseFields: (context: OAuthProviderTokenContext) => {
          void context;
          return {};
        },
      });
      const grantToken = successfulAssertions[0]?.value.grantToken;
      if (!grantToken) {
        expect.fail("Expected a successful assertion grant.");
      }
      const tokenContext = oauthTokenContext(binding, grantToken, user);
      const grantAttempts = await Promise.allSettled([
        Promise.resolve(
          protectedOAuth.customTokenResponseFields?.(tokenContext),
        ),
        Promise.resolve(
          protectedOAuth.customTokenResponseFields?.(tokenContext),
        ),
      ]);
      expect(
        grantAttempts.filter((result) => result.status === "fulfilled"),
      ).toHaveLength(1);
      expect(
        grantAttempts.filter((result) => result.status === "rejected"),
      ).toHaveLength(1);
    } finally {
      await pool.end();
    }
  }, 30_000);
});

function mockProvider(
  assertionBarrier: () => Promise<void>,
): DeviceAttestationProvider {
  return {
    id: "postgres-attestation",
    maxEvidenceBytes: 1024,
    decodeKeyId(value) {
      return decodeBase64Strict(value, {
        label: "postgres_key_id",
        exactBytes: 32,
        maxBytes: 32,
      });
    },
    verifyRegistration() {
      return Promise.resolve({
        applicationId: APP_ID,
        environment: "production",
        publicKey: PUBLIC_KEY,
        counter: 0,
        extensionsPresent: true,
        validationCategory: UINT32_MAX,
      });
    },
    async verifyAssertion(input) {
      await assertionBarrier();
      expect(input.credential.validationCategory).toBe(UINT32_MAX);
      return {
        counter: input.credential.counter + 1,
        extensionsPresent: true,
        validationCategory: UINT32_MAX,
      };
    },
  };
}

function oauthBinding(): OAuthAuthorizationBinding {
  return {
    clientId: "mobile-app",
    redirectUri: "com.example.mobile:/oauth/callback",
    codeChallenge: Buffer.alloc(32, 0x73).toString("base64url"),
    codeChallengeMethod: "S256",
    dpopJkt: sha256(Buffer.from("postgres-dpop-key")).toString("base64url"),
    scope: "openid offline_access",
  };
}

function oauthTokenContext(
  binding: OAuthAuthorizationBinding,
  grantToken: string,
  user: {
    id: string;
    name: string;
    email: string;
    emailVerified: boolean;
    createdAt: Date;
    updatedAt: Date;
  },
): OAuthProviderTokenContext {
  const query: StoredAuthorizationQuery & { device_attestation: string } = {
    response_type: "code",
    client_id: binding.clientId,
    redirect_uri: binding.redirectUri,
    code_challenge: binding.codeChallenge,
    code_challenge_method: binding.codeChallengeMethod,
    dpop_jkt: binding.dpopJkt,
    scope: binding.scope,
    device_attestation: grantToken,
  };
  return {
    grantType: "authorization_code",
    user,
    scopes: ["openid", "offline_access"],
    verificationValue: {
      type: "authorization_code",
      query,
      sessionId: "postgres-session",
      userId: user.id,
    },
  };
}

function twoPartyBarrier(): () => Promise<void> {
  let arrivals = 0;
  let release: () => void = () => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });
  return async () => {
    arrivals += 1;
    if (arrivals === 2) {
      release();
    }
    await gate;
  };
}
