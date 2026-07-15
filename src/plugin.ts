import { randomBytes } from "node:crypto";

import type { BetterAuthPlugin } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  sensitiveSessionMiddleware,
} from "better-auth/api";
import { z } from "zod";

import {
  decodeBase64Strict,
  decodeBase64UrlStrict,
} from "./encoding/base64.js";
import {
  DEVICE_ATTESTATION_ERROR_CODES,
  DeviceAttestationError,
  deviceAttestationErrorMessage,
  rejection,
} from "./errors.js";
import {
  createClientData,
  hashOAuthBinding,
  normalizeOAuthBinding,
} from "./protocol/binding.js";
import {
  credentialLookupKey,
  equalBytes,
  hmacSha256,
  randomToken,
  sha256,
} from "./protocol/crypto.js";
import { deviceAttestationSchema } from "./schema.js";
import type {
  AssertionVerificationResult,
  DeviceAttestationComposition,
  DeviceAttestationOptions,
  DeviceAttestationProvider,
  OAuthAuthorizationBinding,
  OAuthProviderCompositionOptions,
  OAuthProviderTokenContext,
  RegistrationVerificationResult,
  StoredAttestationCredential,
} from "./types.js";

const PLUGIN_VERSION = "0.1.0-alpha.0";
const CREDENTIAL_MODEL = "deviceAttestationCredential";
const UINT32_MAX = 0xffff_ffff;

const oauthBindingSchema = z.object({
  clientId: z.string().min(1).max(256),
  redirectUri: z.string().min(1).max(2048),
  codeChallenge: z.string().min(1).max(256),
  codeChallengeMethod: z.literal("S256"),
  dpopJkt: z.string().min(1).max(256),
  scope: z.string().min(1).max(2048),
  resources: z.array(z.string().min(1).max(2048)).max(16).optional(),
  nonce: z.string().max(512).optional(),
});

const challengeBodySchema = z.discriminatedUnion("operation", [
  z.object({
    provider: z.string().min(1).max(64),
    applicationId: z.string().min(1).max(512),
    operation: z.literal("register"),
    keyId: z.string().min(1).max(1024),
    purpose: z.literal("credential-registration"),
  }),
  z.object({
    provider: z.string().min(1).max(64),
    applicationId: z.string().min(1).max(512),
    operation: z.literal("assert"),
    keyId: z.string().min(1).max(1024),
    purpose: z.literal("oauth-authorization"),
    binding: oauthBindingSchema,
  }),
]);

const verifyBodySchema = z.object({
  challengeToken: z.string().min(1).max(128),
  keyId: z.string().min(1).max(1024),
  evidence: z.string().min(1),
});

const retireBodySchema = z.object({
  credentialId: z.string().min(1).max(512),
});

const challengeStateSchema = z.object({
  version: z.literal(1),
  provider: z.string(),
  applicationId: z.string(),
  operation: z.enum(["register", "assert"]),
  purpose: z.enum(["credential-registration", "oauth-authorization"]),
  credentialLookupKey: z.string(),
  clientDataHash: z.string(),
  bindingHash: z.string().optional(),
});

const grantStateSchema = z.object({
  version: z.literal(1),
  provider: z.string(),
  applicationId: z.string(),
  credentialId: z.string(),
  bindingHash: z.string(),
  counterExhausted: z.boolean(),
});

type RuntimeContext = Parameters<NonNullable<BetterAuthPlugin["init"]>>[0];

/**
 * Create a stateful Better Auth device-attestation composition.
 *
 * Install `serverPlugin` in exactly one `betterAuth()` instance. When the
 * Better Auth OAuth Provider is used, pass its options through
 * `protectOAuthProvider()` before installing it. The composition owns one-time
 * challenge and grant state, credential persistence, counter updates, user
 * binding, lifecycle hooks, rate limits, and safe error translation.
 *
 * @throws {TypeError} When providers or lifecycle policy are invalid, or when
 * the same composition initializes more than once.
 */
export function createDeviceAttestation(options: DeviceAttestationOptions) {
  const providers = new Map<string, DeviceAttestationProvider>();
  for (const provider of options.providers) {
    if (providers.has(provider.id)) {
      throw new TypeError(
        `Duplicate device attestation provider: ${provider.id}`,
      );
    }
    providers.set(provider.id, provider);
  }
  if (providers.size === 0) {
    throw new TypeError(
      "At least one device attestation provider is required.",
    );
  }
  const oauthPurpose = options.purposes.oauthAuthorization;
  const registrationPurpose = options.purposes.credentialRegistration;
  if (
    oauthPurpose.requireDpopJkt !== true ||
    oauthPurpose.protectedClientIds.length === 0 ||
    oauthPurpose.protectedClientIds.some((clientId) => clientId.length === 0)
  ) {
    throw new TypeError(
      "OAuth authorization requires DPoP and at least one non-empty protected client ID.",
    );
  }
  if (
    new Set(oauthPurpose.protectedClientIds).size !==
    oauthPurpose.protectedClientIds.length
  ) {
    throw new TypeError("protectedClientIds must not contain duplicates.");
  }

  const challengeTtlSeconds = positiveSeconds(
    oauthPurpose.challengeTtlSeconds,
    120,
    "purposes.oauthAuthorization.challengeTtlSeconds",
  );
  const registrationChallengeTtlSeconds = positiveSeconds(
    registrationPurpose.challengeTtlSeconds,
    120,
    "purposes.credentialRegistration.challengeTtlSeconds",
  );
  const grantTtlSeconds = positiveSeconds(
    oauthPurpose.grantTtlSeconds,
    300,
    "purposes.oauthAuthorization.grantTtlSeconds",
  );
  const unboundCredentialTtlSeconds = positiveSeconds(
    registrationPurpose.unboundCredentialTtlSeconds,
    24 * 60 * 60,
    "purposes.credentialRegistration.unboundCredentialTtlSeconds",
  );
  const expiredCredentialRetentionSeconds = positiveSeconds(
    registrationPurpose.expiredCredentialRetentionSeconds,
    7 * 24 * 60 * 60,
    "purposes.credentialRegistration.expiredCredentialRetentionSeconds",
  );
  const maxActiveUnboundCredentialsPerApplication = optionalPositiveInteger(
    registrationPurpose.maxActiveUnboundCredentialsPerApplication,
    "purposes.credentialRegistration.maxActiveUnboundCredentialsPerApplication",
  );

  let runtime: RuntimeContext | undefined;

  const serverPlugin = {
    id: "device-attestation",
    version: PLUGIN_VERSION,
    $ERROR_CODES: DEVICE_ATTESTATION_ERROR_CODES,
    schema: deviceAttestationSchema,
    init(context) {
      if (runtime !== undefined) {
        throw new TypeError(
          "A device attestation composition cannot initialize more than once.",
        );
      }
      runtime = context;
      const hostBeforeUserDelete =
        context.options.databaseHooks?.user?.delete?.before;
      return {
        options: {
          databaseHooks: {
            user: {
              delete: {
                before: async (user, hookContext) => {
                  const hostResult = await hostBeforeUserDelete?.(
                    user,
                    hookContext,
                  );
                  if (hostResult === false) {
                    return false;
                  }
                  await retireCredentialsForUser(context, user.id);
                },
              },
            },
          },
        },
      };
    },
    rateLimit: [
      {
        window: 60,
        max: 30,
        pathMatcher: (path) => path === "/device-attestation/challenge",
      },
      {
        window: 60,
        max: 20,
        pathMatcher: (path) => path === "/device-attestation/verify",
      },
    ],
    endpoints: {
      createDeviceAttestationChallenge: createAuthEndpoint(
        "/device-attestation/challenge",
        {
          method: "POST",
          body: challengeBodySchema,
          metadata: {
            openapi: {
              operationId: "createDeviceAttestationChallenge",
              description: "Create a one-time device-attestation challenge.",
            },
          },
        },
        async (ctx) =>
          withPublicError(
            options,
            () => ({ provider: ctx.body.provider, operation: "challenge" }),
            async () => {
              const provider = requireProvider(providers, ctx.body.provider);
              const keyId = provider.decodeKeyId(ctx.body.keyId);
              const lookupKey = credentialLookupKey({
                provider: provider.id,
                applicationId: ctx.body.applicationId,
                keyId,
              });

              if (ctx.body.operation === "assert") {
                const credential =
                  await ctx.context.adapter.findOne<StoredAttestationCredential>(
                    {
                      model: CREDENTIAL_MODEL,
                      where: [{ field: "lookupKey", value: lookupKey }],
                    },
                  );
                requireUsableCredential(credential);
              } else {
                await maintainUnboundCredentials(
                  ctx.context,
                  provider.id,
                  ctx.body.applicationId,
                  expiredCredentialRetentionSeconds,
                );
              }

              const bindingHash =
                ctx.body.operation === "assert"
                  ? hashOAuthBinding(ctx.body.binding)
                  : undefined;
              const clientData = createClientData({
                nonce: randomBytes(32),
                provider: provider.id,
                operation: ctx.body.operation,
                purpose: ctx.body.purpose,
                applicationId: ctx.body.applicationId,
                keyLookupHash: lookupKey,
                ...(bindingHash === undefined ? {} : { bindingHash }),
              });
              const token = randomToken();
              const challengeTtl =
                ctx.body.operation === "register"
                  ? registrationChallengeTtlSeconds
                  : challengeTtlSeconds;
              const expiresAt = new Date(Date.now() + challengeTtl * 1000);
              const state = {
                version: 1,
                provider: provider.id,
                applicationId: ctx.body.applicationId,
                operation: ctx.body.operation,
                purpose: ctx.body.purpose,
                credentialLookupKey: lookupKey,
                clientDataHash: sha256(clientData).toString("base64url"),
                ...(bindingHash === undefined
                  ? {}
                  : { bindingHash: bindingHash.toString("base64url") }),
              } as const;

              await ctx.context.internalAdapter.createVerificationValue({
                identifier: challengeIdentifier(ctx.context.secret, token),
                value: JSON.stringify(state),
                expiresAt,
              });

              return ctx.json({
                challengeToken: token,
                clientData: clientData.toString("base64url"),
                expiresAt,
              });
            },
          ),
      ),
      verifyDeviceAttestation: createAuthEndpoint(
        "/device-attestation/verify",
        {
          method: "POST",
          body: verifyBodySchema,
          metadata: {
            openapi: {
              operationId: "verifyDeviceAttestation",
              description:
                "Consume a challenge and verify attestation evidence.",
            },
          },
        },
        async (ctx) => {
          let providerId = "unknown";
          let operation: "verify" | "register" | "assert" = "verify";
          return withPublicError(
            options,
            () => ({ provider: providerId, operation }),
            async () => {
              decodeBase64UrlStrict(ctx.body.challengeToken, {
                label: "challenge_token",
                maxBytes: 32,
                exactBytes: 32,
              });
              const verification =
                await ctx.context.internalAdapter.consumeVerificationValue(
                  challengeIdentifier(
                    ctx.context.secret,
                    ctx.body.challengeToken,
                  ),
                );
              if (!verification) {
                throw new DeviceAttestationError({
                  code: "DEVICE_ATTESTATION_CHALLENGE_EXPIRED",
                  stage: "challenge",
                  reason: "challenge_unavailable",
                });
              }

              const state = parseStoredState(
                challengeStateSchema,
                verification.value,
                "invalid_challenge_state",
              );
              providerId = state.provider;
              operation = state.operation;
              const provider = requireProvider(providers, state.provider);
              const keyId = provider.decodeKeyId(ctx.body.keyId);
              const lookupKey = credentialLookupKey({
                provider: provider.id,
                applicationId: state.applicationId,
                keyId,
              });
              if (lookupKey !== state.credentialLookupKey) {
                throw rejection("challenge", "credential_lookup_mismatch");
              }

              const evidence = decodeBase64Strict(ctx.body.evidence, {
                label: "evidence",
                maxBytes: provider.maxEvidenceBytes,
              });
              const clientDataHash = Buffer.from(
                state.clientDataHash,
                "base64url",
              );

              if (state.operation === "register") {
                await enforceUnboundCredentialQuota(
                  ctx.context,
                  provider.id,
                  state.applicationId,
                  maxActiveUnboundCredentialsPerApplication,
                );
                const result = await provider.verifyRegistration({
                  applicationId: state.applicationId,
                  keyId,
                  clientDataHash,
                  evidence,
                });
                const credential = await registerCredential(
                  ctx.context,
                  provider,
                  lookupKey,
                  state.applicationId,
                  result,
                  unboundCredentialTtlSeconds,
                );
                return ctx.json({
                  credentialId: credential.id,
                  credentialState: "registered-unbound" as const,
                });
              }

              const credential =
                await ctx.context.adapter.findOne<StoredAttestationCredential>({
                  model: CREDENTIAL_MODEL,
                  where: [{ field: "lookupKey", value: lookupKey }],
                });
              requireUsableCredential(credential);
              const normalizedCredential =
                normalizeCredentialCounter(credential);
              const result = await provider.verifyAssertion({
                credential: normalizedCredential,
                keyId,
                clientDataHash,
                evidence,
              });
              const updated = await advanceCounter(
                ctx.context,
                normalizedCredential,
                result,
              );
              const grantToken = randomToken();
              const expiresAt = new Date(Date.now() + grantTtlSeconds * 1000);
              const grant = {
                version: 1,
                provider: provider.id,
                applicationId: state.applicationId,
                credentialId: updated.id,
                bindingHash: requiredBindingHash(state),
                counterExhausted:
                  updated.status === "revoked" &&
                  updated.revocationReason === "counter_exhausted",
              } as const;
              await ctx.context.internalAdapter.createVerificationValue({
                identifier: grantIdentifier(ctx.context.secret, grantToken),
                value: JSON.stringify(grant),
                expiresAt,
              });

              return ctx.json({
                grantToken,
                expiresAt,
                credentialState: "asserted" as const,
              });
            },
          );
        },
      ),
      listDeviceAttestationCredentials: createAuthEndpoint(
        "/device-attestation/credentials",
        {
          method: "GET",
          use: [sensitiveSessionMiddleware],
          metadata: {
            openapi: {
              operationId: "listDeviceAttestationCredentials",
              description:
                "List the authenticated user's device-attestation credentials.",
            },
          },
        },
        async (ctx) => {
          const userId = ctx.context.session.user.id;
          const credentials =
            await ctx.context.adapter.findMany<StoredAttestationCredential>({
              model: CREDENTIAL_MODEL,
              where: [{ field: "userId", value: userId }],
            });
          return ctx.json({
            credentials: credentials.map((credential) => ({
              id: credential.id,
              provider: credential.provider,
              applicationId: credential.applicationId,
              status: credential.status,
            })),
          });
        },
      ),
      retireDeviceAttestationCredential: createAuthEndpoint(
        "/device-attestation/credentials/retire",
        {
          method: "POST",
          body: retireBodySchema,
          use: [sensitiveSessionMiddleware],
          metadata: {
            openapi: {
              operationId: "retireDeviceAttestationCredential",
              description:
                "Permanently retire one device-attestation credential owned by the authenticated user.",
            },
          },
        },
        async (ctx) => {
          const retired =
            await ctx.context.adapter.incrementOne<StoredAttestationCredential>(
              {
                model: CREDENTIAL_MODEL,
                where: [
                  { field: "id", value: ctx.body.credentialId },
                  { field: "userId", value: ctx.context.session.user.id },
                  { field: "status", value: "active" },
                ],
                increment: { bindingVersion: 1 },
                set: {
                  status: "revoked",
                  revokedAt: new Date(),
                  revocationReason: "user",
                  publicKey: null,
                  validationCategory: null,
                  bundleVersion: null,
                },
              },
            );
          if (!retired) {
            throw new APIError("NOT_FOUND", {
              code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED",
              message: deviceAttestationErrorMessage(
                "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED",
              ),
            });
          }
          return ctx.json({ retired: true });
        },
      ),
    },
    options,
  } satisfies BetterAuthPlugin;

  return {
    serverPlugin,
    protectOAuthProvider<T extends OAuthProviderCompositionOptions>(
      oauthOptions: T,
    ): T {
      const hostCallback = oauthOptions.customTokenResponseFields;
      return {
        ...oauthOptions,
        customTokenResponseFields: async (info: OAuthProviderTokenContext) => {
          if (
            info.grantType !== "authorization_code" ||
            !isProtectedClient(info, oauthPurpose.protectedClientIds)
          ) {
            return hostCallback ? await hostCallback(info) : {};
          }

          try {
            await consumeAndBindGrant(requireRuntime(runtime), info);
          } catch (error) {
            await reportDiagnostic(options, error, "unknown", "grant");
            throw toPublicApiError(error);
          }

          return hostCallback ? await hostCallback(info) : {};
        },
      };
    },
  } satisfies DeviceAttestationComposition;
}

async function registerCredential(
  context: RuntimeContext,
  provider: DeviceAttestationProvider,
  lookupKey: string,
  expectedApplicationId: string,
  result: RegistrationVerificationResult,
  unboundCredentialTtlSeconds: number,
): Promise<StoredAttestationCredential> {
  if (result.applicationId !== expectedApplicationId || result.counter !== 0) {
    throw rejection("app-identity", "invalid_registration_result");
  }
  const existing = await context.adapter.findOne<StoredAttestationCredential>({
    model: CREDENTIAL_MODEL,
    where: [{ field: "lookupKey", value: lookupKey }],
  });
  if (existing) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED",
      stage: "credential-binding",
      reason: "credential_already_registered",
    });
  }

  return context.adapter.create<StoredAttestationCredential>({
    model: CREDENTIAL_MODEL,
    data: {
      lookupKey,
      provider: provider.id,
      applicationId: result.applicationId,
      environment: result.environment,
      publicKey: result.publicKey,
      counter: 0,
      userId: null,
      bindingVersion: 0,
      status: "active",
      extensionsPresent: result.extensionsPresent,
      unboundExpiresAt: new Date(
        Date.now() + unboundCredentialTtlSeconds * 1000,
      ),
      ...(result.validationCategory === undefined
        ? {}
        : { validationCategory: result.validationCategory }),
      ...(result.bundleVersion === undefined
        ? {}
        : { bundleVersion: result.bundleVersion }),
    },
  });
}

async function advanceCounter(
  context: RuntimeContext,
  credential: StoredAttestationCredential,
  result: AssertionVerificationResult,
): Promise<StoredAttestationCredential> {
  if (
    !Number.isSafeInteger(result.counter) ||
    result.counter <= credential.counter ||
    result.counter > UINT32_MAX
  ) {
    throw rejection("counter", "invalid_assertion_counter");
  }

  const exhausted = result.counter === UINT32_MAX;
  const updated =
    await context.adapter.incrementOne<StoredAttestationCredential>({
      model: CREDENTIAL_MODEL,
      where: [
        { field: "id", value: credential.id },
        { field: "counter", value: credential.counter },
        { field: "status", value: "active" },
      ],
      increment: { counter: result.counter - credential.counter },
      set: {
        lastUsedAt: new Date(),
        extensionsPresent: result.extensionsPresent,
        validationCategory: result.validationCategory ?? null,
        bundleVersion: result.bundleVersion ?? null,
        ...(exhausted
          ? {
              status: "revoked",
              revokedAt: new Date(),
              revocationReason: "counter_exhausted",
            }
          : {}),
      },
    });
  if (!updated) {
    throw rejection("counter", "assertion_counter_race");
  }
  return updated;
}

async function retireCredentialsForUser(
  context: RuntimeContext,
  userId: string,
): Promise<void> {
  await context.adapter.updateMany({
    model: CREDENTIAL_MODEL,
    where: [
      { field: "userId", value: userId },
      { field: "status", value: "active" },
    ],
    update: {
      status: "revoked",
      revokedAt: new Date(),
      revocationReason: "user_deleted",
      publicKey: null,
      validationCategory: null,
      bundleVersion: null,
      unboundExpiresAt: null,
    },
  });
}

async function maintainUnboundCredentials(
  context: RuntimeContext,
  provider: string,
  applicationId: string,
  retentionSeconds: number,
): Promise<void> {
  const now = new Date();
  await context.adapter.updateMany({
    model: CREDENTIAL_MODEL,
    where: [
      { field: "provider", value: provider },
      { field: "applicationId", value: applicationId },
      { field: "status", value: "active" },
      { field: "userId", value: null },
      { field: "unboundExpiresAt", value: now, operator: "lt" },
    ],
    update: {
      status: "expired",
      publicKey: null,
      validationCategory: null,
      bundleVersion: null,
      updatedAt: now,
    },
  });
  await context.adapter.deleteMany({
    model: CREDENTIAL_MODEL,
    where: [
      { field: "provider", value: provider },
      { field: "applicationId", value: applicationId },
      { field: "status", value: "expired" },
      { field: "userId", value: null },
      {
        field: "updatedAt",
        value: new Date(now.getTime() - retentionSeconds * 1000),
        operator: "lt",
      },
    ],
  });
}

async function enforceUnboundCredentialQuota(
  context: RuntimeContext,
  provider: string,
  applicationId: string,
  maximum: number | undefined,
): Promise<void> {
  if (maximum === undefined) {
    return;
  }
  const count = await context.adapter.count({
    model: CREDENTIAL_MODEL,
    where: [
      { field: "provider", value: provider },
      { field: "applicationId", value: applicationId },
      { field: "status", value: "active" },
      { field: "userId", value: null },
    ],
  });
  if (count >= maximum) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_RETRY",
      stage: "storage",
      reason: "unbound_credential_quota_reached",
      retryable: true,
    });
  }
}

async function consumeAndBindGrant(
  runtime: RuntimeContext,
  info: OAuthProviderTokenContext,
): Promise<void> {
  const query = info.verificationValue?.query;
  const grantToken = readQueryString(query, "device_attestation");
  const userId = info.user?.id;
  if (!grantToken || !userId) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_GRANT_REQUIRED",
      stage: "grant-binding",
      reason: "missing_grant_or_user",
    });
  }

  decodeBase64UrlStrict(grantToken, {
    label: "grant_token",
    maxBytes: 32,
    exactBytes: 32,
  });
  const verification = await runtime.internalAdapter.consumeVerificationValue(
    grantIdentifier(runtime.secret, grantToken),
  );
  if (!verification) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_GRANT_REQUIRED",
      stage: "grant-binding",
      reason: "grant_unavailable",
    });
  }
  const grant = parseStoredState(
    grantStateSchema,
    verification.value,
    "invalid_grant_state",
  );
  const binding = oauthBindingFromQuery(query);
  const actualBindingHash = hashOAuthBinding(binding);
  if (
    !equalBytes(actualBindingHash, Buffer.from(grant.bindingHash, "base64url"))
  ) {
    throw rejection("grant-binding", "oauth_binding_mismatch");
  }

  const credential = await runtime.adapter.findOne<StoredAttestationCredential>(
    {
      model: CREDENTIAL_MODEL,
      where: [{ field: "id", value: grant.credentialId }],
    },
  );
  const exhaustedCredential =
    grant.counterExhausted &&
    credential?.status === "revoked" &&
    credential.revocationReason === "counter_exhausted";
  if (!exhaustedCredential) {
    requireUsableCredential(credential);
  }
  if (!credential) {
    throw rejection("credential-binding", "credential_not_found");
  }
  if (
    credential.provider !== grant.provider ||
    credential.applicationId !== grant.applicationId
  ) {
    throw rejection("grant-binding", "grant_credential_mismatch");
  }
  if (credential.userId === userId) {
    return;
  }
  if (credential.userId) {
    throw rejection("credential-binding", "credential_user_mismatch");
  }
  if (
    !credential.unboundExpiresAt ||
    credential.unboundExpiresAt.getTime() <= Date.now()
  ) {
    throw rejection("credential-binding", "unbound_credential_expired");
  }

  const bound = await runtime.adapter.incrementOne<StoredAttestationCredential>(
    {
      model: CREDENTIAL_MODEL,
      where: [
        { field: "id", value: credential.id },
        { field: "bindingVersion", value: 0 },
        { field: "userId", value: null },
        {
          field: "status",
          value: exhaustedCredential ? "revoked" : "active",
        },
      ],
      increment: { bindingVersion: 1 },
      set: {
        userId,
        boundAt: new Date(),
        unboundExpiresAt: null,
      },
    },
  );
  if (!bound) {
    const raced = await runtime.adapter.findOne<StoredAttestationCredential>({
      model: CREDENTIAL_MODEL,
      where: [{ field: "id", value: credential.id }],
    });
    if (raced?.userId !== userId || raced.status !== "active") {
      throw rejection("credential-binding", "credential_binding_race");
    }
  }
}

function oauthBindingFromQuery(
  query: object | undefined,
): OAuthAuthorizationBinding {
  const resource = readQueryValue(query, "resource");
  const resources = Array.isArray(resource)
    ? resource.filter((value): value is string => typeof value === "string")
    : typeof resource === "string"
      ? [resource]
      : undefined;
  return normalizeOAuthBinding({
    clientId: requireQueryString(query, "client_id"),
    redirectUri: requireQueryString(query, "redirect_uri"),
    codeChallenge: requireQueryString(query, "code_challenge"),
    codeChallengeMethod: requireQueryString(
      query,
      "code_challenge_method",
    ) as "S256",
    dpopJkt: requireQueryString(query, "dpop_jkt"),
    scope: requireQueryString(query, "scope"),
    ...(resources === undefined ? {} : { resources }),
    ...(typeof readQueryValue(query, "nonce") === "string"
      ? { nonce: readQueryValue(query, "nonce") as string }
      : {}),
  });
}

function requireUsableCredential(
  credential: StoredAttestationCredential | null,
): asserts credential is StoredAttestationCredential {
  if (!credential || credential.status !== "active" || !credential.publicKey) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED",
      stage: "credential-binding",
      reason: "credential_not_active",
    });
  }
  if (
    !credential.userId &&
    (!credential.unboundExpiresAt ||
      credential.unboundExpiresAt.getTime() <= Date.now())
  ) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_CREDENTIAL_REQUIRED",
      stage: "credential-binding",
      reason: "unbound_credential_expired",
    });
  }
}

function normalizeCredentialCounter(
  credential: StoredAttestationCredential,
): StoredAttestationCredential {
  const value: unknown = credential.counter;
  const counter =
    typeof value === "number"
      ? value
      : typeof value === "string" && /^(0|[1-9][0-9]*)$/u.test(value)
        ? Number(value)
        : Number.NaN;
  if (!Number.isSafeInteger(counter) || counter < 0 || counter > UINT32_MAX) {
    throw rejection("storage", "invalid_stored_counter");
  }
  return counter === value ? credential : { ...credential, counter };
}

function challengeIdentifier(secret: string, token: string): string {
  return `device-attestation:challenge:${hmacSha256(secret, token)}`;
}

function grantIdentifier(secret: string, token: string): string {
  return `device-attestation:grant:${hmacSha256(secret, token)}`;
}

function requiredBindingHash(state: {
  bindingHash?: string | undefined;
}): string {
  if (!state.bindingHash) {
    throw rejection("grant-binding", "missing_binding_hash");
  }
  return state.bindingHash;
}

function requireProvider(
  providers: Map<string, DeviceAttestationProvider>,
  id: string,
): DeviceAttestationProvider {
  const provider = providers.get(id);
  if (!provider) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_INVALID_REQUEST",
      stage: "request",
      reason: "unknown_provider",
    });
  }
  return provider;
}

function parseStoredState<T extends z.ZodType>(
  schema: T,
  value: string,
  reason: string,
): z.output<T> {
  try {
    return schema.parse(JSON.parse(value) as unknown);
  } catch {
    throw rejection("storage", reason);
  }
}

async function withPublicError<T>(
  options: DeviceAttestationOptions,
  context: () => {
    provider: string;
    operation: "challenge" | "verify" | "register" | "assert" | "grant";
  },
  action: () => Promise<T>,
): Promise<T> {
  try {
    return await action();
  } catch (error) {
    const { provider, operation } = context();
    await reportDiagnostic(options, error, provider, operation);
    throw toPublicApiError(error);
  }
}

async function reportDiagnostic(
  options: DeviceAttestationOptions,
  error: unknown,
  provider: string,
  operation: "challenge" | "verify" | "register" | "assert" | "grant",
): Promise<void> {
  const report = options.diagnostics?.report;
  if (!report) {
    return;
  }
  const failure =
    error instanceof DeviceAttestationError
      ? error
      : new DeviceAttestationError({
          code: "DEVICE_ATTESTATION_RETRY",
          stage: "unexpected",
          reason: "unexpected_failure",
          retryable: true,
        });
  try {
    await report({
      provider,
      operation,
      stage: failure.stage,
      reason: failure.reason,
      retryable: failure.retryable,
      ...(failure.measurements === undefined
        ? {}
        : { measurements: failure.measurements }),
    });
  } catch {
    // Diagnostic delivery must not replace the original authentication result.
  }
}

function toPublicApiError(error: unknown): APIError {
  const failure =
    error instanceof DeviceAttestationError
      ? error
      : new DeviceAttestationError({
          code: "DEVICE_ATTESTATION_RETRY",
          stage: "unexpected",
          reason: "unexpected_failure",
          retryable: true,
        });
  const status = failure.retryable ? "SERVICE_UNAVAILABLE" : "FORBIDDEN";
  return new APIError(status, {
    code: failure.code,
    message: deviceAttestationErrorMessage(failure.code),
  });
}

function positiveSeconds(
  value: number | undefined,
  fallback: number,
  label: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) {
    throw new TypeError(`${label} must be a positive safe integer.`);
  }
  return resolved;
}

function optionalPositiveInteger(
  value: number | undefined,
  label: string,
): number | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new TypeError(`${label} must be a positive safe integer.`);
  }
  return value;
}

function isProtectedClient(
  info: OAuthProviderTokenContext,
  protectedClientIds: string[],
): boolean {
  const clientId = readQueryString(info.verificationValue?.query, "client_id");
  return clientId !== undefined && protectedClientIds.includes(clientId);
}

function readQueryString(
  query: object | undefined,
  key: string,
): string | undefined {
  const value = readQueryValue(query, key);
  return typeof value === "string" ? value : undefined;
}

function readQueryValue(query: object | undefined, key: string): unknown {
  return query === undefined ? undefined : Reflect.get(query, key);
}

function requireQueryString(query: object | undefined, key: string): string {
  const value = readQueryString(query, key);
  if (!value) {
    throw rejection("grant-binding", `missing_${key}`);
  }
  return value;
}

function requireRuntime(runtime: RuntimeContext | undefined): RuntimeContext {
  if (!runtime) {
    throw new DeviceAttestationError({
      code: "DEVICE_ATTESTATION_RETRY",
      stage: "storage",
      reason: "plugin_not_initialized",
      retryable: true,
    });
  }
  return runtime;
}
