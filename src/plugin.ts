import { randomBytes } from "node:crypto";

import type { BetterAuthPlugin } from "better-auth";
import {
  APIError,
  createAuthEndpoint,
  sensitiveSessionMiddleware,
} from "better-auth/api";

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
  advanceCounter,
  CREDENTIAL_MODEL,
  enforceUnboundCredentialQuota,
  maintainUnboundCredentials,
  normalizeCredentialIntegers,
  registerCredential,
  requireUsableCredential,
  retireCredentialsForUser,
  type RuntimeContext,
} from "./credential-store.js";
import {
  reportDiagnostic,
  toPublicApiError,
  withPublicError,
} from "./diagnostics.js";
import {
  consumeAndBindGrant,
  grantIdentifier,
  isProtectedClient,
} from "./oauth-grant.js";
import { resolveDeviceAttestationOptions } from "./plugin-options.js";
import {
  challengeBodySchema,
  challengeStateSchema,
  retireBodySchema,
  verifyBodySchema,
} from "./plugin-schemas.js";
import { createClientData, hashOAuthBinding } from "./protocol/binding.js";
import {
  credentialLookupKey,
  hmacSha256,
  randomToken,
  sha256,
} from "./protocol/crypto.js";
import { deviceAttestationSchema } from "./schema.js";
import type {
  DeviceAttestationComposition,
  DeviceAttestationOptions,
  DeviceAttestationProvider,
  OAuthProviderCompositionOptions,
  OAuthProviderTokenContext,
  StoredAttestationCredential,
} from "./types.js";

const PLUGIN_VERSION = "0.1.0-alpha.0";

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
  const resolved = resolveDeviceAttestationOptions(options);
  const { providers } = resolved;
  const oauthPurpose = options.purposes.oauthAuthorization;

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
                  resolved.expiredCredentialRetentionSeconds,
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
                  ? resolved.registrationChallengeTtlSeconds
                  : resolved.challengeTtlSeconds;
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

              const state = parseChallengeState(verification.value);
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
                  resolved.maxActiveUnboundCredentialsPerApplication,
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
                  resolved.unboundCredentialTtlSeconds,
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
                normalizeCredentialIntegers(credential);
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
              const expiresAt = new Date(
                Date.now() + resolved.grantTtlSeconds * 1000,
              );
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

function challengeIdentifier(secret: string, token: string): string {
  return `device-attestation:challenge:${hmacSha256(secret, token)}`;
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

function parseChallengeState(value: string) {
  try {
    return challengeStateSchema.parse(JSON.parse(value) as unknown);
  } catch {
    throw rejection("storage", "invalid_challenge_state");
  }
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
