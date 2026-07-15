import type { BetterAuthPlugin } from "better-auth";
import type { OAuthOptions } from "@better-auth/oauth-provider";

import type { DeviceAttestationDiagnosticEvent } from "./errors.js";

export type DeviceAttestationEnvironment = "development" | "production";

export interface OAuthAuthorizationBinding {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: "S256";
  dpopJkt: string;
  scope: string;
  resources?: string[] | undefined;
  nonce?: string | undefined;
}

export interface StoredAttestationCredential {
  id: string;
  lookupKey: string;
  provider: string;
  applicationId: string;
  environment: DeviceAttestationEnvironment;
  publicKey?: string | null;
  counter: number;
  userId?: string | null;
  bindingVersion: number;
  status: "active" | "expired" | "revoked";
  validationCategory?: number | null;
  bundleVersion?: string | null;
  extensionsPresent: boolean;
  unboundExpiresAt?: Date | null;
  revokedAt?: Date | null;
  revocationReason?:
    "user" | "user_deleted" | "counter_exhausted" | "provider" | null;
}

export interface RegistrationVerificationResult {
  applicationId: string;
  environment: DeviceAttestationEnvironment;
  publicKey: string;
  counter: 0;
  validationCategory?: number;
  bundleVersion?: string;
  extensionsPresent: boolean;
  untrustedReceipt?: Uint8Array;
}

export interface AssertionVerificationResult {
  counter: number;
  validationCategory?: number;
  bundleVersion?: string;
  extensionsPresent: boolean;
}

export interface DeviceAttestationProvider {
  readonly id: string;
  readonly maxEvidenceBytes: number;
  decodeKeyId(value: string): Uint8Array;
  verifyRegistration(input: {
    applicationId: string;
    keyId: Uint8Array;
    clientDataHash: Uint8Array;
    evidence: Uint8Array;
  }): Promise<RegistrationVerificationResult>;
  verifyAssertion(input: {
    credential: StoredAttestationCredential;
    keyId: Uint8Array;
    clientDataHash: Uint8Array;
    evidence: Uint8Array;
  }): Promise<AssertionVerificationResult>;
}

export interface DeviceAttestationOptions {
  providers: DeviceAttestationProvider[];
  purposes: {
    credentialRegistration: {
      challengeTtlSeconds?: number;
      unboundCredentialTtlSeconds?: number;
      expiredCredentialRetentionSeconds?: number;
      maxActiveUnboundCredentialsPerApplication?: number;
    };
    oauthAuthorization: {
      protectedClientIds: string[];
      challengeTtlSeconds?: number;
      grantTtlSeconds?: number;
      requireDpopJkt: true;
    };
  };
  diagnostics?: {
    report?: (event: DeviceAttestationDiagnosticEvent) => void | Promise<void>;
  };
}

export interface VerifiedAttestationGrant {
  credentialId: string;
  provider: string;
  applicationId: string;
  userId: string;
}

export interface DeviceAttestationComposition {
  serverPlugin: BetterAuthPlugin;
  protectOAuthProvider<T extends OAuthProviderCompositionOptions>(
    options: T,
  ): T;
}

export type OAuthProviderCompositionOptions = OAuthOptions;

export type OAuthProviderTokenContext = Parameters<
  NonNullable<OAuthOptions["customTokenResponseFields"]>
>[0];
