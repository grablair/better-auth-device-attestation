import { createPublicKey, verify as verifySignature } from "node:crypto";

import { decodeSingleCbor } from "../cbor/decode.js";
import { decodeBase64Strict } from "../encoding/base64.js";
import { rejection } from "../errors.js";
import { equalBytes, sha256 } from "../protocol/crypto.js";
import type {
  AssertionVerificationResult,
  DeviceAttestationEnvironment,
  DeviceAttestationProvider,
  RegistrationVerificationResult,
} from "../types.js";
import { parseAuthenticatorData } from "./authenticator-data.js";
import { verifyAppAttestCoseKey } from "./cose.js";
import {
  parseAppAttestExtensions,
  type AppAttestExtensions,
} from "./extensions.js";
import { verifyAppAttestCertificateChain } from "./x509.js";

const PRODUCTION_AAGUID = Buffer.concat([
  Buffer.from("appattest", "ascii"),
  Buffer.alloc(7),
]);
const DEVELOPMENT_AAGUID = Buffer.from("appattestdevelop", "ascii");
const DEFAULT_MAX_EVIDENCE_BYTES = 128 * 1024;
const MAX_AUTHENTICATOR_DATA_BYTES = 16 * 1024;
const MAX_RECEIPT_BYTES = 96 * 1024;

declare const untrustedReceiptBrand: unique symbol;

export type UntrustedAppAttestReceipt = Uint8Array & {
  readonly [untrustedReceiptBrand]: true;
};

export type AppAttestExtensionPresence = "if-present" | "required";

export interface AppAttestApplication {
  appId: string;
  environment: DeviceAttestationEnvironment;
  extensions: {
    presence: AppAttestExtensionPresence;
    allowedValidationCategories: readonly number[];
    validateBundleVersion: (version: string) => boolean | Promise<boolean>;
  };
}

export interface AppAttestOptions {
  applications: readonly AppAttestApplication[];
  maxEvidenceBytes?: number;
  receipt?: {
    onReceipt: (
      receipt: UntrustedAppAttestReceipt,
      context: {
        applicationId: string;
        environment: DeviceAttestationEnvironment;
      },
    ) => void | Promise<void>;
    failureMode: "report";
  };
}

interface AttestationEnvelope {
  authData: Buffer;
  certificates: Buffer[];
  receipt: Buffer;
}

interface AssertionEnvelope {
  authenticatorData: Buffer;
  signature: Buffer;
}

export function appAttest(
  options: AppAttestOptions,
): DeviceAttestationProvider {
  const applications = validateApplications(options.applications);
  if (
    options.receipt !== undefined &&
    (options.receipt.failureMode !== "report" ||
      typeof options.receipt.onReceipt !== "function")
  ) {
    throw new TypeError(
      "App Attest receipt handling requires an onReceipt callback and report failure mode.",
    );
  }
  const maxEvidenceBytes = positiveBound(
    options.maxEvidenceBytes,
    DEFAULT_MAX_EVIDENCE_BYTES,
  );

  return {
    id: "app-attest",
    maxEvidenceBytes,
    decodeKeyId(value) {
      return decodeBase64Strict(value, {
        label: "app_attest_key_id",
        maxBytes: 32,
        exactBytes: 32,
      });
    },
    async verifyRegistration(input) {
      const application = requireApplication(applications, input.applicationId);
      const envelope = parseAttestationEnvelope(input.evidence);
      const authData = parseAuthenticatorData(envelope.authData, {
        mode: "attestation",
        maxBytes: MAX_AUTHENTICATOR_DATA_BYTES,
        allowUnflaggedExtensions: true,
      });
      const certificate = await verifyAppAttestCertificateChain(
        envelope.certificates,
      );

      const expectedNonce = sha256(
        Buffer.concat([authData.raw, Buffer.from(input.clientDataHash)]),
      );
      if (!equalBytes(expectedNonce, certificate.nonce)) {
        throw rejection("nonce", "attestation_nonce_mismatch");
      }
      if (!equalBytes(sha256(certificate.publicKeyRaw), input.keyId)) {
        throw rejection("app-identity", "credential_key_id_mismatch");
      }
      verifyRpId(authData.rpIdHash, application.appId);
      if (authData.counter !== 0) {
        throw rejection("counter", "nonzero_attestation_counter");
      }

      const attested = authData.attestedCredentialData;
      if (!attested) {
        throw rejection(
          "authenticator-data",
          "missing_attested_credential_data",
        );
      }
      verifyEnvironment(attested.aaguid, application.environment);
      if (!equalBytes(attested.credentialId, input.keyId)) {
        throw rejection("app-identity", "credential_id_mismatch");
      }
      verifyAppAttestCoseKey(
        attested.credentialPublicKey,
        certificate.publicKeyRaw,
      );

      const extensions = await verifyDistributionPolicy(
        authData.extensions,
        application,
      );
      await reportReceipt(options.receipt, envelope.receipt, application);

      return registrationResult(
        application,
        certificate.publicKeySpki,
        envelope.receipt,
        extensions,
      );
    },
    async verifyAssertion(input) {
      const application = requireApplication(
        applications,
        input.credential.applicationId,
      );
      if (input.credential.environment !== application.environment) {
        throw rejection("environment", "stored_environment_mismatch");
      }

      const envelope = parseAssertionEnvelope(input.evidence);
      const authData = parseAuthenticatorData(envelope.authenticatorData, {
        mode: "assertion",
        maxBytes: MAX_AUTHENTICATOR_DATA_BYTES,
        allowUnflaggedExtensions: true,
      });
      verifyRpId(authData.rpIdHash, application.appId);
      if (authData.counter <= input.credential.counter) {
        throw rejection("counter", "assertion_counter_not_advanced");
      }

      const publicKey = decodeStoredPublicKey(input.credential.publicKey);
      if (!equalBytes(publicKeyIdentifier(publicKey), input.keyId)) {
        throw rejection("app-identity", "credential_key_id_mismatch");
      }
      const nonce = sha256(
        Buffer.concat([authData.raw, Buffer.from(input.clientDataHash)]),
      );
      if (
        !verifySignature(
          "sha256",
          nonce,
          { key: publicKey, dsaEncoding: "der" },
          envelope.signature,
        )
      ) {
        throw rejection("signature", "invalid_assertion_signature");
      }

      const extensions = await verifyDistributionPolicy(
        authData.extensions,
        application,
      );
      return assertionResult(authData.counter, extensions);
    },
  };
}

function parseAttestationEnvelope(input: Uint8Array): AttestationEnvelope {
  const decoded = decodeSingleCbor(input, { label: "attestation_object" });
  const object = exactObject(decoded.value, ["attStmt", "authData", "fmt"]);
  if (object.fmt !== "apple-appattest") {
    throw rejection("cbor", "invalid_attestation_format");
  }
  if (!(object.authData instanceof Uint8Array)) {
    throw rejection("cbor", "invalid_attestation_auth_data");
  }

  const statement = exactObject(object.attStmt, ["receipt", "x5c"]);
  if (
    !Array.isArray(statement.x5c) ||
    !statement.x5c.every(
      (certificate): certificate is Uint8Array =>
        certificate instanceof Uint8Array && certificate.byteLength > 0,
    )
  ) {
    throw rejection("cbor", "invalid_attestation_certificate_chain");
  }
  if (
    !(statement.receipt instanceof Uint8Array) ||
    statement.receipt.byteLength === 0 ||
    statement.receipt.byteLength > MAX_RECEIPT_BYTES
  ) {
    throw rejection("cbor", "invalid_attestation_receipt");
  }

  return {
    authData: Buffer.from(object.authData),
    certificates: statement.x5c.map((certificate) => Buffer.from(certificate)),
    receipt: Buffer.from(statement.receipt),
  };
}

function parseAssertionEnvelope(input: Uint8Array): AssertionEnvelope {
  const decoded = decodeSingleCbor(input, { label: "assertion_object" });
  const object = exactObject(decoded.value, ["authenticatorData", "signature"]);
  if (
    !(object.authenticatorData instanceof Uint8Array) ||
    !(object.signature instanceof Uint8Array) ||
    object.signature.byteLength < 8 ||
    object.signature.byteLength > 80
  ) {
    throw rejection("cbor", "invalid_assertion_object");
  }
  return {
    authenticatorData: Buffer.from(object.authenticatorData),
    signature: Buffer.from(object.signature),
  };
}

function exactObject(
  value: unknown,
  expectedKeys: readonly string[],
): Record<string, unknown> {
  let object: Record<string, unknown>;
  if (value instanceof Map) {
    object = Object.create(null) as Record<string, unknown>;
    for (const [key, entry] of value) {
      if (typeof key !== "string" || Object.hasOwn(object, key)) {
        throw rejection("cbor", "invalid_object_keys");
      }
      object[key] = entry;
    }
  } else if (isPlainObject(value)) {
    object = value;
  } else {
    throw rejection("cbor", "invalid_object_container");
  }

  const actualKeys = Object.keys(object).sort();
  const sortedExpected = [...expectedKeys].sort();
  if (
    actualKeys.length !== sortedExpected.length ||
    actualKeys.some((key, index) => key !== sortedExpected[index])
  ) {
    throw rejection("cbor", "unexpected_object_fields");
  }
  return object;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}

function validateApplications(
  input: readonly AppAttestApplication[],
): Map<string, AppAttestApplication> {
  if (input.length === 0) {
    throw new TypeError("App Attest requires at least one application.");
  }
  const applications = new Map<string, AppAttestApplication>();
  for (const application of input) {
    if (!application.appId || applications.has(application.appId)) {
      throw new TypeError(
        "App Attest application IDs must be non-empty and unique.",
      );
    }
    if (
      (application.environment !== "development" &&
        application.environment !== "production") ||
      (application.extensions.presence !== "if-present" &&
        application.extensions.presence !== "required") ||
      typeof application.extensions.validateBundleVersion !== "function"
    ) {
      throw new TypeError("App Attest application policy is invalid.");
    }
    if (
      application.extensions.allowedValidationCategories.length === 0 ||
      application.extensions.allowedValidationCategories.some(
        (category) =>
          !Number.isSafeInteger(category) ||
          category < 0 ||
          category > 0xffff_ffff,
      )
    ) {
      throw new TypeError(
        "Each App Attest application requires valid allowed validation categories.",
      );
    }
    applications.set(application.appId, application);
  }
  return applications;
}

function requireApplication(
  applications: Map<string, AppAttestApplication>,
  applicationId: string,
): AppAttestApplication {
  const application = applications.get(applicationId);
  if (!application) {
    throw rejection("app-identity", "unknown_application");
  }
  return application;
}

function verifyRpId(actual: Uint8Array, applicationId: string): void {
  if (!equalBytes(actual, sha256(Buffer.from(applicationId, "utf8")))) {
    throw rejection("app-identity", "rp_id_hash_mismatch");
  }
}

function verifyEnvironment(
  aaguid: Uint8Array,
  expected: DeviceAttestationEnvironment,
): void {
  const actual = equalBytes(aaguid, PRODUCTION_AAGUID)
    ? "production"
    : equalBytes(aaguid, DEVELOPMENT_AAGUID)
      ? "development"
      : undefined;
  if (!actual || actual !== expected) {
    throw rejection("environment", "app_attest_environment_mismatch");
  }
}

async function verifyDistributionPolicy(
  container: unknown,
  application: AppAttestApplication,
): Promise<AppAttestExtensions | undefined> {
  if (container === undefined) {
    if (application.extensions.presence === "required") {
      throw rejection("distribution-metadata", "extensions_required");
    }
    return undefined;
  }

  const extensions = parseAppAttestExtensions(container);
  if (
    !application.extensions.allowedValidationCategories.includes(
      extensions.validationCategory,
    )
  ) {
    throw rejection("distribution-metadata", "validation_category_disallowed");
  }
  if (
    !(await application.extensions.validateBundleVersion(
      extensions.bundleVersion,
    ))
  ) {
    throw rejection("distribution-metadata", "bundle_version_disallowed");
  }
  return extensions;
}

function registrationResult(
  application: AppAttestApplication,
  publicKeySpki: Uint8Array,
  receipt: Uint8Array,
  extensions: AppAttestExtensions | undefined,
): RegistrationVerificationResult {
  return {
    applicationId: application.appId,
    environment: application.environment,
    publicKey: Buffer.from(publicKeySpki).toString("base64"),
    counter: 0,
    extensionsPresent: extensions !== undefined,
    untrustedReceipt: Buffer.from(receipt),
    ...(extensions === undefined
      ? {}
      : {
          validationCategory: extensions.validationCategory,
          bundleVersion: extensions.bundleVersion,
        }),
  };
}

function assertionResult(
  counter: number,
  extensions: AppAttestExtensions | undefined,
): AssertionVerificationResult {
  return {
    counter,
    extensionsPresent: extensions !== undefined,
    ...(extensions === undefined
      ? {}
      : {
          validationCategory: extensions.validationCategory,
          bundleVersion: extensions.bundleVersion,
        }),
  };
}

function decodeStoredPublicKey(value: string | null | undefined) {
  if (!value) {
    throw rejection("credential-binding", "missing_credential_public_key");
  }
  const spki = decodeBase64Strict(value, {
    label: "stored_credential_public_key",
    maxBytes: 256,
  });
  try {
    const key = createPublicKey({ key: spki, format: "der", type: "spki" });
    if (
      key.asymmetricKeyType !== "ec" ||
      key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
    ) {
      throw new TypeError("Unexpected stored key algorithm");
    }
    return key;
  } catch {
    throw rejection("credential-binding", "invalid_credential_public_key");
  }
}

function publicKeyIdentifier(key: ReturnType<typeof createPublicKey>): Buffer {
  try {
    const jwk = key.export({ format: "jwk" });
    if (!jwk.x || !jwk.y) {
      throw new TypeError("Missing EC coordinates");
    }
    const x = Buffer.from(jwk.x, "base64url");
    const y = Buffer.from(jwk.y, "base64url");
    if (x.length !== 32 || y.length !== 32) {
      throw new TypeError("Invalid EC coordinates");
    }
    return sha256(Buffer.concat([Buffer.from([0x04]), x, y]));
  } catch {
    throw rejection("credential-binding", "invalid_credential_public_key");
  }
}

async function reportReceipt(
  receiptOptions: AppAttestOptions["receipt"],
  receipt: Uint8Array,
  application: AppAttestApplication,
): Promise<void> {
  if (!receiptOptions) {
    return;
  }
  try {
    await receiptOptions.onReceipt(
      Buffer.from(receipt) as unknown as UntrustedAppAttestReceipt,
      {
        applicationId: application.appId,
        environment: application.environment,
      },
    );
  } catch {
    // Receipt processing is separate from the synchronous attestation decision.
  }
}

function positiveBound(value: number | undefined, fallback: number): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) {
    throw new TypeError("maxEvidenceBytes must be a positive safe integer.");
  }
  return resolved;
}
