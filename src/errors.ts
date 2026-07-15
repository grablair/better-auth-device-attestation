import { defineErrorCodes } from "@better-auth/core/utils/error-codes";

const DEVICE_ATTESTATION_ERROR_MESSAGES = {
  DEVICE_ATTESTATION_INVALID_REQUEST: "The attestation request is invalid.",
  DEVICE_ATTESTATION_CHALLENGE_EXPIRED:
    "The attestation challenge is absent, expired, or already used.",
  DEVICE_ATTESTATION_CREDENTIAL_REQUIRED:
    "An active attestation credential is required.",
  DEVICE_ATTESTATION_REJECTED: "The attestation evidence was rejected.",
  DEVICE_ATTESTATION_GRANT_REQUIRED:
    "A valid device-attestation grant is required.",
  DEVICE_ATTESTATION_RETRY: "The attestation operation must be retried.",
} as const;

export const DEVICE_ATTESTATION_ERROR_CODES = defineErrorCodes(
  DEVICE_ATTESTATION_ERROR_MESSAGES,
);

export type DeviceAttestationPublicErrorCode =
  keyof typeof DEVICE_ATTESTATION_ERROR_MESSAGES;

export function deviceAttestationErrorMessage(
  code: DeviceAttestationPublicErrorCode,
): string {
  return DEVICE_ATTESTATION_ERROR_MESSAGES[code];
}

export type DeviceAttestationFailureStage =
  | "request"
  | "challenge"
  | "cbor"
  | "authenticator-data"
  | "certificate-chain"
  | "nonce"
  | "app-identity"
  | "environment"
  | "distribution-metadata"
  | "signature"
  | "counter"
  | "credential-binding"
  | "grant-binding"
  | "storage"
  | "unexpected";

export interface DeviceAttestationDiagnosticMeasurements {
  evidenceBytes?: number;
  authenticatorDataBytes?: number;
  flags?: number;
  extensionBytes?: number;
}

export interface DeviceAttestationDiagnosticEvent {
  provider: string;
  operation: "challenge" | "verify" | "register" | "assert" | "grant";
  stage: DeviceAttestationFailureStage;
  reason: string;
  retryable: boolean;
  measurements?: DeviceAttestationDiagnosticMeasurements;
}

export class DeviceAttestationError extends Error {
  readonly code: DeviceAttestationPublicErrorCode;
  readonly stage: DeviceAttestationFailureStage;
  readonly reason: string;
  readonly retryable: boolean;
  readonly measurements: DeviceAttestationDiagnosticMeasurements | undefined;

  constructor(input: {
    code: DeviceAttestationPublicErrorCode;
    stage: DeviceAttestationFailureStage;
    reason: string;
    retryable?: boolean;
    measurements?: DeviceAttestationDiagnosticMeasurements;
  }) {
    super(deviceAttestationErrorMessage(input.code));
    this.name = "DeviceAttestationError";
    this.code = input.code;
    this.stage = input.stage;
    this.reason = input.reason;
    this.retryable = input.retryable ?? false;
    this.measurements = input.measurements;
  }
}

export function rejection(
  stage: DeviceAttestationFailureStage,
  reason: string,
  measurements?: DeviceAttestationDiagnosticMeasurements,
): DeviceAttestationError {
  return new DeviceAttestationError({
    code: "DEVICE_ATTESTATION_REJECTED",
    stage,
    reason,
    ...(measurements === undefined ? {} : { measurements }),
  });
}
