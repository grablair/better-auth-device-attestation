import { rejection } from "../errors.js";

const STANDARD_BASE64 =
  /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const BASE64URL = /^[A-Za-z0-9_-]*$/u;

export function decodeBase64Strict(
  value: string,
  options: {
    maxBytes: number;
    exactBytes?: number;
    label: string;
  },
): Buffer {
  if (!STANDARD_BASE64.test(value)) {
    throw rejection("request", `invalid_${options.label}_base64`);
  }

  const decoded = Buffer.from(value, "base64");
  assertDecodedLength(decoded, options);

  if (decoded.toString("base64") !== value) {
    throw rejection("request", `non_canonical_${options.label}_base64`);
  }

  return decoded;
}

export function decodeBase64UrlStrict(
  value: string,
  options: {
    maxBytes: number;
    exactBytes?: number;
    label: string;
  },
): Buffer {
  if (!BASE64URL.test(value) || value.length % 4 === 1) {
    throw rejection("request", `invalid_${options.label}_base64url`);
  }

  const decoded = Buffer.from(value, "base64url");
  assertDecodedLength(decoded, options);

  if (decoded.toString("base64url") !== value) {
    throw rejection("request", `non_canonical_${options.label}_base64url`);
  }

  return decoded;
}

function assertDecodedLength(
  decoded: Buffer,
  options: {
    maxBytes: number;
    exactBytes?: number;
    label: string;
  },
): void {
  if (decoded.length > options.maxBytes) {
    throw rejection("request", `${options.label}_too_large`, {
      evidenceBytes: decoded.length,
    });
  }

  if (
    options.exactBytes !== undefined &&
    decoded.length !== options.exactBytes
  ) {
    throw rejection("request", `invalid_${options.label}_length`);
  }
}
