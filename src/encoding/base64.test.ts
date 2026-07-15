import { describe, expect, it } from "vitest";

import { DeviceAttestationError } from "../errors.js";
import { decodeBase64Strict, decodeBase64UrlStrict } from "./base64.js";

describe("strict base64 decoding", () => {
  it("accepts canonical standard base64", () => {
    expect(
      decodeBase64Strict("AQIDBA==", {
        label: "evidence",
        maxBytes: 4,
        exactBytes: 4,
      }),
    ).toEqual(Buffer.from([1, 2, 3, 4]));
  });

  it.each(["AQIDBA", "AQIDBA=", "AQIDBA===", "AQID BA==", "***="])(
    "rejects non-canonical standard base64 %s",
    (value) => {
      expect(() =>
        decodeBase64Strict(value, {
          label: "evidence",
          maxBytes: 100,
        }),
      ).toThrow(DeviceAttestationError);
    },
  );

  it("accepts unpadded canonical base64url", () => {
    expect(
      decodeBase64UrlStrict("AQIDBA", {
        label: "token",
        maxBytes: 4,
        exactBytes: 4,
      }),
    ).toEqual(Buffer.from([1, 2, 3, 4]));
  });

  it.each(["AQIDBA==", "AQIDBA+", "AQID BA", "a"])(
    "rejects non-canonical base64url %s",
    (value) => {
      expect(() =>
        decodeBase64UrlStrict(value, {
          label: "token",
          maxBytes: 100,
        }),
      ).toThrow(DeviceAttestationError);
    },
  );
});
