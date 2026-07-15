import type { createDeviceAttestation } from "./plugin.js";

export function deviceAttestationClient() {
  return {
    id: "device-attestation",
    version: "0.1.0-alpha.0",
    $InferServerPlugin: {} as ReturnType<
      typeof createDeviceAttestation
    >["serverPlugin"],
  };
}
