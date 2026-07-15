import { execFileSync } from "node:child_process";
import {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execPath } from "node:process";
import { fileURLToPath } from "node:url";

const repository = dirname(dirname(fileURLToPath(import.meta.url)));
const temporaryDirectory = mkdtempSync(
  join(tmpdir(), "better-auth-device-attestation-"),
);

try {
  const packed = JSON.parse(
    execFileSync(
      "npm",
      ["pack", "--json", "--pack-destination", temporaryDirectory],
      { cwd: repository, encoding: "utf8" },
    ),
  );
  const filename = packed[0]?.filename;
  if (typeof filename !== "string") {
    throw new TypeError("npm pack did not return a package filename.");
  }

  const consumer = join(temporaryDirectory, "consumer");
  mkdirSync(consumer);
  writeFileSync(
    join(consumer, "package.json"),
    JSON.stringify({ name: "package-smoke", private: true, type: "module" }),
  );
  execFileSync(
    "npm",
    [
      "install",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      join(temporaryDirectory, filename),
    ],
    { cwd: consumer, stdio: "pipe" },
  );
  execFileSync(
    execPath,
    [
      "--input-type=module",
      "--eval",
      [
        'const server = await import("@grablair/better-auth-device-attestation");',
        'const client = await import("@grablair/better-auth-device-attestation/client");',
        'if (typeof server.appAttest !== "function") throw new TypeError("Missing appAttest export");',
        'if (typeof server.createDeviceAttestation !== "function") throw new TypeError("Missing createDeviceAttestation export");',
        'if (typeof client.deviceAttestationClient !== "function") throw new TypeError("Missing client export");',
      ].join("\n"),
    ],
    { cwd: consumer, stdio: "pipe" },
  );

  const installedPackage = JSON.parse(
    readFileSync(
      join(
        consumer,
        "node_modules",
        "@grablair",
        "better-auth-device-attestation",
        "package.json",
      ),
      "utf8",
    ),
  );
  if (installedPackage.name !== "@grablair/better-auth-device-attestation") {
    throw new TypeError("Installed package metadata is invalid.");
  }
} finally {
  rmSync(temporaryDirectory, { recursive: true, force: true });
}
