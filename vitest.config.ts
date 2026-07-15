import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: [
        "src/**/*.test.ts",
        "src/app-attest/root-certificate.ts",
        "src/index.ts",
      ],
      reporter: ["text", "json-summary"],
      reportsDirectory: "coverage",
      thresholds: {
        statements: 85,
        branches: 75,
        functions: 90,
        lines: 85,
      },
    },
  },
});
