import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["src/adapter.integration.test.ts"],
    env: {
      TEST_POSTGRES: "true",
    },
  },
});
