// Vitest config for the dashboard v4 client (ADR-0025 / JEF-397). Offline, jsdom-backed, and
// preact-aliased so `@testing-library/preact` and the source's automatic JSX runtime resolve
// without pulling React. `vitest run` is the offline test entry; nothing here touches the network.

import { defineConfig } from "vitest/config";

export default defineConfig({
  esbuild: {
    // The source uses the automatic Preact JSX runtime (same as the production esbuild build), so
    // no manual `h`/`Fragment` pragma is needed in test or source files.
    jsx: "automatic",
    jsxImportSource: "preact",
  },
  test: {
    environment: "jsdom",
    globals: true,
    include: ["test/**/*.test.{js,jsx}"],
  },
  resolve: {
    // Map React-flavoured testing-library imports onto Preact's compat shim so the library renders
    // with the same reconciler the production bundle ships.
    alias: {
      react: "preact/compat",
      "react-dom": "preact/compat",
    },
  },
});
