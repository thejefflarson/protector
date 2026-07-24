// ESLint flat config (eslint 9) for the Preact dashboard client (JEF-499). The point of this config
// is an ACCESSIBILITY gate: eslint-plugin-jsx-a11y's recommended rules, mapped onto Preact JSX, so a
// PR that introduces an a11y regression fails `npm run lint` (wired into CI). jsx-a11y works on JSX
// generically — it inspects JSXElement/JSXAttribute nodes, so it lints our `.jsx` views without any
// React runtime; the stock espree parser handles JSX once `ecmaFeatures.jsx` is on.
//
// We layer `@eslint/js` recommended on top (dead code / real bugs), scoped with the right globals per
// area (browser for the client, vitest for tests, node for the build/config scripts) so `no-undef`
// never false-fires. No eslint-plugin-react: jsx-a11y needs no React plugin, and the engine is Preact.

import js from "@eslint/js";
import jsxA11y from "eslint-plugin-jsx-a11y";
import react from "eslint-plugin-react";
import globals from "globals";

// The vitest test globals (config sets `globals: true`, so tests call describe/it/expect/vi without
// importing them). Declared readonly so eslint's no-undef recognises them in the test tree.
const vitestGlobals = {
  describe: "readonly",
  it: "readonly",
  test: "readonly",
  expect: "readonly",
  vi: "readonly",
  beforeEach: "readonly",
  afterEach: "readonly",
  beforeAll: "readonly",
  afterAll: "readonly",
};

export default [
  { ignores: ["dist/**", "node_modules/**"] },

  // Base JS correctness everywhere we lint.
  js.configs.recommended,

  // The client source (browser runtime) + the a11y gate. jsx-a11y's recommended flat config brings
  // the plugin registration and the 34 recommended rules. We ALSO register eslint-plugin-react for a
  // single rule — `react/jsx-uses-vars` — so `no-unused-vars` sees a component referenced only in
  // JSX (`<CoverageRow/>`) as used; without it core no-unused-vars false-fires on every view helper.
  // We deliberately do NOT pull the full react ruleset (the engine is Preact, automatic JSX runtime).
  {
    ...jsxA11y.flatConfigs.recommended,
    files: ["src/**/*.{js,jsx}"],
    plugins: { ...jsxA11y.flatConfigs.recommended.plugins, react },
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.browser },
    },
    rules: {
      ...jsxA11y.flatConfigs.recommended.rules,
      "react/jsx-uses-vars": "error",
    },
  },

  // Tests: same JSX + a11y gate (the axe route-smoke and view tests are .jsx), plus the vitest and
  // browser (jsdom) globals.
  {
    ...jsxA11y.flatConfigs.recommended,
    files: ["test/**/*.{js,jsx}"],
    plugins: { ...jsxA11y.flatConfigs.recommended.plugins, react },
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.browser, ...vitestGlobals },
    },
    rules: {
      ...jsxA11y.flatConfigs.recommended.rules,
      "react/jsx-uses-vars": "error",
    },
  },

  // The build + vitest config scripts run under node.
  {
    files: ["build.mjs", "vitest.config.js", "eslint.config.js"],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: "module",
      globals: { ...globals.node },
    },
  },
];
