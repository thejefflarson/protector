// Build the Preact dashboard bundle from source into dist/dashboard.js (ADR-0025).
//
// The engine `include_str!`s dist/dashboard.js, so this must run BEFORE `cargo build`
// (a node stage in the Docker build; a node step in CI). The bundle is gitignored —
// source under src/ is the single truth, mirroring how compiled Rust artifacts are
// never committed.
//
// Multi-arch: we use esbuild-WASM (arch-neutral), NOT the native esbuild binary. The
// buildkit build is multi-arch (arm64 + amd64) and esbuild ships a per-platform native
// binary resolved via npm optional-deps; esbuild-wasm sidesteps that resolution with a
// single arch-neutral WASM artifact — a tiny bundle (Preact ~4 KB) builds fast enough
// that the WASM speed cost is irrelevant. One artifact, every arch, no optional-dep
// juggling in the Docker node stage.

import { build } from "esbuild-wasm";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));

await build({
  entryPoints: [join(here, "src", "main.jsx")],
  outfile: join(here, "dist", "dashboard.js"),
  bundle: true,
  minify: true,
  treeShaking: true,
  format: "iife",
  // Preact's automatic JSX runtime: esbuild auto-imports `jsx`/`Fragment` from
  // `preact/jsx-runtime`, so source files need no manual `import { h, Fragment }` pragma
  // (which the language server flagged as "unused" without a jsx-factory config). No React.
  jsx: "automatic",
  jsxImportSource: "preact",
  // A modern in-cluster browser reached through the cluster's own ingress (ADR-0025 (d));
  // no legacy transpile target needed.
  target: "es2020",
  legalComments: "none",
});
