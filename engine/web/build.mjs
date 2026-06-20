// Build the self-contained dashboard graph bundle with esbuild-wasm (pure WASM —
// no native binary to install, so it runs anywhere node does). Output is checked
// in at web/dist/ and embedded in the protector binary; rebuild with `npm run build`.
import { build } from 'esbuild-wasm';
await build({
  entryPoints: ['entry.mjs'],
  bundle: true,
  format: 'esm',
  minify: true,
  legalComments: 'none',
  outfile: 'dist/beautiful-mermaid.js',
});
console.log('built web/dist/beautiful-mermaid.js');
