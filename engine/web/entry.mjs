// The one function the dashboard needs. esbuild bundles this + elkjs + entities
// into web/dist/beautiful-mermaid.js, which protector serves same-origin (no CDN).
export { renderMermaidSVG } from 'beautiful-mermaid';
