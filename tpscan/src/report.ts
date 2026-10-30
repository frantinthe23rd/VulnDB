// Report output. JSON is the source of truth; HTML and CSV are rendered from it.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import type { ErrorObject, ValidateFunction } from 'ajv';
import { assetPath } from './paths.js';
import type { Item, Report } from './types.js';

const require = createRequire(import.meta.url);

let validator: ValidateFunction | null = null;

type AjvCtor = new (opts: object) => { compile(schema: object): ValidateFunction };

/** Validates against assets/report.schema.json; returns error strings (empty when valid). */
export function validateReport(report: unknown): string[] {
  if (!validator) {
    // ajv ships its draft 2020-12 build as CommonJS.
    const Ajv2020 = (require('ajv/dist/2020.js') as { default: AjvCtor }).default;
    validator = new Ajv2020({ allErrors: true, strict: false }).compile(JSON.parse(readFileSync(assetPath('report.schema.json'), 'utf8')));
  }
  const validate = validator;
  if (validate(report)) return [];
  return (validate.errors ?? []).map((e: ErrorObject) => `${e.instancePath || '/'} ${e.message ?? ''}`.trim());
}

export function toJson(report: Report): string {
  return JSON.stringify(report, null, 2) + '\n';
}

const CSV_COLUMNS: (keyof Item | 'chainText')[] = [
  'id', 'rating', 'kind', 'party', 'vendor', 'category', 'domain', 'host', 'url', 'frame', 'frameUrl',
  'loadedBy', 'chainText', 'initiatorType', 'sri', 'crossorigin', 'sandbox', 'allow', 'evergreen', 'dynamic',
  'injected', 'consentGated', 'cloaked', 'cname', 'passes', 'status', 'contentType', 'size', 'method', 'reasons', 'modifiers',
];

function csvCell(value: unknown): string {
  let s = value === null || value === undefined ? '' : Array.isArray(value) ? value.join('; ') : String(value);
  // Spreadsheet formula injection: hostile URLs could start with = + - @.
  if (/^[=+\-@\t\r]/.test(s)) s = `'${s}`;
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/** One row per item, item fields flattened, for pasting into a risk register. */
export function toCsv(report: Report): string {
  const header = ['page_url', 'scanned_at', ...CSV_COLUMNS.map((c) => (c === 'chainText' ? 'chain' : c))];
  const rows = report.items.map((it) => [
    report.scan.finalUrl,
    report.scan.scannedAt,
    ...CSV_COLUMNS.map((c) => (c === 'chainText' ? it.chain.join(' > ') : it[c])),
  ]);
  return [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n') + '\r\n';
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);
}

/** JSON that is safe inside a <script> element: no "</script", "<!--" or U+2028/2029 can end it early. */
export function jsonForScript(value: unknown): string {
  return JSON.stringify(value).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

/** A single self-contained HTML file: no external assets. */
export function toHtml(report: Report): string {
  const renderer = readFileSync(assetPath('renderer.js'), 'utf8');
  const title = `Third-party exposure: ${report.scan.finalUrl}`;
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)}</title>
<style>
  :root { --bg:#0f172a; --surface:#1e293b; --border:#334155; --accent:#38bdf8; --text:#e2e8f0; --muted:#94a3b8;
          --crit:#ef4444; --high:#f97316; --med:#eab308; --low:#22c55e; }
  body { margin:0; background:var(--bg); color:var(--text); }
  main { max-width:1100px; margin:0 auto; padding:24px 16px 48px; }
  .brand { font:600 .85rem "Segoe UI",system-ui,sans-serif; color:var(--accent); letter-spacing:.5px; margin-bottom:14px; }
</style>
</head>
<body>
<main>
<div class="brand">tpscan · third-party exposure report</div>
<div id="report"><noscript>This report needs JavaScript to render. The data is in the JSON report alongside it.</noscript></div>
</main>
<script id="report-data" type="application/json">${jsonForScript(report)}</script>
<script>${renderer.replace(/<\/script/gi, '<\\/script')}</script>
<script>TPScanReport.render(document.getElementById('report'), JSON.parse(document.getElementById('report-data').textContent));</script>
</body>
</html>
`;
}

/** Directory name for a URL: host plus a readable, filesystem-safe path. */
export function slugFor(url: string): string {
  const u = new URL(url);
  const path = (u.pathname + u.search).replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 60);
  return (u.hostname + (u.port ? `-${u.port}` : '') + (path ? `_${path}` : '')).toLowerCase();
}
