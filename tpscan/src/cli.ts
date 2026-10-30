#!/usr/bin/env node
// tpscan: load a page in Chromium and report every third-party service it loads
// or talks to, rated by exposure. Maps attack surface; does not detect compromise.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { slugFor, toCsv, toHtml, toJson, validateReport } from './report.js';
import { RuleSet } from './rules.js';
import { Scanner } from './scan.js';
import { TOOL_VERSION } from './paths.js';
import type { ConsentMode, Report } from './types.js';
import { VendorMap } from './vendors.js';

const USAGE = `tpscan ${TOOL_VERSION} - third-party exposure scanner

Usage:
  tpscan <url> [options]
  tpscan --urls <file> [options]

Options:
  --urls <file>            File with one URL per line (# comments allowed)
  --out <dir>              Output directory (default ./reports/<host>; with --urls,
                           ./reports, one subdirectory per URL)
  --format <list>          Any of json,html,csv (default json,html)
  --consent <mode>         none | accept | reject | both (default both)
  --interact / --no-interact
                           Scroll, focus a form field, wait for lazy loaders (default on)
  --settle <ms>            Extra wait after network idle (default 10000)
  --first-party <list>     Comma-separated domains the site owns (CDN, sister brands)
  --dns-check              Resolve CNAMEs of first-party hosts to catch cloaked vendors
  --timeout <s>            Hard cap per pass (default 60)
  --headful                Show the browser, for debugging
  --block-private          Refuse private, loopback, link-local and metadata addresses,
                           on every hop (always use when URLs come from other people)
  --vendors <file>         Extra vendor map (JSON, same shape as assets/vendors.json); repeatable
  --tracker-radar <dir>    Also read a local DuckDuckGo Tracker Radar checkout's domains/
                           directory (check its licence for your use first)
  --rules <file>           Rating rules YAML (default assets/rules.yaml)
  --version, --help

Exit codes: 0 scanned, 1 a scan failed, 2 bad arguments.`;

function fail(msg: string): never {
  process.stderr.write(`tpscan: ${msg}\n\n${USAGE}\n`);
  process.exit(2);
}

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      urls: { type: 'string' },
      out: { type: 'string' },
      format: { type: 'string', default: 'json,html' },
      consent: { type: 'string', default: 'both' },
      interact: { type: 'boolean', default: true },
      'no-interact': { type: 'boolean', default: false },
      settle: { type: 'string', default: '10000' },
      'first-party': { type: 'string', default: '' },
      'dns-check': { type: 'boolean', default: false },
      timeout: { type: 'string', default: '60' },
      headful: { type: 'boolean', default: false },
      'block-private': { type: 'boolean', default: false },
      vendors: { type: 'string', multiple: true, default: [] },
      'tracker-radar': { type: 'string' },
      rules: { type: 'string' },
      version: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (values.help) {
    process.stdout.write(USAGE + '\n');
    return 0;
  }
  if (values.version) {
    process.stdout.write(TOOL_VERSION + '\n');
    return 0;
  }

  let urls = positionals;
  if (values.urls) {
    urls = [...urls, ...readFileSync(values.urls, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'))];
  }
  if (urls.length === 0) fail('give a URL or --urls <file>');
  for (const u of urls) {
    try {
      const p = new URL(u);
      if (p.protocol !== 'http:' && p.protocol !== 'https:') throw new Error();
    } catch {
      fail(`not an http(s) URL: ${u}`);
    }
  }

  const formats = values.format.split(',').map((f) => f.trim().toLowerCase()).filter(Boolean);
  for (const f of formats) if (!['json', 'html', 'csv'].includes(f)) fail(`unknown format "${f}"`);
  const consent = values.consent as ConsentMode;
  if (!['none', 'accept', 'reject', 'both'].includes(consent)) fail(`--consent must be none, accept, reject or both`);
  const settleMs = Number(values.settle);
  const timeoutS = Number(values.timeout);
  if (!Number.isFinite(settleMs) || settleMs < 0) fail('--settle must be a number of milliseconds');
  if (!Number.isFinite(timeoutS) || timeoutS < 10) fail('--timeout must be at least 10 seconds');

  const scanner = new Scanner({
    consent,
    interact: values.interact && !values['no-interact'],
    settleMs,
    timeoutMs: timeoutS * 1000,
    firstParty: values['first-party'].split(',').map((d) => d.trim()).filter(Boolean),
    dnsCheck: values['dns-check'],
    headful: values.headful,
    blockPrivate: values['block-private'],
    vendors: VendorMap.create({ overrides: values.vendors, trackerRadar: values['tracker-radar'] }),
    rules: RuleSet.load(values.rules),
    chromiumArgs: process.env.TPSCAN_CHROMIUM_ARGS ? (JSON.parse(process.env.TPSCAN_CHROMIUM_ARGS) as string[]) : undefined,
  });

  const batch = urls.length > 1 || !!values.urls;
  let failures = 0;
  try {
    for (const url of urls) {
      const started = Date.now();
      process.stderr.write(`scanning ${url} ...\n`);
      let report: Report;
      try {
        report = await scanner.scan(url);
      } catch (err) {
        failures++;
        process.stderr.write(`  failed: ${(err as Error).message}\n`);
        continue;
      }
      const problems = validateReport(report);
      if (problems.length) {
        failures++;
        process.stderr.write(`  report does not match the schema:\n    ${problems.join('\n    ')}\n`);
      }
      const dir = values.out
        ? batch ? join(values.out, slugFor(url)) : values.out
        : join('reports', batch ? slugFor(url) : new URL(url).hostname);
      mkdirSync(dir, { recursive: true });
      if (formats.includes('json')) writeFileSync(join(dir, 'report.json'), toJson(report));
      if (formats.includes('html')) writeFileSync(join(dir, 'report.html'), toHtml(report));
      if (formats.includes('csv')) writeFileSync(join(dir, 'report.csv'), toCsv(report));
      if (report.errors.length && report.items.length === 0) failures++;
      const s = report.summary;
      process.stderr.write(
        `  ${report.page.rating.toUpperCase()}: ${s.vendors} vendors, ${s.thirdPartyDomains} third-party domains, ` +
        `SRI ${s.sriCoverage.with}/${s.sriCoverage.of}, ${((Date.now() - started) / 1000).toFixed(0)}s -> ${dir}\n`,
      );
      for (const e of report.errors) process.stderr.write(`  warning: ${e}\n`);
    }
  } finally {
    await scanner.close();
  }
  return failures ? 1 : 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`tpscan: ${(err as Error).stack ?? err}\n`);
    process.exit(1);
  },
);
