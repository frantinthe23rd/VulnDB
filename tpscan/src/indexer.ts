#!/usr/bin/env node
// tpscan-index <dir>: writes <dir>/index.json listing every <dir>/<slug>/report.json,
// which the VulnDB site's exposure page reads.
import { existsSync, readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { RATING_ORDER, type Report } from './types.js';

export interface IndexEntry {
  slug: string;
  url: string;
  finalUrl: string;
  scannedAt: string;
  rating: Report['page']['rating'];
  vendors: number;
  thirdPartyDomains: number;
  topFrameThirdPartyScripts: number;
  sriCoverage: Report['summary']['sriCoverage'];
  byRating: Report['summary']['byRating'];
  sensitive: boolean;
  formats: string[];
}

export function buildIndex(dir: string): { generatedAt: string; scans: IndexEntry[] } {
  const scans: IndexEntry[] = [];
  for (const slug of readdirSync(dir).sort()) {
    if (!/^[a-z0-9._-]+$/.test(slug)) continue;
    const file = join(dir, slug, 'report.json');
    if (!existsSync(file)) continue;
    const r = JSON.parse(readFileSync(file, 'utf8')) as Report;
    scans.push({
      slug,
      url: r.scan.url,
      finalUrl: r.scan.finalUrl,
      scannedAt: r.scan.scannedAt,
      rating: r.page.rating,
      vendors: r.summary.vendors,
      thirdPartyDomains: r.summary.thirdPartyDomains,
      topFrameThirdPartyScripts: r.summary.topFrameThirdPartyScripts,
      sriCoverage: r.summary.sriCoverage,
      byRating: r.summary.byRating,
      sensitive: r.page.sensitiveSignals.length > 0,
      formats: ['json', 'html', 'csv'].filter((f) => existsSync(join(dir, slug, `report.${f}`))),
    });
  }
  scans.sort((a, b) => RATING_ORDER.indexOf(a.rating) - RATING_ORDER.indexOf(b.rating) || (a.url < b.url ? -1 : a.url > b.url ? 1 : 0));
  return { generatedAt: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'), scans };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const dir = process.argv[2];
  if (!dir) {
    process.stderr.write('usage: tpscan-index <reports-dir>\n');
    process.exit(2);
  }
  const index = buildIndex(dir);
  writeFileSync(join(dir, 'index.json'), JSON.stringify(index, null, 2) + '\n');
  process.stderr.write(`indexed ${index.scans.length} scan(s) -> ${join(dir, 'index.json')}\n`);
}
