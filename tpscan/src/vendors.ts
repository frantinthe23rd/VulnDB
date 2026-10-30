// Domain -> vendor -> category lookup. Sources, highest precedence first:
// --vendors override files, the built-in assets/vendors.json, and (optionally)
// a local DuckDuckGo Tracker Radar checkout passed with --tracker-radar.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { registrableDomain } from './domains.js';
import { assetPath } from './paths.js';
import type { Category } from './types.js';

export interface VendorInfo {
  vendor: string;
  category: Category;
  known: boolean;
}

const CATEGORIES = new Set<Category>([
  'tag-manager', 'analytics', 'rum-performance', 'session-replay', 'advertising', 'ab-testing',
  'chat-support', 'payments', 'auth-sso', 'consent', 'cdn-library', 'fonts', 'social', 'unknown',
]);

// Tracker Radar category names -> ours, most specific first.
const RADAR_CATEGORIES: [string, Category][] = [
  ['Tag Manager', 'tag-manager'],
  ['Session Replay', 'session-replay'],
  ['Consent Management Platform', 'consent'],
  ['Online Payment', 'payments'],
  ['SSO', 'auth-sso'],
  ['Federated Login', 'auth-sso'],
  ['Support Chat Widget', 'chat-support'],
  ['Embedded Content', 'social'],
  ['Social - Comment', 'social'],
  ['Social - Share', 'social'],
  ['Social Network', 'social'],
  ['Analytics', 'analytics'],
  ['Audience Measurement', 'analytics'],
  ['Third-Party Analytics Marketing', 'analytics'],
  ['Advertising', 'advertising'],
  ['Ad Motivated Tracking', 'advertising'],
  ['Action Pixels', 'advertising'],
  ['Ad Fraud', 'advertising'],
  ['CDN', 'cdn-library'],
  ['Fonts', 'fonts'],
];

type Entry = { vendor: string; category: Category };

export class VendorMap {
  private readonly entries = new Map<string, Entry>();

  /** Adds entries; existing keys are kept, so load sources in precedence order. */
  private add(domain: string, entry: Entry): void {
    const key = domain.toLowerCase().replace(/^\.+|\.+$/g, '');
    if (key && !this.entries.has(key)) this.entries.set(key, entry);
  }

  loadFile(path: string): void {
    const data = JSON.parse(readFileSync(path, 'utf8')) as { domains?: Record<string, Entry> };
    for (const [domain, entry] of Object.entries(data.domains ?? {})) {
      if (!entry?.vendor) throw new Error(`${path}: entry for ${domain} has no vendor`);
      const category = CATEGORIES.has(entry.category) ? entry.category : 'unknown';
      this.add(domain, { vendor: entry.vendor, category });
    }
  }

  /** Reads Tracker Radar domain files (domains/<region>/*.json or domains/*.json). */
  loadTrackerRadar(dir: string): number {
    let count = 0;
    const walk = (d: string) => {
      for (const name of readdirSync(d).sort()) {
        const p = join(d, name);
        if (statSync(p).isDirectory()) walk(p);
        else if (name.endsWith('.json')) {
          try {
            const rec = JSON.parse(readFileSync(p, 'utf8')) as {
              domain?: string; owner?: { name?: string; displayName?: string }; categories?: string[];
            };
            if (!rec.domain) continue;
            const cats = rec.categories ?? [];
            const category = RADAR_CATEGORIES.find(([name]) => cats.some((c) => c.startsWith(name)))?.[1] ?? 'unknown';
            const vendor = rec.owner?.displayName || rec.owner?.name || rec.domain;
            this.add(rec.domain, { vendor, category });
            count++;
          } catch {
            // Skip unreadable files rather than failing the scan.
          }
        }
      }
    };
    walk(dir);
    return count;
  }

  /** Full hostname first, then each parent domain; unmapped hosts are "unknown", never dropped. */
  lookup(host: string): VendorInfo {
    const labels = host.toLowerCase().split('.');
    for (let i = 0; i < labels.length - 1; i++) {
      const hit = this.entries.get(labels.slice(i).join('.'));
      if (hit) return { ...hit, known: true };
    }
    return { vendor: registrableDomain(host) || host, category: 'unknown', known: false };
  }

  static create(opts: { overrides?: string[]; trackerRadar?: string | null; builtin?: boolean }): VendorMap {
    const map = new VendorMap();
    for (const f of opts.overrides ?? []) map.loadFile(f);
    if (opts.builtin !== false) map.loadFile(assetPath('vendors.json'));
    if (opts.trackerRadar) map.loadTrackerRadar(opts.trackerRadar);
    return map;
  }
}
