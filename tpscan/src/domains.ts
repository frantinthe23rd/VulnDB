// Registrable domain (eTLD+1) handling. Never split hostnames by hand:
// example.co.uk and user.github.io break naive "last two labels" rules.
import { getDomain, parse } from 'tldts';
import type { Party } from './types.js';

export function hostOf(url: string): string {
  try {
    return new URL(url).hostname.replace(/^\[|\]$/g, '').toLowerCase();
  } catch {
    return '';
  }
}

/** eTLD+1 using the Public Suffix List, private section included (github.io, herokuapp.com). */
export function registrableDomain(hostOrUrl: string): string {
  const host = hostOrUrl.includes('://') ? hostOf(hostOrUrl) : hostOrUrl.toLowerCase();
  if (!host) return '';
  const info = parse(host, { allowPrivateDomains: true });
  if (info.isIp) return host;
  return getDomain(host, { allowPrivateDomains: true }) ?? host;
}

export class PartyClassifier {
  private readonly owned: Set<string>;

  constructor(readonly pageDomain: string, ownedDomains: string[] = []) {
    this.owned = new Set(ownedDomains.map((d) => registrableDomain(d.trim())).filter(Boolean));
  }

  classify(host: string): Party {
    const domain = registrableDomain(host);
    if (domain === this.pageDomain) return 'first';
    if (this.owned.has(domain)) return 'owned';
    return 'third';
  }
}

/** True when the URL has no version or content hash, so the vendor can change what it serves at will. */
export function isEvergreen(url: string): boolean {
  let u: URL;
  try {
    u = new URL(url);
  } catch {
    return true;
  }
  const path = u.pathname + u.search;
  if (/(^|[^\d])v?\d+\.\d+(\.\d+)?/.test(path)) return false;          // 1.2 / v3.4.5
  if (/[.\-_/@][0-9a-f]{8,}([.\-_/]|$)/i.test(u.pathname)) return false; // content hash
  if (/[?&](v|ver|version|rev|hash)=[^&]+/i.test(u.search)) return false;
  return true;
}
