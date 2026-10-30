// Merges every pass's raw data by URL, then classifies, rates and orders it.
// Ordering is deterministic (rating, vendor, URL) so two scans can be diffed.
import { summariseCsp } from './csp.js';
import { hostOf, isEvergreen, PartyClassifier, registrableDomain } from './domains.js';
import { RuleSet, maxRating } from './rules.js';
import { TOOL_VERSION } from './paths.js';
import {
  RATING_ORDER, type Category, type ConsentMode, type DomIframe, type DomScript, type FrameKind, type Item, type Kind,
  type PassResult, type Phase, type Rating, type RawInitiator, type Report, type VendorSummary,
} from './types.js';
import type { VendorMap } from './vendors.js';

export interface BuildOptions {
  url: string;
  scannedAt: string;
  consentMode: ConsentMode;
  interact: boolean;
  settleMs: number;
  dnsCheck: boolean;
  blockPrivate: boolean;
  firstParty: string[];
  /** host -> CNAME chain, from --dns-check. */
  cnames?: Map<string, string[]>;
  blocked?: { url: string; reason: string }[];
}

export const LIMITATIONS = [
  'Server-side integrations are invisible: calls the site\'s backend makes to payment, CRM or analytics APIs never reach the browser.',
  'Bundled dependencies look first-party: a compromised npm package compiled into the site\'s own JavaScript is served from the site\'s domain.',
  'Only the pages and states visited are covered: logged-in areas, other routes and later steps of a flow are not scanned.',
  'Loading can vary by country, user agent, time and A/B bucket, and some vendors suppress scripts for headless browsers.',
  'This is a point-in-time snapshot: a vendor can change its code after the scan.',
  'Vendors cloaked behind first-party subdomains look first-party unless --dns-check is on.',
  'Ratings are heuristics about what a vendor could do if compromised, not a measured risk score, and say nothing about whether any vendor is compromised.',
];

const PHASE_ORDER: Phase[] = ['pre-consent', 'post-accept', 'post-reject'];
const KIND_BY_RESOURCE: Record<string, Kind> = {
  script: 'script', document: 'iframe', websocket: 'websocket', fetch: 'fetch', xhr: 'fetch', eventsource: 'fetch',
  ping: 'beacon', image: 'image', media: 'image', stylesheet: 'stylesheet', font: 'font',
};
const FRAME_PRIORITY: FrameKind[] = ['top', 'sub', 'service-worker', 'worker'];
const POWERFUL_PERMISSIONS = [
  'payment', 'camera', 'microphone', 'clipboard-read', 'clipboard-write', 'geolocation', 'usb', 'serial', 'hid',
  'bluetooth', 'display-capture', 'publickey-credentials-get', 'publickey-credentials-create', 'otp-credentials',
];

function normalise(url: string): string {
  const i = url.indexOf('#');
  return i === -1 ? url : url.slice(0, i);
}

function isNetworkUrl(url: string): boolean {
  return /^(https?|wss?):/i.test(url);
}

const cmp = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

interface Draft {
  url: string;
  kind: Kind;
  frame: FrameKind;
  frameUrl: string | null;
  workerUrl: string | null;
  method: string | null;
  status: number | null;
  contentType: string | null;
  size: number | null;
  phases: Set<Phase>;
  initiator: RawInitiator | null;
}

export function buildReport(passes: PassResult[], opts: BuildOptions, vendors: VendorMap, rules: RuleSet): Report {
  const finalUrl = passes.find((p) => p.finalUrl && p.finalUrl !== 'about:blank')?.finalUrl ?? opts.url;
  const pageDomain = registrableDomain(finalUrl);
  const parties = new PartyClassifier(pageDomain, opts.firstParty);

  // URLs that are "the page itself": the scanned URL, its redirect hops and the final URL.
  const pageUrls = new Set<string>([normalise(opts.url), normalise(finalUrl)]);
  for (const p of passes) for (const r of p.requests) if (r.isMainNavigation) pageUrls.add(normalise(r.url));

  // ---- merge observations by URL
  const drafts = new Map<string, Draft>();
  const initiatorOf = (url: string): RawInitiator | null => {
    for (const p of passes) if (p.initiators[url]) return p.initiators[url];
    return null;
  };
  const upsert = (url: string, init: () => Omit<Draft, 'phases'>, phase: Phase): Draft => {
    let d = drafts.get(url);
    if (!d) {
      d = { ...init(), phases: new Set() };
      drafts.set(url, d);
    }
    d.phases.add(phase);
    return d;
  };

  for (const p of passes) {
    for (const r of p.requests) {
      if (r.isMainNavigation || !isNetworkUrl(r.url)) continue;
      const url = normalise(r.url);
      const kind: Kind = KIND_BY_RESOURCE[r.resourceType] ?? 'other';
      const d = upsert(url, () => ({
        url, kind, frame: r.frameKind, frameUrl: r.frameUrl, workerUrl: r.workerUrl, method: r.method,
        status: r.status, contentType: r.contentType, size: r.size, initiator: initiatorOf(r.url),
      }), r.phase);
      if (FRAME_PRIORITY.indexOf(r.frameKind) < FRAME_PRIORITY.indexOf(d.frame)) {
        Object.assign(d, { frame: r.frameKind, frameUrl: r.frameUrl, workerUrl: r.workerUrl });
      }
      d.status ??= r.status;
      d.contentType ??= r.contentType;
      d.size ??= r.size;
    }
    for (const ws of p.websockets) {
      if (!isNetworkUrl(ws.url)) continue;
      const url = normalise(ws.url);
      upsert(url, () => ({
        url, kind: 'websocket', frame: 'top', frameUrl: ws.frameUrl, workerUrl: null, method: 'GET',
        status: null, contentType: null, size: null, initiator: ws.initiator,
      }), ws.phase);
    }
    for (const w of p.workers) {
      if (!isNetworkUrl(w.url)) continue;
      const url = normalise(w.url);
      const d = upsert(url, () => ({
        url, kind: w.type, frame: 'top', frameUrl: finalUrl, workerUrl: null, method: 'GET',
        status: null, contentType: null, size: null, initiator: initiatorOf(w.url),
      }), w.phase);
      // The worker's own script fetch is reported as a request; the item is the worker.
      d.kind = w.type;
      d.frame = 'top';
      d.workerUrl = null;
    }
  }

  // Workers fetch importScripts() with resource type "other"; they are scripts.
  for (const d of drafts.values()) {
    if (d.kind === 'other' && (d.frame === 'service-worker' || d.frame === 'worker') &&
        (/javascript|ecmascript/.test(d.contentType ?? '') || /\.m?js$/.test(new URL(d.url).pathname))) {
      d.kind = 'script';
    }
  }

  // ---- DOM inventory, indexed by absolute URL
  const domScripts = new Map<string, DomScript[]>();
  const domIframes = new Map<string, DomIframe>();
  for (const p of passes) {
    for (const s of p.scripts) if (s.src) domScripts.set(normalise(s.src), [...(domScripts.get(normalise(s.src)) ?? []), s]);
    for (const f of p.iframes) if (f.src && !domIframes.has(normalise(f.src))) domIframes.set(normalise(f.src), f);
  }

  const sensitiveSignals = [...new Set(passes.flatMap((p) => p.sensitiveSignals))].sort();
  const consentClicked = passes.some((p) => p.consent.clicked);

  // ---- who loaded what: parent URL, "page", or null when unknown
  const parentOf = (d: Draft): string | null => {
    if (d.frame === 'service-worker' && d.workerUrl) {
      const sw = normalise(d.workerUrl);
      return drafts.has(sw) ? sw : 'page';
    }
    const from = d.initiator?.url ? normalise(d.initiator.url) : null;
    if (!from) {
      // No initiator reported (e.g. a request in a new out-of-process frame beat Network.enable):
      // attribute it to the document of the frame it loaded in. initiatorType stays null.
      if (d.frame === 'top') return 'page';
      const doc = d.frameUrl ? normalise(d.frameUrl) : null;
      if (d.frame === 'sub' && doc) return pageUrls.has(doc) ? 'page' : drafts.has(doc) ? doc : null;
      return null;
    }
    if (from === d.url) return 'page';
    if (pageUrls.has(from)) return 'page';
    if (drafts.has(from)) return from;
    // Initiated from a document or script we didn't record (inline in a subframe, eval).
    return d.frame === 'top' ? 'page' : null;
  };

  const parents = new Map<string, string | null>();
  for (const d of drafts.values()) parents.set(d.url, parentOf(d));

  // ---- classify and rate
  interface Staged { draft: Draft; item: Omit<Item, 'id' | 'loadedBy' | 'chain'>; parent: string | null; known: boolean }
  const staged: Staged[] = [];
  for (const d of drafts.values()) {
    const host = hostOf(d.url);
    const domain = registrableDomain(host);
    let party = parties.classify(host);
    let v = vendors.lookup(host);
    const cname = opts.cnames?.get(host) ?? null;
    let cloaked = false;
    if (party !== 'third' && cname) {
      // A first-party name that CNAMEs to a known vendor is that vendor wearing the site's domain.
      for (const target of cname) {
        const tv = vendors.lookup(target);
        if (tv.known && registrableDomain(target) !== pageDomain) {
          party = 'third';
          v = tv;
          cloaked = true;
          break;
        }
      }
    }

    const isScriptLike = d.kind === 'script' || d.kind === 'worker' || d.kind === 'service-worker';
    const inDom = domScripts.get(d.url);
    let sri: boolean | null = null;
    let crossorigin: string | null = null;
    if (d.kind === 'script' && (d.frame === 'top' || d.frame === 'sub')) {
      sri = inDom ? inDom.some((s) => (s.integrity ?? '').trim() !== '') : null;
      crossorigin = inDom?.find((s) => s.crossorigin !== null)?.crossorigin ?? null;
    }
    const dynamic = d.kind === 'script' && (d.frame === 'top' || d.frame === 'sub') && !inDom;
    const injected = d.kind === 'script' && d.initiator?.type === 'script';
    const iframe = d.kind === 'iframe' ? domIframes.get(d.url) ?? null : null;
    const sandbox = iframe?.sandbox ?? null;
    const allow = iframe?.allow ?? null;
    const sandboxTokens = (sandbox ?? '').toLowerCase().split(/\s+/);
    const powerful = (allow ?? '').toLowerCase().split(';').map((x) => x.trim().split(/\s+/)[0]).filter((x) => POWERFUL_PERMISSIONS.includes(x));
    const weakIsolation = d.kind === 'iframe' && (
      !iframe || sandbox === null ||
      (sandboxTokens.includes('allow-scripts') && sandboxTokens.includes('allow-same-origin')) ||
      powerful.length > 0
    );

    const parent = parents.get(d.url) ?? null;
    const parentDraft = parent && parent !== 'page' ? drafts.get(parent) : undefined;
    const loadedByThirdPartyScript = !!parentDraft &&
      (parentDraft.kind === 'script' || parentDraft.kind === 'worker' || parentDraft.kind === 'service-worker') &&
      parties.classify(hostOf(parentDraft.url)) === 'third';

    const verdict = rules.evaluate({
      kind: d.kind, party, frame: d.frame, category: v.category, sri,
      sensitivePage: sensitiveSignals.length > 0, loadedByThirdPartyScript, weakIsolation,
    });
    const reasons = [...verdict.reasons];
    if (sri === null && d.kind === 'script' && verdict.reasons.includes('no SRI')) {
      reasons[reasons.indexOf('no SRI')] = 'no SRI (unverifiable: the script was not in the DOM at snapshot)';
    }
    if (d.kind === 'iframe' && party === 'third') {
      if (sandbox === null && iframe) reasons.push('iframe has no sandbox attribute');
      if (powerful.length) reasons.push(`iframe granted ${powerful.join(', ')}`);
    }
    if (cloaked) reasons.push(`cloaked: ${host} is a CNAME to ${cname!.join(' -> ')}`);

    const passes = PHASE_ORDER.filter((ph) => d.phases.has(ph));
    // Seen after accepting but neither before any choice nor after rejecting. Something seen after
    // both choices was gated by time or scrolling, not consent.
    const consentGated = consentClicked && d.phases.has('post-accept') && !d.phases.has('pre-consent') && !d.phases.has('post-reject');
    const evergreen = isScriptLike && isEvergreen(d.url);
    const modifiers: string[] = [];
    if (party === 'third') {
      if (evergreen) modifiers.push('evergreen');
      if (consentGated) modifiers.push('seen only after consent');
      if (dynamic) modifiers.push('removed from DOM');
      if (injected) modifiers.push('injected dynamically');
    }

    staged.push({
      draft: d,
      parent,
      known: v.known,
      item: {
        kind: d.kind, url: d.url, host, domain, party, cloaked, cname,
        vendor: party === 'third' ? v.vendor : party === 'owned' ? `${domain} (owned)` : `${pageDomain} (first party)`,
        category: party === 'third' ? v.category : 'unknown' as Category,
        frame: d.frame, frameUrl: d.frameUrl, initiatorType: d.initiator?.type ?? null, method: d.method,
        status: d.status, contentType: d.contentType, size: d.size, sri, crossorigin, sandbox, allow,
        evergreen, dynamic, injected, consentGated, passes, rating: verdict.rating, reasons, modifiers,
      },
    });
  }

  staged.sort((a, b) =>
    RATING_ORDER.indexOf(a.item.rating) - RATING_ORDER.indexOf(b.item.rating) ||
    cmp(a.item.vendor.toLowerCase(), b.item.vendor.toLowerCase()) ||
    cmp(a.item.url, b.item.url));

  const idOf = new Map<string, string>();
  staged.forEach((s, i) => idOf.set(s.draft.url, `i${i + 1}`));

  const items: Item[] = staged.map((s) => {
    const loadedBy = s.parent === null ? null : s.parent === 'page' ? 'page' : idOf.get(s.parent) ?? null;
    const chain: string[] = [idOf.get(s.draft.url)!];
    const seen = new Set(chain);
    let cur = s.parent;
    while (cur && cur !== 'page') {
      const id = idOf.get(cur);
      if (!id || seen.has(id)) break;
      chain.unshift(id);
      seen.add(id);
      cur = parents.get(cur) ?? null;
    }
    chain.unshift(cur === 'page' ? 'page' : 'unknown');
    return { id: idOf.get(s.draft.url)!, ...s.item, loadedBy, chain };
  });

  // ---- vendors (third parties only)
  const vendorMap = new Map<string, VendorSummary>();
  for (const [i, it] of items.entries()) {
    if (it.party !== 'third') continue;
    let v = vendorMap.get(it.vendor);
    if (!v) {
      v = { vendor: it.vendor, category: it.category, known: staged[i].known, domains: [], rating: 'none', items: [] };
      vendorMap.set(it.vendor, v);
    }
    if (!v.domains.includes(it.host)) v.domains.push(it.host);
    v.items.push(it.id);
    v.rating = maxRating([v.rating, it.rating]);
  }
  const vendorList = [...vendorMap.values()]
    .map((v) => ({ ...v, domains: v.domains.sort() }))
    .sort((a, b) => RATING_ORDER.indexOf(a.rating) - RATING_ORDER.indexOf(b.rating) || cmp(a.vendor.toLowerCase(), b.vendor.toLowerCase()));

  // ---- page-level controls
  const headerPass = passes.find((p) => p.headers.csp.length || p.headers.cspReportOnly.length || p.headers.permissionsPolicy) ?? passes[0];
  const metaPass = passes.find((p) => p.metaCsp.length) ?? passes[0];
  const csp = summariseCsp(headerPass.headers, metaPass.metaCsp);

  const third = items.filter((i) => i.party === 'third');
  const topScripts = third.filter((i) => i.kind === 'script' && i.frame === 'top');
  const byRating = Object.fromEntries(RATING_ORDER.map((r) => [r, items.filter((i) => i.rating === r).length])) as Record<Rating, number>;

  // ---- consent diff
  let diff: Report['consent']['diff'] = null;
  if (opts.consentMode !== 'none') {
    const inPhase = (ph: Phase) => new Set(third.filter((i) => i.passes.includes(ph)).map((i) => i.vendor));
    const pre = inPhase('pre-consent');
    const acc = inPhase('post-accept');
    const rej = inPhase('post-reject');
    const sorted = (s: Iterable<string>) => [...s].sort((a, b) => cmp(a.toLowerCase(), b.toLowerCase()));
    diff = {
      onlyAfterAccept: sorted([...acc].filter((v) => !pre.has(v) && !rej.has(v))),
      afterReject: sorted([...rej].filter((v) => !pre.has(v))),
      preConsent: sorted(pre),
    };
  }

  // ---- cookies: third party = cookie domain outside the page's registrable domain
  const cookieKey = (c: { name: string; domain: string }) => `${c.domain}\u0000${c.name}`;
  const cookies = new Map<string, PassResult['cookies'][number]>();
  for (const p of passes) for (const c of p.cookies) cookies.set(cookieKey(c), c);
  const thirdPartyCookies = [...cookies.values()]
    .filter((c) => parties.classify(c.domain.replace(/^\./, '')) === 'third')
    .sort((a, b) => cmp(cookieKey(a), cookieKey(b)));

  const errors = [...new Set(passes.flatMap((p) => p.errors.map((e) => `${p.name} pass: ${e}`)))];
  const limitations = [...LIMITATIONS];
  for (const p of passes) {
    if (p.name !== 'none' && !p.consent.clicked) {
      limitations.push(`No consent control was found for the ${p.name} pass, so "post-${p.name}" is not a real consent state.`);
    }
  }

  const passPhases: Phase[] = ['pre-consent'];
  if (passes.some((p) => p.name === 'accept')) passPhases.push('post-accept');
  if (passes.some((p) => p.name === 'reject')) passPhases.push('post-reject');

  return {
    scan: {
      url: opts.url,
      finalUrl,
      scannedAt: opts.scannedAt,
      toolVersion: TOOL_VERSION,
      consentMode: opts.consentMode,
      passes: passPhases,
      consentMethod: Object.fromEntries(passes.map((p) => [p.name, p.consent.method])),
      options: {
        interact: opts.interact, settleMs: opts.settleMs, dnsCheck: opts.dnsCheck,
        blockPrivate: opts.blockPrivate, firstParty: [...opts.firstParty].sort(),
      },
    },
    page: {
      registrableDomain: pageDomain,
      sensitiveSignals,
      csp,
      permissionsPolicy: headerPass.headers.permissionsPolicy,
      inlineScripts: passes.find((p) => p.inlineScripts.count > 0)?.inlineScripts ?? { count: 0, sha256: [] },
      rating: maxRating(third.map((i) => i.rating)),
    },
    summary: {
      items: items.length,
      thirdPartyItems: third.length,
      thirdPartyDomains: new Set(third.map((i) => i.domain)).size,
      vendors: vendorList.length,
      unknownVendors: vendorList.filter((v) => !v.known).length,
      topFrameThirdPartyScripts: topScripts.length,
      sriCoverage: { with: topScripts.filter((i) => i.sri === true).length, of: topScripts.length },
      byRating,
    },
    consent: {
      mode: opts.consentMode,
      passes: passes.filter((p) => p.name !== 'none').map((p) => ({ name: p.name, method: p.consent.method, clicked: p.consent.clicked })),
      diff,
    },
    vendors: vendorList,
    items,
    cookies: { thirdParty: thirdPartyCookies, firstPartyCount: cookies.size - thirdPartyCookies.length },
    blocked: [...(opts.blocked ?? [])].sort((a, b) => cmp(a.url, b.url)),
    errors,
    limitations,
  };
}
