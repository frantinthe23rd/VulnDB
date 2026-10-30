// Shared types: what a browser pass records, and the report built from it.

export type Rating = 'critical' | 'high' | 'medium' | 'low' | 'none';
export const RATING_ORDER: Rating[] = ['critical', 'high', 'medium', 'low', 'none'];

export type Kind =
  | 'script' | 'iframe' | 'worker' | 'service-worker' | 'websocket'
  | 'fetch' | 'beacon' | 'image' | 'stylesheet' | 'font' | 'other';

export type Party = 'first' | 'owned' | 'third';
export type FrameKind = 'top' | 'sub' | 'worker' | 'service-worker';

export type Category =
  | 'tag-manager' | 'analytics' | 'rum-performance' | 'session-replay' | 'advertising'
  | 'ab-testing' | 'chat-support' | 'payments' | 'auth-sso' | 'consent' | 'cdn-library'
  | 'fonts' | 'social' | 'unknown';

export type ConsentMode = 'none' | 'accept' | 'reject' | 'both';
/** Label of the moment a request was seen: before any consent click, or after accept/reject. */
export type Phase = 'pre-consent' | 'post-accept' | 'post-reject';

// ---------------------------------------------------------------- raw pass data

export interface RawRequest {
  url: string;
  method: string;
  resourceType: string;
  frameKind: FrameKind;
  frameUrl: string | null;
  /** Script URL of the worker or service worker that made the request. */
  workerUrl: string | null;
  isMainNavigation: boolean;
  status: number | null;
  contentType: string | null;
  size: number | null;
  failure: string | null;
  phase: Phase;
}

export interface RawInitiator {
  type: string;
  /** Script on top of the initiating stack, or the document URL for parser loads. */
  url: string | null;
}

export interface DomScript {
  src: string | null;
  integrity: string | null;
  crossorigin: string | null;
  type: string | null;
  async: boolean;
  defer: boolean;
  frameUrl: string;
  top: boolean;
}

export interface DomIframe {
  src: string;
  sandbox: string | null;
  allow: string | null;
  parentUrl: string;
}

export interface CookieInfo {
  name: string;
  domain: string;
  sameSite: string;
  secure: boolean;
  httpOnly: boolean;
}

export interface ConsentResult {
  /** e.g. "onetrust-selector", "text-match", "none-found", "not-attempted". */
  method: string;
  clicked: boolean;
  frameUrl: string | null;
}

export interface PassResult {
  name: 'none' | 'accept' | 'reject';
  finalUrl: string;
  requests: RawRequest[];
  initiators: Record<string, RawInitiator>;
  websockets: { url: string; frameUrl: string | null; initiator: RawInitiator | null; phase: Phase }[];
  workers: { url: string; type: 'worker' | 'service-worker'; phase: Phase }[];
  scripts: DomScript[];
  inlineScripts: { count: number; sha256: string[] };
  iframes: DomIframe[];
  cookies: CookieInfo[];
  headers: { csp: string[]; cspReportOnly: string[]; permissionsPolicy: string | null };
  metaCsp: { content: string; reportOnly: boolean }[];
  sensitiveSignals: string[];
  consent: ConsentResult;
  blocked: { url: string; reason: string }[];
  errors: string[];
}

// ---------------------------------------------------------------- report

export interface CspPolicy {
  source: 'header' | 'meta';
  reportOnly: boolean;
  raw: string;
  directives: Record<string, string[]>;
}

export interface CspSummary {
  present: boolean;
  reportOnly: boolean;
  policies: CspPolicy[];
  scriptSrc: string[] | null;
  connectSrc: string[] | null;
  issues: string[];
}

export interface Item {
  id: string;
  kind: Kind;
  url: string;
  host: string;
  domain: string;
  party: Party;
  cloaked: boolean;
  cname: string[] | null;
  vendor: string;
  category: Category;
  frame: FrameKind;
  frameUrl: string | null;
  loadedBy: string | null;
  chain: string[];
  initiatorType: string | null;
  method: string | null;
  status: number | null;
  contentType: string | null;
  size: number | null;
  sri: boolean | null;
  crossorigin: string | null;
  sandbox: string | null;
  allow: string | null;
  evergreen: boolean;
  dynamic: boolean;
  injected: boolean;
  consentGated: boolean;
  passes: Phase[];
  rating: Rating;
  reasons: string[];
  modifiers: string[];
}

export interface VendorSummary {
  vendor: string;
  category: Category;
  known: boolean;
  domains: string[];
  rating: Rating;
  items: string[];
}

export interface Report {
  scan: {
    url: string;
    finalUrl: string;
    scannedAt: string;
    toolVersion: string;
    consentMode: ConsentMode;
    passes: Phase[];
    consentMethod: Record<string, string>;
    options: { interact: boolean; settleMs: number; dnsCheck: boolean; blockPrivate: boolean; firstParty: string[] };
  };
  page: {
    registrableDomain: string;
    sensitiveSignals: string[];
    csp: CspSummary;
    permissionsPolicy: string | null;
    inlineScripts: { count: number; sha256: string[] };
    rating: Rating;
  };
  summary: {
    items: number;
    thirdPartyItems: number;
    thirdPartyDomains: number;
    vendors: number;
    unknownVendors: number;
    topFrameThirdPartyScripts: number;
    sriCoverage: { with: number; of: number };
    byRating: Record<Rating, number>;
  };
  consent: {
    mode: ConsentMode;
    passes: { name: string; method: string; clicked: boolean }[];
    diff: { onlyAfterAccept: string[]; afterReject: string[]; preConsent: string[] } | null;
  };
  vendors: VendorSummary[];
  items: Item[];
  cookies: { thirdParty: CookieInfo[]; firstPartyCount: number };
  blocked: { url: string; reason: string }[];
  errors: string[];
  limitations: string[];
}
