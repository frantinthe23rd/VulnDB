// Content-Security-Policy parsing (header and <meta>) and the page-level checks the report shows.
import type { CspPolicy, CspSummary } from './types.js';

export function parsePolicy(raw: string, source: 'header' | 'meta', reportOnly: boolean): CspPolicy {
  const directives: Record<string, string[]> = {};
  for (const part of raw.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    // Per CSP3, a repeated directive is ignored after its first occurrence.
    if (!(name in directives)) directives[name] = tokens.slice(1);
  }
  return { source, reportOnly, raw: raw.trim(), directives };
}

function effective(policy: CspPolicy, directive: string, fallbacks: string[]): string[] | null {
  for (const name of [directive, ...fallbacks]) {
    if (policy.directives[name]) return policy.directives[name];
  }
  return null;
}

const SCRIPT_FALLBACKS = ['default-src'];
const SCRIPT_ELEM = ['script-src-elem', 'script-src', 'default-src'];

/**
 * Builds the CSP summary. A header can carry several policies separated by commas;
 * the browser enforces all of them, so a weakness only counts if every enforcing
 * policy that sets the directive has it.
 */
export function summariseCsp(
  headers: { csp: string[]; cspReportOnly: string[] },
  metas: { content: string; reportOnly: boolean }[],
): CspSummary {
  const policies: CspPolicy[] = [];
  for (const h of headers.csp) for (const p of h.split(',')) if (p.trim()) policies.push(parsePolicy(p, 'header', false));
  for (const h of headers.cspReportOnly) for (const p of h.split(',')) if (p.trim()) policies.push(parsePolicy(p, 'header', true));
  for (const m of metas) policies.push(parsePolicy(m.content, 'meta', m.reportOnly));

  const issues: string[] = [];
  const enforcing = policies.filter((p) => !p.reportOnly);
  const present = policies.length > 0;
  const reportOnly = present && enforcing.length === 0;

  if (!present) {
    return { present, reportOnly, policies, scriptSrc: null, connectSrc: null, issues: ['no CSP: any script source and any data destination is allowed'] };
  }
  if (reportOnly) issues.push('CSP is report-only: nothing is enforced');
  for (const p of policies) {
    if (p.reportOnly && p.source === 'meta') issues.push('report-only CSP in <meta> is ignored by browsers');
    else if (p.reportOnly && enforcing.length > 0) issues.push(`report-only ${p.source} policy is monitored, not enforced: ${p.raw}`);
  }

  const scriptLists = enforcing.map((p) => effective(p, 'script-src', SCRIPT_FALLBACKS));
  const elemLists = enforcing.map((p) => effective(p, 'script-src-elem', SCRIPT_ELEM.slice(1)));
  const connectLists = enforcing.map((p) => effective(p, 'connect-src', ['default-src']));
  const scriptSrc = scriptLists.find((l) => l !== null) ?? null;
  const connectSrc = connectLists.find((l) => l !== null) ?? null;

  if (enforcing.length > 0) {
    // A source is allowed only if every enforcing policy allows it (a missing directive allows everything).
    const allAllow = (lists: (string[] | null)[], test: (l: string[]) => boolean) => lists.every((l) => l === null || test(l));
    const has = (tok: string) => (l: string[]) => l.some((t) => t.toLowerCase() === tok);
    const hasNonceOrHash = (l: string[]) => l.some((t) => /^'(nonce|sha256|sha384|sha512)-/i.test(t));
    const strictDynamic = (l: string[]) => has("'strict-dynamic'")(l);

    if (scriptLists.every((l) => l === null)) issues.push('script-src (and default-src) not set: any script source is allowed');
    else {
      if (allAllow(elemLists, (l) => has('*')(l) && !strictDynamic(l))) issues.push('script-src allows any host (*)');
      else if (allAllow(elemLists, (l) => (has('https:')(l) || has('http:')(l)) && !strictDynamic(l))) issues.push('script-src allows any host over https:');
      if (allAllow(scriptLists, (l) => has("'unsafe-inline'")(l) && !hasNonceOrHash(l))) issues.push("script-src allows 'unsafe-inline'");
      if (allAllow(scriptLists, has("'unsafe-eval'"))) issues.push("script-src allows 'unsafe-eval'");
    }
    if (connectLists.every((l) => l === null)) issues.push('connect-src not set: scripts can send data anywhere');
    else if (allAllow(connectLists, (l) => has('*')(l) || has('https:')(l))) issues.push('connect-src allows any host');
  }
  return { present, reportOnly, policies, scriptSrc, connectSrc, issues };
}
