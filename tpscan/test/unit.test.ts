// Unit tests: no browser.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { summariseCsp } from '../src/csp.js';
import { isEvergreen, PartyClassifier, registrableDomain } from '../src/domains.js';
import { cnameChains } from '../src/dnscheck.js';
import { blockedAddressReason, GuardProxy } from '../src/guard.js';
import { jsonForScript, slugFor, toCsv } from '../src/report.js';
import { RuleSet, type RuleFacts } from '../src/rules.js';
import type { Report } from '../src/types.js';
import { VendorMap } from '../src/vendors.js';

test('registrable domain uses the Public Suffix List', () => {
  assert.equal(registrableDomain('www.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('a.b.shop.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('cdn.example.com.au'), 'example.com.au');
  assert.equal(registrableDomain('news.bbc.co.uk'), 'bbc.co.uk');
  // Private section: each github.io user is their own site.
  assert.equal(registrableDomain('alice.github.io'), 'alice.github.io');
  assert.equal(registrableDomain('docs.alice.github.io'), 'alice.github.io');
  assert.notEqual(registrableDomain('alice.github.io'), registrableDomain('bob.github.io'));
  assert.equal(registrableDomain('https://x.y.example.com:8443/path'), 'example.com');
  assert.equal(registrableDomain('203.0.113.9'), '203.0.113.9');
});

test('party classification, with owned domains', () => {
  const p = new PartyClassifier('example.co.uk', ['example-cdn.net']);
  assert.equal(p.classify('static.example.co.uk'), 'first');
  assert.equal(p.classify('img.example-cdn.net'), 'owned');
  assert.equal(p.classify('other.co.uk'), 'third');
  const gh = new PartyClassifier('alice.github.io');
  assert.equal(gh.classify('bob.github.io'), 'third');
});

test('evergreen URLs have no version or hash', () => {
  assert.equal(isEvergreen('https://cdn.vendor.com/rum.js'), true);
  assert.equal(isEvergreen('https://cdn.vendor.com/latest/sdk.js'), true);
  assert.equal(isEvergreen('https://cdn.vendor.com/v3.2.1/sdk.js'), false);
  assert.equal(isEvergreen('https://cdn.jsdelivr.net/npm/lib@1.4.0/dist/lib.min.js'), false);
  assert.equal(isEvergreen('https://cdn.vendor.com/app.3f9a2b7c1d.js'), false);
  assert.equal(isEvergreen('https://cdn.vendor.com/sdk.js?v=20261030'), false);
});

test('vendor lookup walks up to parent domains and keeps unknowns', () => {
  const v = VendorMap.create({});
  assert.deepEqual(v.lookup('www.googletagmanager.com'), { vendor: 'Google Tag Manager', category: 'tag-manager', known: true });
  assert.equal(v.lookup('cdn.debugbear.com').vendor, 'DebugBear');
  assert.deepEqual(v.lookup('t.nobody-knows.example'), { vendor: 'nobody-knows.example', category: 'unknown', known: false });
});

test('CSP: header and meta parsed, report-only flagged, weaknesses found', () => {
  const csp = summariseCsp(
    { csp: [], cspReportOnly: ["default-src 'self'; report-uri /r"] },
    [{ content: "script-src * 'unsafe-inline'", reportOnly: false }],
  );
  assert.equal(csp.present, true);
  assert.equal(csp.reportOnly, false);
  assert.equal(csp.policies.length, 2);
  assert.deepEqual(csp.policies.map((p) => [p.source, p.reportOnly]), [['header', true], ['meta', false]]);
  assert.deepEqual(csp.scriptSrc, ['*', "'unsafe-inline'"]);
  assert.equal(csp.connectSrc, null);
  assert.ok(csp.issues.some((i) => i.startsWith('report-only header policy')));
  assert.ok(csp.issues.includes('script-src allows any host (*)'));
  assert.ok(csp.issues.includes("script-src allows 'unsafe-inline'"));
  assert.ok(csp.issues.some((i) => i.startsWith('connect-src not set')));

  const onlyRo = summariseCsp({ csp: [], cspReportOnly: ["script-src 'self'"] }, []);
  assert.equal(onlyRo.reportOnly, true);
  assert.ok(onlyRo.issues[0].includes('report-only'));

  const strict = summariseCsp({ csp: ["default-src 'self'; script-src 'self' 'nonce-abc' 'unsafe-inline' https:; connect-src 'self'"], cspReportOnly: [] }, []);
  assert.ok(!strict.issues.includes("script-src allows 'unsafe-inline'"), 'unsafe-inline is ignored when a nonce is present');
  assert.ok(strict.issues.includes('script-src allows any host over https:'));
  assert.deepEqual(strict.connectSrc, ["'self'"]);

  // Two enforcing policies: a weakness counts only if both allow it.
  const two = summariseCsp({ csp: ["script-src *", "script-src 'self'"], cspReportOnly: [] }, []);
  assert.ok(!two.issues.includes('script-src allows any host (*)'));

  assert.equal(summariseCsp({ csp: [], cspReportOnly: [] }, []).present, false);
});

test('guard refuses private, loopback, link-local and metadata addresses', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.1', '169.254.169.254',
    '100.64.0.1', '0.0.0.0', '::1', '::', 'fe80::1', 'fc00::1', 'fd00:ec2::254', '::ffff:127.0.0.1', '::ffff:a9fe:a9fe', '64:ff9b::a9fe:a9fe']) {
    assert.ok(blockedAddressReason(ip), `${ip} should be blocked`);
  }
  for (const ip of ['8.8.8.8', '172.32.0.1', '1.1.1.1', '2606:4700:4700::1111', '::ffff:8.8.8.8']) {
    assert.equal(blockedAddressReason(ip), null, `${ip} should be allowed`);
  }
});

test('guard checks every resolved address and blocked names', async () => {
  const g = new GuardProxy({ resolve: async (h) => (h === 'mixed.example' ? ['93.184.216.34', '10.0.0.5'] : ['93.184.216.34']) });
  await assert.rejects(g.check('mixed.example'), /private/);
  await assert.rejects(g.check('metadata.google.internal'), /blocked hostname/);
  await assert.rejects(g.check('anything.localhost'), /blocked hostname/);
  await assert.rejects(g.check('[::1]'), /loopback/);
  assert.equal(await g.check('example.com'), '93.184.216.34');
});

const facts = (over: Partial<RuleFacts>): RuleFacts => ({
  kind: 'script', party: 'third', frame: 'top', category: 'analytics', sri: false,
  sensitivePage: false, loadedByThirdPartyScript: false, weakIsolation: false, ...over,
});

test('rating rules: first match wins, all matches give reasons', () => {
  const rules = RuleSet.load();
  const crit = rules.evaluate(facts({ sensitivePage: true }));
  assert.equal(crit.rating, 'critical');
  assert.deepEqual(crit.ruleIds, ['sensitive-page-unpinned-script', 'unpinned-top-frame-script']);
  assert.ok(crit.reasons.includes('no SRI') && crit.reasons.includes('third-party script in top frame'));
  assert.equal(rules.evaluate(facts({ sri: null, sensitivePage: true })).rating, 'critical', 'unknown SRI counts as no SRI');
  assert.equal(rules.evaluate(facts({})).rating, 'high');
  const tm = rules.evaluate(facts({ category: 'tag-manager', sri: true }));
  assert.equal(tm.rating, 'high');
  assert.ok(tm.ruleIds.includes('pinned-top-frame-script'), 'lower rules still add reasons');
  assert.equal(rules.evaluate(facts({ frame: 'sub', loadedByThirdPartyScript: true })).rating, 'high');
  assert.equal(rules.evaluate(facts({ frame: 'service-worker', sri: null })).rating, 'high');
  assert.equal(rules.evaluate(facts({ sri: true })).rating, 'medium');
  assert.equal(rules.evaluate(facts({ kind: 'iframe', sri: null, weakIsolation: true })).rating, 'medium');
  assert.equal(rules.evaluate(facts({ kind: 'iframe', sri: null })).rating, 'low');
  assert.equal(rules.evaluate(facts({ kind: 'beacon', sri: null })).rating, 'medium');
  assert.equal(rules.evaluate(facts({ kind: 'image', sri: null })).rating, 'low');
  assert.equal(rules.evaluate(facts({ party: 'first' })).rating, 'none');
  assert.equal(rules.evaluate(facts({ party: 'owned' })).rating, 'none');
});

test('dns check follows CNAME chains', async () => {
  const table: Record<string, string[]> = { 'metrics.a.com': ['edge.b.net'], 'edge.b.net': ['x.c.org.'], 'loop.a.com': ['loop.a.com'] };
  const chains = await cnameChains(['metrics.a.com', 'www.a.com', 'loop.a.com'], async (h) => {
    if (!table[h]) throw new Error('ENODATA');
    return table[h];
  });
  assert.deepEqual(chains.get('metrics.a.com'), ['edge.b.net', 'x.c.org']);
  assert.equal(chains.has('www.a.com'), false);
  assert.deepEqual(chains.get('loop.a.com'), ['loop.a.com']);
});

test('CSV cells are quoted and protected from formula injection', () => {
  const report = {
    scan: { finalUrl: 'https://e.com/', scannedAt: '2026-10-30T00:00:00Z' },
    items: [{
      id: 'i1', rating: 'high', kind: 'script', party: 'third', vendor: '=HYPERLINK("x")', category: 'unknown',
      domain: 'v.com', host: 'v.com', url: 'https://v.com/a,b.js', frame: 'top', frameUrl: null, loadedBy: 'page',
      chain: ['page', 'i1'], initiatorType: 'parser', sri: false, crossorigin: null, sandbox: null, allow: null,
      evergreen: true, dynamic: false, injected: false, consentGated: false, cloaked: false, cname: null,
      passes: ['pre-consent'], status: 200, contentType: 'application/javascript', size: 10, method: 'GET',
      reasons: ['a', 'b'], modifiers: [],
    }],
  } as unknown as Report;
  const [header, row] = toCsv(report).trim().split('\r\n');
  assert.ok(header.startsWith('page_url,scanned_at,id,rating'));
  assert.ok(row.includes(`"'=HYPERLINK(""x"")"`));
  assert.ok(row.includes('"https://v.com/a,b.js"'));
  assert.ok(row.includes('page > i1'));
});

test('report JSON cannot break out of its <script> element', () => {
  const s = jsonForScript({ url: 'https://x/</script><script>alert(1)</script>', c: '<!--' });
  assert.ok(!s.includes('<'));
  assert.deepEqual(JSON.parse(s), { url: 'https://x/</script><script>alert(1)</script>', c: '<!--' });
});

test('slugs are filesystem-safe and distinct per path', () => {
  assert.equal(slugFor('https://Example.co.uk/'), 'example.co.uk');
  assert.equal(slugFor('https://example.co.uk/login?next=/a'), 'example.co.uk_login-next-a');
  assert.equal(slugFor('http://site.test:8080/'), 'site.test-8080');
  assert.match(slugFor('https://e.com/../../etc/passwd'), /^[a-z0-9._-]+$/);
});
