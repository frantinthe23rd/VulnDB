// Acceptance tests against the local fixture site (see test/fixture/serve.ts).
// Real sites change too often to be the oracle; the fixture holds still.
import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { startFixture, type Fixture } from './fixture/serve.js';
import { toJson, validateReport } from '../src/report.js';
import { RuleSet } from '../src/rules.js';
import { Scanner, type ScanOptions } from '../src/scan.js';
import type { Item, Report } from '../src/types.js';
import { VendorMap } from '../src/vendors.js';

const FIXTURE_VENDORS = fileURLToPath(new URL('../../test/fixture/vendors.json', import.meta.url));

let fx: Fixture;
let first: Report;
let second: Report;

function baseOptions(over: Partial<ScanOptions> = {}): ScanOptions {
  return {
    consent: 'both',
    interact: true,
    settleMs: 500,
    timeoutMs: 60000,
    firstParty: [],
    dnsCheck: true,
    headful: false,
    blockPrivate: false,
    vendors: VendorMap.create({ overrides: [FIXTURE_VENDORS] }),
    rules: RuleSet.load(),
    chromiumArgs: fx.chromiumArgs,
    cnameResolver: async (host) => {
      if (host === 'metrics.site.test') return ['edge.cname-vendor.test'];
      throw new Error('ENODATA');
    },
    ...over,
  };
}

function item(report: Report, host: string, path: string): Item {
  const url = `${fx.origin(host)}${path}`.replace(/^http:\/\/(.*)\/ws$/, 'ws://$1/ws');
  const it = report.items.find((i) => i.url === url);
  assert.ok(it, `expected an item for ${url}; have:\n${report.items.map((i) => i.url).join('\n')}`);
  return it;
}

const byId = (report: Report, id: string | null) => report.items.find((i) => i.id === id);

before(async () => {
  fx = await startFixture();
  const scanner = new Scanner(baseOptions());
  try {
    first = await scanner.scan(`${fx.origin('site.test')}/`);
    second = await scanner.scan(`${fx.origin('site.test')}/`);
  } finally {
    await scanner.close();
  }
});

after(async () => {
  await fx?.close();
});

describe('fixture scan', () => {
  test('every fixture item has the right kind, party, frame and loader chain', () => {
    const r = first;
    const gtm = item(r, 'tags.vendor-c.test', '/gtm.js');
    const pixel = item(r, 'vendor-b.test', '/pixel.js');
    const beacon = item(r, 'vendor-b.test', '/collect');
    const widget = item(r, 'vendor-a.test', '/widget.js');
    const rum = item(r, 'vendor-a.test', '/rum');
    const sw = item(r, 'site.test', '/sw.js');
    const swLib = item(r, 'vendor-b.test', '/sw-lib.js');
    const chat = item(r, 'vendor-e.test', '/chat.html');
    const chatJs = item(r, 'vendor-e.test', '/chat.js');
    const ws = item(r, 'vendor-a.test', '/ws');

    const expect: [Item, Partial<Item>][] = [
      [gtm, { kind: 'script', party: 'third', frame: 'top', loadedBy: 'page', vendor: 'ExampleTags', category: 'tag-manager' }],
      [pixel, { kind: 'script', party: 'third', frame: 'top', loadedBy: gtm.id, injected: true }],
      [beacon, { kind: 'beacon', party: 'third', frame: 'top', loadedBy: pixel.id }],
      [widget, { kind: 'script', party: 'third', frame: 'top', loadedBy: 'page', injected: false }],
      [rum, { kind: 'fetch', party: 'third', frame: 'top', loadedBy: widget.id }],
      [sw, { kind: 'service-worker', party: 'first', loadedBy: 'page' }],
      [swLib, { kind: 'script', party: 'third', frame: 'service-worker', loadedBy: sw.id }],
      [chat, { kind: 'iframe', party: 'third', frame: 'top', loadedBy: 'page', sandbox: null, allow: 'clipboard-write' }],
      [chatJs, { kind: 'script', party: 'third', frame: 'sub', loadedBy: chat.id }],
      [ws, { kind: 'websocket', party: 'third', loadedBy: 'page' }],
      [item(r, 'vendor-d.test', '/frame.html'), { kind: 'iframe', party: 'third', frame: 'top', sandbox: 'allow-scripts' }],
      [item(r, 'vendor-d.test', '/style.css'), { kind: 'stylesheet', party: 'third', frame: 'top' }],
      [item(r, 'vendor-d.test', '/pixel.gif'), { kind: 'image', party: 'third', frame: 'top' }],
      [item(r, 'vendor-a.test', '/selfremove.js'), { kind: 'script', party: 'third', dynamic: true, sri: null }],
      [item(r, 'vendor-f.test', '/ads.js'), { kind: 'script', party: 'third', frame: 'top', loadedBy: 'page', injected: true }],
      [item(r, 'site.test', '/app.js'), { kind: 'script', party: 'first', frame: 'top', rating: 'none' }],
    ];
    for (const [it, want] of expect) {
      for (const [k, v] of Object.entries(want)) assert.deepEqual(it[k as keyof Item], v, `${it.url} ${k}`);
    }
    assert.deepEqual(beacon.chain, ['page', gtm.id, pixel.id, beacon.id]);
    assert.deepEqual(swLib.chain, ['page', sw.id, swLib.id]);
    assert.deepEqual(chatJs.chain, ['page', chat.id, chatJs.id]);
    // The main document and its own navigation are not items.
    assert.ok(!r.items.some((i) => i.url === `${fx.origin('site.test')}/`));
  });

  test('SRI is reported for scripts with and without integrity', () => {
    assert.equal(item(first, 'vendor-a.test', '/sri.js').sri, true);
    assert.equal(item(first, 'vendor-a.test', '/sri.js').crossorigin, 'anonymous');
    assert.equal(item(first, 'vendor-a.test', '/widget.js').sri, false);
    assert.equal(item(first, 'tags.vendor-c.test', '/gtm.js').sri, false);
    assert.deepEqual(first.summary.sriCoverage, { with: 1, of: 6 });
  });

  test('consent: the accept pass shows the gated vendor and the diff lists it', () => {
    const ads = item(first, 'vendor-f.test', '/ads.js');
    assert.deepEqual(ads.passes, ['post-accept']);
    assert.equal(ads.consentGated, true);
    assert.ok(ads.modifiers.includes('seen only after consent'));
    assert.deepEqual(first.consent.diff?.onlyAfterAccept, ['ExampleAds']);
    assert.deepEqual(first.consent.diff?.afterReject, []);
    assert.ok(first.consent.diff?.preConsent.includes('ExampleTags'));
    assert.deepEqual(first.consent.passes, [
      { name: 'accept', method: 'text-match', clicked: true },
      { name: 'reject', method: 'text-match', clicked: true },
    ]);
    // Loaded on scroll after both choices: gated by interaction, not consent.
    assert.equal(item(first, 'vendor-d.test', '/lazy.gif').consentGated, false);
  });

  test('CSP is parsed from header and meta; report-only is flagged', () => {
    const csp = first.page.csp;
    assert.deepEqual(csp.policies.map((p) => [p.source, p.reportOnly]), [['header', true], ['meta', false]]);
    assert.deepEqual(csp.scriptSrc, ['*', "'unsafe-inline'"]);
    assert.ok(csp.issues.some((i) => i.startsWith('report-only header policy is monitored')));
    assert.ok(csp.issues.includes('script-src allows any host (*)'));
    assert.equal(first.page.permissionsPolicy, 'camera=(), geolocation=()');
  });

  test('rating rules give the expected rating and reasons for each item', () => {
    const expected: [string, string, string, string[]][] = [
      ['tags.vendor-c.test', '/gtm.js', 'critical', ['sensitive page (password, payment or login field)', 'tag manager can load further code nobody at the site reviewed']],
      ['vendor-b.test', '/pixel.js', 'critical', ['loaded by another third-party script']],
      ['vendor-a.test', '/widget.js', 'critical', ['third-party script in top frame', 'no SRI']],
      ['vendor-a.test', '/selfremove.js', 'critical', ['no SRI (unverifiable: the script was not in the DOM at snapshot)']],
      ['vendor-f.test', '/ads.js', 'critical', ['no SRI']],
      ['vendor-b.test', '/sw-lib.js', 'high', ["imported into a service worker, which can intercept the site's own requests"]],
      ['vendor-a.test', '/sri.js', 'medium', ['pinned with SRI; the vendor still has page access if the hash is updated']],
      ['vendor-e.test', '/chat.html', 'medium', ['iframe has no sandbox attribute', 'iframe granted clipboard-write']],
      ['vendor-b.test', '/collect', 'medium', ['data sent to a third party']],
      ['vendor-a.test', '/rum', 'medium', ['data sent to a third party']],
      ['vendor-a.test', '/ws', 'medium', ['data sent to a third party']],
      ['vendor-d.test', '/frame.html', 'low', []],
      ['vendor-d.test', '/style.css', 'low', []],
      ['vendor-d.test', '/pixel.gif', 'low', []],
      ['vendor-e.test', '/chat.js', 'low', []],
    ];
    for (const [host, path, rating, reasons] of expected) {
      const it = item(first, host, path);
      assert.equal(it.rating, rating, `${it.url} rating (reasons: ${it.reasons.join('; ')})`);
      for (const reason of reasons) assert.ok(it.reasons.includes(reason), `${it.url} should list "${reason}"; has ${JSON.stringify(it.reasons)}`);
    }
    assert.equal(first.page.rating, 'critical');
    assert.deepEqual(first.page.sensitiveSignals, ['login-form', 'password-field']);
    assert.equal(first.vendors[0].rating, 'critical');
  });

  test('--dns-check reclassifies a first-party subdomain that CNAMEs to a vendor', () => {
    const m = item(first, 'metrics.site.test', '/m.gif');
    assert.equal(m.party, 'third');
    assert.equal(m.cloaked, true);
    assert.equal(m.vendor, 'ExampleCloaked');
    assert.deepEqual(m.cname, ['edge.cname-vendor.test']);
  });

  test('JSON validates against the schema and two scans are identical apart from timestamps', () => {
    assert.deepEqual(validateReport(first), []);
    assert.deepEqual(validateReport(second), []);
    const strip = (r: Report) => toJson({ ...r, scan: { ...r.scan, scannedAt: '' } });
    assert.equal(strip(second), strip(first));
  });
});

describe('private-address guard (--block-private)', () => {
  let guarded: Scanner;

  before(() => {
    guarded = new Scanner(baseOptions({
      consent: 'none', interact: false, settleMs: 0, timeoutMs: 30000, dnsCheck: false, blockPrivate: true,
      // The fixture lives on 127.0.0.1; let only its *.test names through so the guard can be exercised.
      chromiumArgs: [],
      guardOptions: {
        resolve: async (host) => (host.endsWith('.test') ? ['127.0.0.1'] : []),
        allowHost: (host) => host.endsWith('.test'),
      },
    }));
  });

  after(async () => {
    await guarded?.close();
  });

  test('navigation to a loopback address is refused', async () => {
    const r = await guarded.scan(`http://127.0.0.1:${fx.port}/`);
    assert.ok(r.blocked.some((b) => b.url.includes('127.0.0.1') && /loopback/.test(b.reason)), JSON.stringify(r.blocked));
    assert.equal(r.items.filter((i) => i.party === 'third').length, 0);
  });

  test('navigation to the cloud metadata address is refused', async () => {
    const r = await guarded.scan('http://169.254.169.254/latest/meta-data/');
    assert.ok(r.blocked.some((b) => b.url.includes('169.254.169.254') && /link-local/.test(b.reason)), JSON.stringify(r.blocked));
  });

  test('redirects to private and metadata addresses are refused', async () => {
    const toLoopback = await guarded.scan(`${fx.origin('site.test')}/redirect-private`);
    assert.ok(toLoopback.blocked.some((b) => b.url.startsWith('http://127.0.0.1')), JSON.stringify(toLoopback.blocked));
    const toMetadata = await guarded.scan(`${fx.origin('site.test')}/redirect-metadata`);
    assert.ok(toMetadata.blocked.some((b) => b.url.includes('169.254.169.254')), JSON.stringify(toMetadata.blocked));
  });

  test('allowed traffic, WebSockets included, still flows through the guard', async () => {
    const r = await guarded.scan(`${fx.origin('site.test')}/`);
    assert.deepEqual(r.blocked, []);
    assert.ok(r.items.some((i) => i.kind === 'websocket'));
    assert.ok(r.items.some((i) => i.url.endsWith('/pixel.js')));
  });
});
