// Scans one URL: one isolated browser pass per consent state, merged into one report.
import { chromium, type Browser, type LaunchOptions } from 'playwright';
import { buildReport } from './build.js';
import { runPass } from './collect.js';
import { cnameChains, type CnameResolver } from './dnscheck.js';
import { PartyClassifier, hostOf, registrableDomain } from './domains.js';
import { assertScannableUrl, GuardProxy, type GuardOptions } from './guard.js';
import { RuleSet } from './rules.js';
import type { ConsentMode, PassResult, Report } from './types.js';
import { VendorMap } from './vendors.js';

export interface ScanOptions {
  consent: ConsentMode;
  interact: boolean;
  settleMs: number;
  timeoutMs: number;
  firstParty: string[];
  dnsCheck: boolean;
  headful: boolean;
  blockPrivate: boolean;
  vendors: VendorMap;
  rules: RuleSet;
  /** Extra Chromium flags (tests use them to map fixture hostnames). */
  chromiumArgs?: string[];
  /** Test hooks. */
  guardOptions?: GuardOptions;
  cnameResolver?: CnameResolver;
  now?: () => Date;
}

export class Scanner {
  private browser: Browser | null = null;
  private guard: GuardProxy | null = null;
  private userAgent: string | undefined;

  constructor(private readonly opts: ScanOptions) {}

  private async start(): Promise<Browser> {
    if (this.browser) return this.browser;
    const args = [
      // Keep Chromium's own traffic (updates, sync, autofill, safe browsing) out of the scan.
      '--disable-background-networking',
      '--disable-component-update',
      '--disable-sync',
      '--disable-domain-reliability',
      '--disable-client-side-phishing-detection',
      '--disable-features=AutofillServerCommunication,OptimizationHints,MediaRouter,Translate',
      '--no-default-browser-check',
      '--no-first-run',
      ...(this.opts.chromiumArgs ?? []),
    ];
    const launch: LaunchOptions = { headless: !this.opts.headful, args };
    if (this.opts.blockPrivate) {
      this.guard = new GuardProxy(this.opts.guardOptions);
      // <-loopback> stops Chromium's implicit proxy bypass for localhost and 127.0.0.1.
      launch.proxy = { server: await this.guard.start(), bypass: '<-loopback>' };
      args.push('--force-webrtc-ip-handling-policy=disable_non_proxied_udp');
    }
    // Full Chromium rather than the headless shell: closer to a real visitor, and it
    // honours the flags service workers need on the test fixture.
    this.browser = await chromium.launch({ ...launch, channel: 'chromium' }).catch(() => chromium.launch(launch));
    const ctx = await this.browser.newContext();
    const page = await ctx.newPage();
    // Vendors that hide from "HeadlessChrome" would otherwise vanish from the scan.
    this.userAgent = (await page.evaluate(() => navigator.userAgent)).replace('HeadlessChrome', 'Chrome');
    await ctx.close();
    return this.browser;
  }

  async scan(url: string): Promise<Report> {
    assertScannableUrl(url);
    const browser = await this.start();
    const blockedBefore = this.guard?.blocked.length ?? 0;
    const names: PassResult['name'][] =
      this.opts.consent === 'both' ? ['accept', 'reject'] : this.opts.consent === 'none' ? ['none'] : [this.opts.consent];
    const scannedAt = (this.opts.now?.() ?? new Date()).toISOString().replace(/\.\d{3}Z$/, 'Z');

    const passes: PassResult[] = [];
    for (const name of names) {
      passes.push(await runPass(browser, {
        url, name, interact: this.opts.interact, settleMs: this.opts.settleMs,
        timeoutMs: this.opts.timeoutMs, userAgent: this.userAgent,
      }));
    }

    let cnames: Map<string, string[]> | undefined;
    if (this.opts.dnsCheck) {
      const finalUrl = passes.find((p) => p.finalUrl !== 'about:blank')?.finalUrl ?? url;
      const parties = new PartyClassifier(registrableDomain(finalUrl), this.opts.firstParty);
      const hosts = passes.flatMap((p) => p.requests.map((r) => hostOf(r.url))).filter((h) => h && parties.classify(h) !== 'third');
      cnames = await cnameChains(hosts, this.opts.cnameResolver);
    }

    return buildReport(passes, {
      url, scannedAt, consentMode: this.opts.consent, interact: this.opts.interact, settleMs: this.opts.settleMs,
      dnsCheck: this.opts.dnsCheck, blockPrivate: this.opts.blockPrivate, firstParty: this.opts.firstParty,
      cnames, blocked: this.guard?.blocked.slice(blockedBefore) ?? [],
    }, this.opts.vendors, this.opts.rules);
  }

  async close(): Promise<void> {
    await this.browser?.close().catch(() => {});
    await this.guard?.stop();
    this.browser = null;
    this.guard = null;
  }
}
