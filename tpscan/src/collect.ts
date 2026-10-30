// One browser pass: fresh context, navigate, consent, interact, settle, snapshot.
// Captures from three layers and leaves merging to build.ts:
//   1. Playwright events  - every request in every frame and worker
//   2. a CDP session      - who initiated each request
//   3. a DOM inventory    - script attributes (SRI), iframes, sensitivity signals
import { createHash } from 'node:crypto';
import type { Browser, BrowserContext, Frame, Page, Request } from 'playwright';
import { handleConsent } from './consent.js';
import type { DomIframe, DomScript, FrameKind, PassResult, Phase, RawInitiator, RawRequest } from './types.js';

export interface PassOptions {
  url: string;
  name: 'none' | 'accept' | 'reject';
  interact: boolean;
  settleMs: number;
  timeoutMs: number;
  userAgent?: string;
}

type CdpStack = { callFrames?: { url?: string }[]; parent?: CdpStack };
type CdpInitiator = { type: string; url?: string; stack?: CdpStack };

function stackTopUrl(stack: CdpStack | undefined): string | null {
  for (let s = stack; s; s = s.parent) {
    const hit = s.callFrames?.find((f) => f.url);
    if (hit?.url) return hit.url;
  }
  return null;
}

function toInitiator(init: CdpInitiator): RawInitiator {
  return { type: init.type, url: stackTopUrl(init.stack) ?? init.url ?? null };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, Math.max(0, ms)));

/** Resolves to `fallback` instead of hanging past `ms`. */
async function bounded<T>(p: Promise<T>, ms: number, fallback: T): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const t = new Promise<T>((resolve) => (timer = setTimeout(() => resolve(fallback), Math.max(0, ms))));
  try {
    return await Promise.race([p.catch(() => fallback), t]);
  } finally {
    clearTimeout(timer);
  }
}

function frameOf(req: Request, page: Page): { kind: FrameKind; frameUrl: string | null; workerUrl: string | null } {
  const sw = req.serviceWorker();
  if (sw) return { kind: 'service-worker', frameUrl: null, workerUrl: sw.url() };
  let frame: Frame;
  try {
    frame = req.frame();
  } catch {
    return { kind: 'worker', frameUrl: null, workerUrl: null };
  }
  // A subframe's own document is "loaded into" the frame that holds the <iframe>.
  const holder = req.isNavigationRequest() && frame !== page.mainFrame() ? frame.parentFrame() ?? frame : frame;
  return { kind: holder === page.mainFrame() ? 'top' : 'sub', frameUrl: holder.url() || null, workerUrl: null };
}

function domSnapshot(): { url: string; scripts: Omit<DomScript, 'frameUrl' | 'top'>[]; inline: string[]; iframes: Omit<DomIframe, 'parentUrl'>[] } {
  const scripts = Array.from(document.scripts);
  return {
    url: location.href,
    scripts: scripts.filter((s) => s.src).map((s) => ({
      src: s.src,
      integrity: s.getAttribute('integrity'),
      crossorigin: s.getAttribute('crossorigin'),
      type: s.getAttribute('type'),
      async: s.async,
      defer: s.defer,
    })),
    inline: scripts.filter((s) => !s.src).map((s) => s.textContent ?? ''),
    iframes: Array.from(document.querySelectorAll('iframe, frame')).map((f) => ({
      src: (f as HTMLIFrameElement).src,
      sandbox: f.hasAttribute('sandbox') ? f.getAttribute('sandbox') : null,
      allow: f.getAttribute('allow'),
    })),
  };
}

function pageSignals(): { sensitive: string[]; metaCsp: { content: string; reportOnly: boolean }[] } {
  const sensitive: string[] = [];
  if (document.querySelector('input[type="password" i]')) sensitive.push('password-field');
  if (document.querySelector('input[autocomplete^="cc-" i], input[autocomplete*=" cc-" i]')) sensitive.push('payment-field');
  if (document.querySelector('input[autocomplete="one-time-code" i]')) sensitive.push('one-time-code-field');
  const formText = (f: HTMLFormElement) => `${f.getAttribute('action') ?? ''} ${f.id} ${f.className} ${f.getAttribute('name') ?? ''}`;
  const forms = Array.from(document.forms);
  if (forms.some((f) => /log-?in|sign-?in|auth/i.test(formText(f)))) sensitive.push('login-form');
  if (forms.some((f) => /checkout|payment|billing/i.test(formText(f)))) sensitive.push('checkout-form');
  const metaCsp = Array.from(document.querySelectorAll('meta[http-equiv]'))
    .map((m) => ({ equiv: (m.getAttribute('http-equiv') ?? '').toLowerCase(), content: m.getAttribute('content') ?? '' }))
    .filter((m) => m.equiv === 'content-security-policy' || m.equiv === 'content-security-policy-report-only')
    .map((m) => ({ content: m.content, reportOnly: m.equiv.endsWith('report-only') }));
  return { sensitive, metaCsp };
}

async function interact(page: Page, deadline: number): Promise<void> {
  // Scroll to the bottom in viewport-sized steps so lazy loaders fire.
  for (let i = 0; i < 25 && Date.now() < deadline - 2000; i++) {
    const atBottom = await bounded(
      page.evaluate(() => {
        window.scrollBy(0, window.innerHeight);
        return window.scrollY + window.innerHeight >= document.documentElement.scrollHeight - 2;
      }),
      2000,
      true,
    );
    await sleep(300);
    if (atBottom) break;
  }
  // Focus (never fill) the first visible form field: some vendors load on focus.
  await bounded(
    page.locator('input:not([type="hidden"]):visible, textarea:visible, select:visible').first().focus({ timeout: 2000 }),
    2500,
    undefined,
  );
}

export async function runPass(browser: Browser, opts: PassOptions): Promise<PassResult> {
  const deadline = Date.now() + opts.timeoutMs;
  const remaining = () => deadline - Date.now();
  let phase: Phase = 'pre-consent';
  const afterPhase: Phase = opts.name === 'reject' ? 'post-reject' : 'post-accept';

  const result: PassResult = {
    name: opts.name,
    finalUrl: opts.url,
    requests: [],
    initiators: {},
    websockets: [],
    workers: [],
    scripts: [],
    inlineScripts: { count: 0, sha256: [] },
    iframes: [],
    cookies: [],
    headers: { csp: [], cspReportOnly: [], permissionsPolicy: null },
    metaCsp: [],
    sensitiveSignals: [],
    consent: { method: 'not-attempted', clicked: false, frameUrl: null },
    blocked: [],
    errors: [],
  };

  // A fresh context is a fresh, empty profile: no cookies, storage or cache from earlier passes.
  const context: BrowserContext = await browser.newContext({
    viewport: { width: 1366, height: 900 },
    locale: 'en-GB',
    serviceWorkers: 'allow',
    userAgent: opts.userAgent,
  });
  try {
    const page = await context.newPage();
    const byRequest = new Map<Request, RawRequest>();
    const wsInitiators = new Map<string, RawInitiator>();

    context.on('request', (req) => {
      const f = frameOf(req, page);
      let isMainNavigation = false;
      try {
        isMainNavigation = req.isNavigationRequest() && req.frame() === page.mainFrame();
      } catch {
        // Worker request: never a navigation.
      }
      const raw: RawRequest = {
        url: req.url(),
        method: req.method(),
        resourceType: req.resourceType(),
        frameKind: f.kind,
        frameUrl: f.frameUrl,
        workerUrl: f.workerUrl,
        isMainNavigation,
        status: null,
        contentType: null,
        size: null,
        failure: null,
        phase,
      };
      byRequest.set(req, raw);
      result.requests.push(raw);
    });
    context.on('response', async (res) => {
      const raw = byRequest.get(res.request());
      if (!raw) return;
      raw.status = res.status();
      raw.contentType = (res.headers()['content-type'] ?? '').split(';')[0].trim() || null;
      if (raw.isMainNavigation && res.status() < 300) {
        const [csp, ro, pp] = await Promise.all([
          res.headerValues('content-security-policy'),
          res.headerValues('content-security-policy-report-only'),
          res.headerValue('permissions-policy'),
        ]).catch(() => [[], [], null] as [string[], string[], null]);
        result.headers = { csp, cspReportOnly: ro, permissionsPolicy: pp };
      }
    });
    context.on('requestfinished', async (req) => {
      const raw = byRequest.get(req);
      if (!raw) return;
      try {
        raw.size = (await req.sizes()).responseBodySize;
      } catch {
        raw.size = null;
      }
    });
    context.on('requestfailed', (req) => {
      const raw = byRequest.get(req);
      if (raw) raw.failure = req.failure()?.errorText ?? 'failed';
    });
    context.on('serviceworker', (w) => result.workers.push({ url: w.url(), type: 'service-worker', phase }));
    page.on('worker', (w) => result.workers.push({ url: w.url(), type: 'worker', phase }));
    page.on('websocket', (ws) => result.websockets.push({ url: ws.url(), frameUrl: null, initiator: null, phase }));

    const attachCdp = async (target: Page | Frame) => {
      const cdp = await context.newCDPSession(target);
      cdp.on('Network.requestWillBeSent', (e: { request: { url: string }; initiator: CdpInitiator; redirectResponse?: unknown }) => {
        if (!result.initiators[e.request.url]) result.initiators[e.request.url] = toInitiator(e.initiator);
      });
      cdp.on('Network.webSocketCreated', (e: { url: string; initiator?: CdpInitiator }) => {
        if (e.initiator) wsInitiators.set(e.url, toInitiator(e.initiator));
      });
      await cdp.send('Network.enable');
    };
    await attachCdp(page);
    // Out-of-process iframes need their own session where Chromium gives them one.
    page.on('frameattached', (frame) => void attachCdp(frame).catch(() => {}));

    try {
      await page.goto(opts.url, { waitUntil: 'load', timeout: Math.max(1000, remaining() - 5000) });
    } catch (err) {
      result.errors.push(`navigation: ${(err as Error).message.split('\n')[0]}`);
    }
    // Many pages never go quiet (polling, open sockets), so network idle is best-effort.
    await bounded(page.waitForLoadState('networkidle', { timeout: Math.min(15000, Math.max(0, remaining() - 5000)) }), 16000, undefined);

    if (opts.name !== 'none' && remaining() > 5000) {
      result.consent = await bounded(
        handleConsent(page, opts.name, () => (phase = afterPhase)),
        Math.min(20000, remaining() - 4000),
        { method: 'timed-out', clicked: false, frameUrl: null },
      );
      if (result.consent.clicked) {
        await bounded(page.waitForLoadState('networkidle', { timeout: 5000 }), 6000, undefined);
      } else {
        phase = 'pre-consent';
      }
    }

    if (opts.interact && remaining() > 5000) await interact(page, deadline);
    await sleep(Math.min(opts.settleMs, remaining() - 4000));

    // ---- snapshot
    result.finalUrl = page.url();
    for (const ws of result.websockets) ws.initiator = wsInitiators.get(ws.url) ?? null;
    for (const frame of page.frames()) {
      const snap = await bounded(frame.evaluate(domSnapshot), 3000, null);
      if (!snap) continue;
      const top = frame === page.mainFrame();
      for (const s of snap.scripts) result.scripts.push({ ...s, frameUrl: snap.url, top });
      for (const i of snap.iframes) result.iframes.push({ ...i, parentUrl: snap.url });
      if (top) {
        result.inlineScripts = {
          count: snap.inline.length,
          sha256: snap.inline.map((t) => createHash('sha256').update(t).digest('hex')).sort(),
        };
      }
    }
    const signals = await bounded(page.mainFrame().evaluate(pageSignals), 3000, { sensitive: [], metaCsp: [] });
    result.sensitiveSignals = signals.sensitive;
    result.metaCsp = signals.metaCsp;
    for (const sw of context.serviceWorkers()) {
      if (!result.workers.some((w) => w.url === sw.url())) result.workers.push({ url: sw.url(), type: 'service-worker', phase });
    }
    result.cookies = (await bounded(context.cookies(), 3000, [])).map((c) => ({
      name: c.name,
      domain: c.domain,
      sameSite: c.sameSite,
      secure: c.secure,
      httpOnly: c.httpOnly,
    }));
  } finally {
    // Cookies, storage and response bodies go with the context.
    await bounded(context.close(), 5000, undefined);
  }
  return result;
}
