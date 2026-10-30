// Finds and clicks a cookie-consent control: known CMP selectors first, then a
// button whose text reads like "Accept all" / "Reject all". Searches every frame,
// because several CMPs render their banner inside an iframe.
import type { Frame, Page } from 'playwright';
import type { ConsentResult } from './types.js';

type Choice = 'accept' | 'reject';

const CMP_SELECTORS: { name: string; accept: string[]; reject: string[] }[] = [
  { name: 'onetrust', accept: ['#onetrust-accept-btn-handler'], reject: ['#onetrust-reject-all-handler'] },
  {
    name: 'cookiebot',
    accept: ['#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll', '#CybotCookiebotDialogBodyButtonAccept'],
    reject: ['#CybotCookiebotDialogBodyButtonDecline'],
  },
  { name: 'didomi', accept: ['#didomi-notice-agree-button'], reject: ['#didomi-notice-disagree-button'] },
  { name: 'trustarc', accept: ['#truste-consent-button'], reject: ['#truste-consent-required'] },
  {
    name: 'quantcast',
    accept: ['.qc-cmp2-summary-buttons button[mode="primary"]'],
    reject: ['.qc-cmp2-summary-buttons button[mode="secondary"]'],
  },
  { name: 'usercentrics', accept: ['[data-testid="uc-accept-all-button"]'], reject: ['[data-testid="uc-deny-all-button"]'] },
  { name: 'sourcepoint', accept: ['button.sp_choice_type_11'], reject: ['button.sp_choice_type_13'] },
];

const TEXT_PATTERNS: Record<Choice, RegExp> = {
  accept: /^\s*(accept( all)?( cookies)?|allow all( cookies)?|i accept|agree( to all)?|i agree|accept & close|got it)\s*$/i,
  reject: /^\s*(reject( all)?( cookies)?|decline( all)?|refuse( all)?|deny( all)?|only (necessary|essential)( cookies)?|necessary cookies only)\s*$/i,
};

async function tryClick(frame: Frame, selector: string, beforeClick: () => void): Promise<boolean> {
  try {
    const loc = frame.locator(selector).first();
    if ((await loc.count()) === 0 || !(await loc.isVisible())) return false;
    beforeClick();
    await loc.click({ timeout: 3000 });
    return true;
  } catch {
    return false;
  }
}

/** `beforeClick` runs just before the click, so requests the click triggers are labelled as post-consent. */
export async function handleConsent(page: Page, choice: Choice, beforeClick: () => void): Promise<ConsentResult> {
  const frames = page.frames();
  for (const cmp of CMP_SELECTORS) {
    for (const frame of frames) {
      for (const sel of cmp[choice]) {
        if (await tryClick(frame, sel, beforeClick)) return { method: `${cmp.name}-selector`, clicked: true, frameUrl: frame.url() };
      }
    }
  }
  for (const frame of frames) {
    try {
      const loc = frame.getByRole('button', { name: TEXT_PATTERNS[choice] });
      const n = await loc.count();
      for (let i = 0; i < n; i++) {
        const btn = loc.nth(i);
        if (await btn.isVisible()) {
          beforeClick();
          await btn.click({ timeout: 3000 });
          return { method: 'text-match', clicked: true, frameUrl: frame.url() };
        }
      }
    } catch {
      // Detached frame or click intercepted: try the next frame.
    }
  }
  return { method: 'none-found', clicked: false, frameUrl: null };
}
