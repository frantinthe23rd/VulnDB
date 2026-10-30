# tpscan — third-party exposure scanner

Loads a URL in Chromium and reports every third-party service the page loads or talks to, each rated by
exposure: **if this vendor were compromised tomorrow, what could it do to this page's visitors?** It maps
attack surface. It does not detect whether any vendor is compromised.

Built after the 29 October 2026 Polymarket incident, where a compromised third-party monitoring script
drained about $2.7M from users. That attack, and the June 2026 one on the same platform, both used code the
site loaded but did not control.

v1 is passive and single-visit: public pages only, one normal page load per consent state, no crawling,
no logins, no form submission.

Reports are published on the VulnDB site's [exposure page](../exposure.html) (see [Publishing](#publishing-to-the-vulndb-site)).

## Quick start

```bash
cd tpscan
npm ci
npm run build
node dist/src/cli.js https://example.co.uk --out ./reports/example --format json,html,csv
```

Or in the container (preferred: the scanner runs untrusted JavaScript):

```bash
docker build -t tpscan tpscan
docker run --rm --cap-drop ALL --security-opt no-new-privileges -v "$PWD/out:/out" tpscan https://example.co.uk --out /out --block-private
```

Batch mode, with the site's own CDN counted as first party:

```bash
node dist/src/cli.js --urls sites.txt --consent both --first-party example-cdn.net
```

| Option | Default | Purpose |
|---|---|---|
| `<url>` / `--urls <file>` | required | One URL, or a file with one per line (`#` comments allowed) |
| `--out <dir>` | `./reports/<host>` | Where reports go. With `--urls`, one subdirectory per URL |
| `--format` | `json,html` | Any of `json`, `html`, `csv` |
| `--consent` | `both` | `none`, `accept`, `reject` or `both` (one pass per choice, then diffed) |
| `--interact` / `--no-interact` | on | Scroll to the bottom, focus the first form field, wait for lazy loaders |
| `--settle <ms>` | `10000` | Extra wait after network idle, for delayed tags |
| `--first-party <domains>` | none | Comma-separated domains the site owns; labelled `owned` |
| `--dns-check` | off | Resolve CNAMEs of first-party hosts to catch cloaked vendors |
| `--timeout <s>` | `60` | Hard cap per pass |
| `--headful` | off | Show the browser |
| `--block-private` | off | SSRF guard: refuse private, loopback, link-local and metadata addresses on every hop. Always on in the GitHub workflow |
| `--vendors <file>` | none | Extra vendor map (same shape as `assets/vendors.json`); repeatable; wins over the built-in map |
| `--tracker-radar <dir>` | none | Also read a local DuckDuckGo Tracker Radar checkout (see [Vendor data](#vendor-data)) |
| `--rules <file>` | `assets/rules.yaml` | Rating rules |

Exit codes: `0` all scans written, `1` a scan failed, `2` bad arguments.

## How a scan works

Each consent state gets its own isolated browser pass (a fresh, empty profile). All passes are merged by URL
before anything is classified or rated, so the consent diff falls out of the merged data.

1. Fresh browser context; navigate; wait for network idle (best-effort, capped at 15 s: many pages never go quiet).
2. Consent: known CMP buttons (OneTrust, Cookiebot, Didomi, TrustArc, Quantcast, Usercentrics, Sourcepoint) in every
   frame, then any button reading like "Accept all" / "Reject all". The method used is recorded, or `none-found`.
   Requests before the click are labelled `pre-consent`, after it `post-accept` / `post-reject`.
3. Interact: scroll to the bottom in steps, focus (never fill) the first form field, wait `--settle`.
4. Snapshot the DOM inventory, cookies and frames, then close the context. Cookies, storage and bodies go with it.

Three capture layers, merged by URL:

| Layer | Gives |
|---|---|
| Playwright events (`context.on('request')`, `response`, `requestfinished`, `websocket`, `worker`, `serviceworker`) | Every request from every frame, worker and service worker: URL, method, resource type, frame, status, content type, size |
| CDP `Network.requestWillBeSent` / `webSocketCreated` | The initiator: parser or script, and the script on top of the stack. This builds `page → tag manager → vendor → beacon` |
| DOM inventory (every frame) | Script `src`, `integrity`, `crossorigin`, `type`, `async`/`defer`; inline script count and SHA-256s; iframe `sandbox` and `allow`; meta CSP; sensitivity signals |

Where a layer can't supply a field it is `null`, never guessed. Two cases worth knowing:

- A script seen on the network but absent from the DOM was removed after running (`dynamic: true`); its SRI is
  `null`, which the rules treat as "no SRI" and the reason says it was unverifiable.
- When Chromium reports no initiator (a request in a freshly attached out-of-process frame can beat
  `Network.enable`), `loadedBy` is the document of the frame it loaded in and `initiatorType` stays `null`.

### Behaviours verified against Chromium 153 / Playwright 1.63

- `navigator.sendBeacon` requests have resource type `ping` (reported as kind `beacon`).
- Service-worker requests, including `importScripts`, are reported by `context.on('request')` with
  `request.serviceWorker()` set; `importScripts` fetches have resource type `other`, so tpscan reclassifies
  JavaScript fetched by a worker as `script`.
- Playwright's `route()` does **not** see redirect hops. That is why the SSRF guard is a proxy (below), not a route handler.
- The headless shell build ignores `--unsafely-treat-insecure-origin-as-secure`; full Chromium (`channel: 'chromium'`)
  honours it. tpscan uses full Chromium, which is also closer to a real visitor, and replaces `HeadlessChrome` in the user agent.

## Classification and rating

**First or third party.** Registrable domain (eTLD+1) from the Public Suffix List via `tldts`, private section
included: `shop.example.co.uk` is `example.co.uk`, and `alice.github.io` is not the same site as `bob.github.io`.
`--first-party` domains count as first party, labelled `owned`. With `--dns-check`, a first-party host whose CNAME
chain reaches a known vendor becomes third party with `cloaked: true`.

**Vendors.** Hostname, then each parent domain, looked up in `--vendors` files, then `assets/vendors.json`, then
Tracker Radar if given. Unmapped domains appear under their registrable domain as category `unknown`, never dropped.

Categories: `tag-manager`, `analytics`, `rum-performance`, `session-replay`, `advertising`, `ab-testing`,
`chat-support`, `payments`, `auth-sso`, `consent`, `cdn-library`, `fonts`, `social`, `unknown`.

**Item ratings** come from [`assets/rules.yaml`](assets/rules.yaml). The first matching rule sets the rating;
every matching rule adds its reasons. First-party and owned items are `none`.

| Rating | Rule |
|---|---|
| Critical | Third-party script in the top frame, no SRI, on a page with a password, payment or login field |
| High | Third-party script in the top frame without SRI · any tag manager · a script loaded by another third-party script · a third-party script in a service worker's `importScripts` |
| Medium | Third-party top-frame script with SRI · third-party iframe with no sandbox, `allow-scripts` + `allow-same-origin`, or powerful `allow` permissions · outbound data to a third party (fetch, XHR, beacon, WebSocket) · third-party web worker |
| Low | Everything else third party: sandboxed iframes, images, fonts, CSS, scripts inside third-party frames |

Modifiers shown beside the rating (they don't change it): `evergreen` (no version or hash in the URL),
`seen only after consent` (after accepting, but not before any choice or after rejecting), `removed from DOM`,
`injected dynamically`.

**Page level.** The page's rating is its highest item rating. Separately: CSP (header and `<meta>`, each policy
parsed per directive; report-only flagged; `*`, `https:`, `'unsafe-inline'` and `'unsafe-eval'` in `script-src`;
whether `connect-src` restricts where data can go), SRI coverage of top-frame third-party scripts,
Permissions-Policy, and third-party cookies.

## Output

`report.json` is the source of truth and validates against [`assets/report.schema.json`](assets/report.schema.json)
(draft 2020-12, checked with ajv on every scan). `report.html` is a single file with no external assets;
`report.csv` has one row per item for a risk register (cells starting `= + - @` are prefixed with `'`).

Ordering is deterministic (rating, then vendor, then URL; item ids follow that order), so two scans of an
unchanged page produce identical JSON apart from `scannedAt`.

Every report carries a `limitations` list, shown on the HTML report and site page:

- Server-side integrations are invisible.
- Dependencies bundled into the site's own JavaScript look first-party (the June 2026 pattern).
- Only the pages and states visited are covered.
- Loading varies by country, user agent, time and A/B bucket; some vendors hide from headless browsers.
- Point-in-time snapshot.
- Cloaked vendors look first-party unless `--dns-check` is on.
- Ratings are heuristics, not a measured risk score.

## Security

The scanner runs untrusted JavaScript from every site it visits.

- **Container.** `Dockerfile` builds on the official Playwright image and runs as `pwuser`. The workflow adds
  `--cap-drop ALL --security-opt no-new-privileges` and mounts only the URL list (read-only) and an output directory.
  No AWS credentials or repository files are inside the container.
- **SSRF guard (`--block-private`).** Chromium sends every connection through a local filtering proxy
  (`src/guard.ts`), including redirect hops, WebSockets and service-worker fetches, with Chromium's implicit
  loopback bypass turned off and WebRTC limited to proxied UDP. The proxy resolves each hostname itself, refuses
  the connection if any answer is private, loopback, link-local, CGNAT, multicast, reserved, unique-local or a
  cloud-metadata address (IPv4, IPv6 and IPv4-in-IPv6 forms), and then connects to the exact address it checked,
  so DNS rebinding between check and connect does not work. Refusals are listed in the report's `blocked` field.
- **Passive.** One page visit per pass. Consent buttons are clicked and one field is focused; nothing is typed or submitted.
- **Nothing sensitive kept.** Only reports are written. Cookie values are never recorded (name, domain and flags only).
- **Rendering.** The report renderer writes every value with `textContent`; report JSON embedded in HTML is escaped
  so it cannot close its `<script>` element.

Scan only sites you are entitled to assess, and check your organisation's policy before scanning third-party sites
from a corporate network.

## Vendor data

`assets/vendors.json` is a team-maintained map of about 160 common vendor domains. Edit it, or keep your own
overrides in a file passed with `--vendors`.

DuckDuckGo Tracker Radar is **not bundled**. Its data is published under CC BY-NC-SA 4.0 (non-commercial,
share-alike), which needs a decision before use here. To use it where the licence allows:

```bash
git clone --depth 1 https://github.com/duckduckgo/tracker-radar.git
node dist/src/cli.js https://example.co.uk --tracker-radar tracker-radar/domains
```

## Publishing to the VulnDB site

The site is static (S3 + CloudFront), so scans are run by GitHub Actions and published as files, not on demand
from the browser:

- `.github/workflows/tpscan.yml` runs the test suite on every change under `tpscan/`. On its weekly schedule
  (Mondays 06:23 UTC) or a manual run, it builds the image, scans `tpscan/sites.txt` (or the URLs given to the
  manual run) with `--block-private`, merges the reports with those already in `s3://<bucket>/exposure/`,
  rebuilds `exposure/index.json` with `tpscan-index`, uploads, and invalidates `/exposure/*`.
- `exposure.html` lists the published scans and renders a report with `assets/renderer.js` (deployed as
  `exposure-renderer.js` by `deploy.yml`). Its "Open a report file" button renders a local `report.json` in
  the browser without uploading it.

`sites.txt` ships empty: add the pages you're entitled to scan.

A browser-facing "scan any URL" form is deliberately not part of this: it needs a backend that runs the
container per request, behind the SSRF guard (milestone M5).

## Development

```bash
npm test          # build, then unit tests and the fixture acceptance tests (about 2 minutes)
npm run test:unit # no browser
npm run fixture   # serve the fixture site and print a scan command
```

The fixture (`test/fixture/serve.ts`) is one HTTP server answering for `site.test`, `vendor-a.test` … `vendor-f.test`;
Chromium maps `*.test` to `127.0.0.1` with `--host-resolver-rules`, so third parties are real cross-origin loads.
It has: a third-party script with and without SRI, a tag manager that injects a second vendor, a self-removing
script, a sandboxed and an unsandboxed iframe, a WebSocket, a `sendBeacon`, a service worker that `importScripts`
from another host, a CSP header (report-only) and a meta CSP, a password field, a consent banner that loads one
vendor only on accept, a lazy-loaded image, and a first-party host that `--dns-check` tests resolve to a vendor.

Tests that need extra Chromium flags pass them in `ScanOptions.chromiumArgs`; the CLI reads the same from the
`TPSCAN_CHROMIUM_ARGS` environment variable (a JSON array), which only the fixture workflow uses.

### Acceptance criteria

| Criterion | Status |
|---|---|
| Every fixture item has the correct kind, party, frame and `loadedBy` chain | Tested |
| SRI reported correctly with and without `integrity` | Tested |
| Registrable domain correct for `.co.uk`, `.com.au` and `github.io` | Tested |
| Post-accept pass shows the consent-gated vendor and the diff lists it | Tested |
| CSP parsed from header and meta; report-only flagged | Tested |
| Rating rules give the expected rating and reasons per fixture item | Tested |
| Navigation and redirects to private and metadata addresses blocked | Tested (with `--block-private`) |
| JSON validates against the schema; two scans identical apart from timestamps | Tested |
| A typical public news site completes in under 90 s per pass | Not yet measured: the build sandbox had no direct internet. The fixture takes about 20 s per pass, most of it the 15 s network-idle cap |

## Milestones

M1–M4 of the handoff are in place (capture, inventory, rating and reports, consent and coverage). M5, the web
UI, is the read-only exposure page on the VulnDB site; an on-demand scan form is not built.

v2 candidates: per-script hash baselining with change alerts, authenticated scans, same-site crawl to depth N,
fingerprinting known libraries inside first-party bundles.
