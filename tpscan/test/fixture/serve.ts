// Local fixture site for tpscan tests. One HTTP server answers for several
// hostnames (site.test, vendor-a.test, ...) by Host header; the browser maps
// every *.test name to 127.0.0.1 with --host-resolver-rules, so third parties
// are real cross-origin loads.
import { createHash } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { pathToFileURL } from 'node:url';

export interface Fixture {
  server: Server;
  port: number;
  origin(host: string): string;
  /** Chromium args that make the fixture hostnames resolve and site.test a secure context. */
  chromiumArgs: string[];
  close(): Promise<void>;
}

type Body = { type: string; body: string; headers?: Record<string, string> };

const SRI_SCRIPT = `window.__sriLoaded = true;\n`;
const SRI_HASH = 'sha384-' + createHash('sha384').update(SRI_SCRIPT).digest('base64');

function routes(port: number): Record<string, Record<string, Body>> {
  const o = (host: string) => `http://${host}:${port}`;
  const js = (body: string, headers?: Record<string, string>): Body => ({ type: 'application/javascript', body, headers });
  const html = (body: string, headers?: Record<string, string>): Body => ({ type: 'text/html', body, headers });
  return {
    'site.test': {
      '/': html(
        `<!doctype html><html><head>
<meta http-equiv="Content-Security-Policy" content="script-src * 'unsafe-inline'">
<title>Fixture login</title>
<link rel="stylesheet" href="${o('vendor-d.test')}/style.css">
<script src="/app.js"></script>
<script src="${o('vendor-a.test')}/sri.js" integrity="${SRI_HASH}" crossorigin="anonymous"></script>
<script src="${o('vendor-a.test')}/widget.js"></script>
<script src="${o('tags.vendor-c.test')}/gtm.js" async></script>
<script src="${o('vendor-a.test')}/selfremove.js"></script>
</head><body>
<div id="cookie-banner">We use cookies.
  <button id="fx-accept" onclick="acceptConsent()">Accept all</button>
  <button id="fx-reject" onclick="document.getElementById('cookie-banner').remove()">Reject all</button>
</div>
<form action="/login" method="post">
  <input name="user" autocomplete="username"><input type="password" name="pw">
</form>
<iframe sandbox="allow-scripts" src="${o('vendor-d.test')}/frame.html"></iframe>
<iframe src="${o('vendor-e.test')}/chat.html" allow="clipboard-write"></iframe>
<img src="${o('vendor-d.test')}/pixel.gif" alt="">
<img src="${o('metrics.site.test')}/m.gif" alt="">
<div style="height:8000px"></div>
<img loading="lazy" src="${o('vendor-d.test')}/lazy.gif" alt="">
<script>
  function acceptConsent() {
    document.getElementById('cookie-banner').remove();
    var s = document.createElement('script');
    s.src = '${o('vendor-f.test')}/ads.js';
    document.head.appendChild(s);
  }
  var ws = new WebSocket('ws://vendor-a.test:${port}/ws');
  if ('serviceWorker' in navigator) navigator.serviceWorker.register('/sw.js');
</script>
</body></html>`,
        {
          'Content-Security-Policy-Report-Only': "default-src 'self'; report-uri /csp-report",
          'Permissions-Policy': 'camera=(), geolocation=()',
        },
      ),
      '/app.js': js(`window.__app = 1;`),
      '/sw.js': js(`importScripts('${o('vendor-b.test')}/sw-lib.js');\nself.addEventListener('fetch', function () {});`),
      '/redirect-private': { type: 'text/plain', body: '', headers: { Location: 'http://127.0.0.1:' + port + '/' } },
      '/redirect-metadata': { type: 'text/plain', body: '', headers: { Location: 'http://169.254.169.254/latest/meta-data/' } },
    },
    // First-party name that --dns-check tests resolve as a CNAME to a vendor.
    'metrics.site.test': {
      '/m.gif': { type: 'image/gif', body: 'GIF89a' },
    },
    'vendor-a.test': {
      '/sri.js': js(SRI_SCRIPT, { 'Access-Control-Allow-Origin': '*' }),
      '/widget.js': js(`fetch('${o('vendor-a.test')}/rum', { method: 'POST', mode: 'no-cors', body: 'x' });`),
      '/selfremove.js': js(`document.currentScript.remove(); window.__removed = true;`),
      '/rum': { type: 'text/plain', body: 'ok' },
    },
    'tags.vendor-c.test': {
      '/gtm.js': js(`var s = document.createElement('script'); s.src = '${o('vendor-b.test')}/pixel.js'; document.head.appendChild(s);`),
    },
    'vendor-b.test': {
      '/pixel.js': js(`navigator.sendBeacon('${o('vendor-b.test')}/collect', 'event=view');`),
      '/sw-lib.js': js(`self.__swLib = true;`),
      '/collect': { type: 'text/plain', body: '' },
    },
    'vendor-d.test': {
      '/style.css': { type: 'text/css', body: 'body { margin: 0 }' },
      '/frame.html': html(`<!doctype html><p>sandboxed widget</p>`),
      '/pixel.gif': { type: 'image/gif', body: 'GIF89a' },
      '/lazy.gif': { type: 'image/gif', body: 'GIF89a' },
    },
    'vendor-e.test': {
      '/chat.html': html(`<!doctype html><p>chat</p><script src="/chat.js"></script>`),
      '/chat.js': js(`window.__chat = 1;`),
    },
    'vendor-f.test': {
      '/ads.js': js(`window.__ads = 1;`),
    },
  };
}

function handler(port: number) {
  const table = routes(port);
  return (req: IncomingMessage, res: ServerResponse) => {
    const host = (req.headers.host ?? '').split(':')[0];
    const path = (req.url ?? '/').split('?')[0];
    const entry = table[host]?.[path];
    if (!entry) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('not found');
      return;
    }
    const status = entry.headers?.Location ? 302 : 200;
    res.writeHead(status, { 'Content-Type': entry.type, 'Cache-Control': 'no-store', ...entry.headers });
    res.end(entry.body);
  };
}

export async function startFixture(): Promise<Fixture> {
  const server = createServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  server.on('request', handler(port));
  // Minimal WebSocket handshake: enough for the browser to open the socket.
  server.on('upgrade', (req, socket) => {
    const key = req.headers['sec-websocket-key'] ?? '';
    const accept = createHash('sha1').update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest('base64');
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    socket.on('error', () => {});
  });
  return {
    server,
    port,
    origin: (host) => `http://${host}:${port}`,
    chromiumArgs: [
      '--host-resolver-rules=MAP *.test 127.0.0.1, EXCLUDE localhost',
      `--unsafely-treat-insecure-origin-as-secure=http://site.test:${port}`,
    ],
    close: () =>
      new Promise((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const fx = await startFixture();
  console.log(`Fixture on ${fx.origin('site.test')}/`);
  console.log(`Scan with: TPSCAN_CHROMIUM_ARGS='${JSON.stringify(fx.chromiumArgs)}' node dist/src/cli.js ${fx.origin('site.test')}/`);
}
