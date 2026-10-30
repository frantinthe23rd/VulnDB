// SSRF guard. With --block-private, Chromium sends every connection through this
// local proxy: navigations, each redirect hop, subresources, WebSockets and
// service-worker fetches. The proxy resolves the hostname itself, refuses
// private, loopback, link-local and metadata addresses, and connects to the
// exact address it checked, so a DNS answer that changes between check and
// connect (rebinding) cannot slip through.
//
// Playwright's route() is not enough on its own: it does not see redirect hops.
import { lookup } from 'node:dns/promises';
import { createServer, request as httpRequest, type IncomingMessage, type Server } from 'node:http';
import { connect, isIP, type Socket } from 'node:net';
import type { AddressInfo } from 'node:net';
import type { Duplex } from 'node:stream';

const BLOCKED_HOSTNAMES = new Set(['localhost', 'metadata.google.internal', 'metadata', 'instance-data']);

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}

const V4_BLOCKS: [string, number, string][] = [
  ['0.0.0.0', 8, 'this network'],
  ['10.0.0.0', 8, 'private'],
  ['100.64.0.0', 10, 'carrier-grade NAT'],
  ['127.0.0.0', 8, 'loopback'],
  ['169.254.0.0', 16, 'link-local / cloud metadata'],
  ['172.16.0.0', 12, 'private'],
  ['192.0.0.0', 24, 'IETF protocol assignments'],
  ['192.0.2.0', 24, 'documentation'],
  ['192.88.99.0', 24, '6to4 relay'],
  ['192.168.0.0', 16, 'private'],
  ['198.18.0.0', 15, 'benchmarking'],
  ['198.51.100.0', 24, 'documentation'],
  ['203.0.113.0', 24, 'documentation'],
  ['224.0.0.0', 4, 'multicast'],
  ['240.0.0.0', 4, 'reserved'],
];

function expandV6(ip: string): number[] | null {
  let addr = ip.toLowerCase().split('%')[0];
  // Trailing dotted IPv4 (e.g. ::ffff:10.0.0.1) -> two hextets.
  const v4 = addr.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = v4ToInt(v4[1]);
    addr = addr.slice(0, -v4[1].length) + ((n >>> 16) & 0xffff).toString(16) + ':' + (n & 0xffff).toString(16);
  }
  const [head, tail] = addr.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : [];
  if (addr.includes('::')) {
    const fill = 8 - h.length - t.length;
    if (fill < 0) return null;
    return [...h, ...Array(fill).fill('0'), ...t].map((x) => parseInt(x, 16));
  }
  return h.length === 8 ? h.map((x) => parseInt(x, 16)) : null;
}

/** Returns why an address must not be contacted, or null if it is a public address. */
export function blockedAddressReason(ip: string): string | null {
  const family = isIP(ip);
  if (family === 4) {
    const n = v4ToInt(ip);
    for (const [base, bits, label] of V4_BLOCKS) {
      const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
      if ((n & mask) === (v4ToInt(base) & mask)) return `${label} address ${ip}`;
    }
    return null;
  }
  if (family === 6) {
    const h = expandV6(ip);
    if (!h) return `unparseable address ${ip}`;
    if (h.every((x) => x === 0)) return `unspecified address ${ip}`;
    if (h.slice(0, 7).every((x) => x === 0) && h[7] === 1) return `loopback address ${ip}`;
    // IPv4-mapped (::ffff:a.b.c.d), IPv4-compatible (::a.b.c.d) and NAT64 (64:ff9b::/96) embed an IPv4 address.
    const embedsV4 =
      (h.slice(0, 5).every((x) => x === 0) && (h[5] === 0xffff || h[5] === 0)) ||
      (h[0] === 0x64 && h[1] === 0xff9b && h.slice(2, 6).every((x) => x === 0));
    if (embedsV4) {
      const v4 = `${h[6] >> 8}.${h[6] & 0xff}.${h[7] >> 8}.${h[7] & 0xff}`;
      const inner = blockedAddressReason(v4);
      return inner ? `${inner} (inside ${ip})` : null;
    }
    if ((h[0] & 0xfe00) === 0xfc00) return `unique-local address ${ip}`;
    if ((h[0] & 0xffc0) === 0xfe80) return `link-local address ${ip}`;
    if ((h[0] & 0xff00) === 0xff00) return `multicast address ${ip}`;
    if (h[0] === 0x2001 && h[1] === 0x0db8) return `documentation address ${ip}`;
    if (h[0] === 0xfd00 && h[1] === 0x0ec2) return `cloud metadata address ${ip}`;
    return null;
  }
  return `not an IP address: ${ip}`;
}

/** A destination the guard refuses on policy (as opposed to one that simply doesn't resolve). */
export class BlockedError extends Error {}

export type Resolver = (host: string) => Promise<string[]>;

const systemResolver: Resolver = async (host) => (await lookup(host, { all: true, verbatim: true })).map((a) => a.address);

export interface GuardOptions {
  resolve?: Resolver;
  /** Test hook: hosts allowed even though they resolve to a blocked address. */
  allowHost?: (host: string) => boolean;
}

export class GuardProxy {
  readonly blocked: { url: string; reason: string }[] = [];
  private server: Server | null = null;
  private readonly sockets = new Set<Duplex>();
  private readonly resolve: Resolver;
  private readonly allowHost: (host: string) => boolean;

  constructor(opts: GuardOptions = {}) {
    this.resolve = opts.resolve ?? systemResolver;
    this.allowHost = opts.allowHost ?? (() => false);
  }

  /** Resolves and checks a host; returns the address to connect to, or throws with the reason. */
  async check(host: string): Promise<string> {
    const name = host.replace(/^\[|\]$/g, '').toLowerCase().replace(/\.$/, '');
    const allowed = this.allowHost(name);
    if (!allowed && (BLOCKED_HOSTNAMES.has(name) || name.endsWith('.localhost') || name.endsWith('.internal'))) {
      throw new BlockedError(`blocked hostname ${name}`);
    }
    const addrs = isIP(name) ? [name] : await this.resolve(name);
    if (addrs.length === 0) throw new Error(`no address for ${name}`);
    if (!allowed) {
      // Refuse if any answer is private: the browser could otherwise be steered to it.
      for (const a of addrs) {
        const reason = blockedAddressReason(a);
        if (reason) throw new BlockedError(reason);
      }
    }
    return addrs[0];
  }

  private refuse(url: string, err: unknown): void {
    if (err instanceof BlockedError) this.blocked.push({ url, reason: err.message });
  }

  async start(): Promise<string> {
    const server = createServer();
    this.server = server;
    server.on('connection', (s) => {
      this.sockets.add(s);
      s.on('close', () => this.sockets.delete(s));
    });

    // Plain http:// requests arrive in absolute form.
    server.on('request', async (req, res) => {
      let target: URL;
      try {
        target = new URL(req.url ?? '');
        if (target.protocol !== 'http:') throw new Error('unsupported scheme');
      } catch {
        res.writeHead(400).end();
        return;
      }
      let ip: string;
      try {
        ip = await this.check(target.hostname);
      } catch (err) {
        this.refuse(target.href, err);
        res.writeHead(403, { 'Content-Type': 'text/plain' }).end('blocked by tpscan guard');
        return;
      }
      const headers = { ...req.headers };
      delete headers['proxy-connection'];
      delete headers['proxy-authorization'];
      const upstream = httpRequest(
        { host: ip, port: Number(target.port || 80), method: req.method, path: target.pathname + target.search, headers, setHost: false },
        (up) => {
          res.writeHead(up.statusCode ?? 502, up.rawHeaders as unknown as Record<string, string>);
          up.pipe(res);
        },
      );
      upstream.on('error', () => res.headersSent ? res.destroy() : res.writeHead(502).end());
      req.pipe(upstream);
    });

    // https:// and wss:// (and ws:// in some Chromium versions) use CONNECT tunnels.
    server.on('connect', async (req: IncomingMessage, client: Duplex, head: Buffer) => {
      const [host, portStr] = splitHostPort(req.url ?? '');
      const port = Number(portStr || 443);
      let ip: string;
      try {
        ip = await this.check(host);
      } catch (err) {
        this.refuse(`${host}:${port}`, err);
        client.end('HTTP/1.1 403 Forbidden\r\n\r\n');
        return;
      }
      const upstream: Socket = connect(port, ip, () => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length) upstream.write(head);
        upstream.pipe(client);
        client.pipe(upstream);
      });
      this.sockets.add(upstream);
      upstream.on('close', () => this.sockets.delete(upstream));
      upstream.on('error', () => client.destroy());
      client.on('error', () => upstream.destroy());
    });

    // ws:// through a forward proxy as an absolute-form Upgrade request.
    server.on('upgrade', async (req: IncomingMessage, client: Duplex, head: Buffer) => {
      let target: URL;
      try {
        target = new URL(req.url ?? '');
      } catch {
        client.destroy();
        return;
      }
      let ip: string;
      try {
        ip = await this.check(target.hostname);
      } catch (err) {
        this.refuse(target.href, err);
        client.end('HTTP/1.1 403 Forbidden\r\n\r\n');
        return;
      }
      const upstream = connect(Number(target.port || 80), ip, () => {
        const lines = [`${req.method} ${target.pathname}${target.search} HTTP/1.1`];
        for (let i = 0; i < req.rawHeaders.length; i += 2) {
          if (!/^proxy-/i.test(req.rawHeaders[i])) lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
        }
        upstream.write(lines.join('\r\n') + '\r\n\r\n');
        if (head.length) upstream.write(head);
        upstream.pipe(client);
        client.pipe(upstream);
      });
      upstream.on('error', () => client.destroy());
      client.on('error', () => upstream.destroy());
    });

    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  }

  async stop(): Promise<void> {
    for (const s of this.sockets) s.destroy();
    if (this.server) await new Promise<void>((resolve) => this.server!.close(() => resolve()));
  }
}

function splitHostPort(hostPort: string): [string, string] {
  const m = hostPort.match(/^\[([^\]]+)\](?::(\d+))?$/) ?? hostPort.match(/^([^:]+)(?::(\d+))?$/);
  return m ? [m[1], m[2] ?? ''] : [hostPort, ''];
}

/** Checks the URL the user gave before any browser starts. */
export function assertScannableUrl(url: string): URL {
  const u = new URL(url);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`only http and https URLs can be scanned: ${url}`);
  if (u.username || u.password) throw new Error('URLs with credentials are refused');
  return u;
}
