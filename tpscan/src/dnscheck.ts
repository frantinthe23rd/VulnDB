// --dns-check: follows the CNAME chain of each first-party hostname, so a vendor
// served from metrics.example.com (CNAME -> vendor) is not mistaken for the site.
import { Resolver } from 'node:dns/promises';

export type CnameResolver = (host: string) => Promise<string[]>;

const resolver = new Resolver({ timeout: 3000, tries: 2 });
const systemCname: CnameResolver = (host) => resolver.resolveCname(host);

export async function cnameChains(hosts: string[], resolve: CnameResolver = systemCname): Promise<Map<string, string[]>> {
  const out = new Map<string, string[]>();
  await Promise.all(
    [...new Set(hosts)].map(async (host) => {
      const chain: string[] = [];
      let cur = host;
      for (let depth = 0; depth < 8; depth++) {
        let next: string[];
        try {
          next = await resolve(cur);
        } catch {
          break; // NXDOMAIN / no CNAME: end of chain
        }
        if (next.length === 0 || chain.includes(next[0].toLowerCase())) break;
        cur = next[0].toLowerCase().replace(/\.$/, '');
        chain.push(cur);
      }
      if (chain.length) out.set(host, chain);
    }),
  );
  return out;
}
