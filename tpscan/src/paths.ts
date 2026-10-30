// Locates files shipped with the package (rules, vendor map, report renderer, schema).
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

// Compiled code lives in dist/src/, so the package root is two levels up.
const ROOT = fileURLToPath(new URL('../../', import.meta.url));

export function assetPath(name: string): string {
  return `${ROOT}assets/${name}`;
}

export const TOOL_VERSION: string = (JSON.parse(readFileSync(`${ROOT}package.json`, 'utf8')) as { version: string }).version;
