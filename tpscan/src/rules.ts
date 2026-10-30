// Loads the YAML rating rules and applies them to an item.
import { readFileSync } from 'node:fs';
import { parse } from 'yaml';
import { assetPath } from './paths.js';
import { RATING_ORDER, type Rating } from './types.js';

export interface RuleFacts {
  kind: string;
  party: string;
  frame: string;
  category: string;
  sri: boolean | null;
  sensitivePage: boolean;
  loadedByThirdPartyScript: boolean;
  weakIsolation: boolean;
}

interface Rule {
  id: string;
  rating: Exclude<Rating, 'none'>;
  fallback: boolean;
  when: Partial<Record<keyof RuleFacts, unknown>>;
  reasons: string[];
}

const FACT_KEYS = new Set<keyof RuleFacts>([
  'kind', 'party', 'frame', 'category', 'sri', 'sensitivePage', 'loadedByThirdPartyScript', 'weakIsolation',
]);

export class RuleSet {
  private constructor(readonly rules: Rule[]) {}

  static load(path = assetPath('rules.yaml')): RuleSet {
    const doc = parse(readFileSync(path, 'utf8')) as { rules?: unknown[] };
    if (!Array.isArray(doc?.rules)) throw new Error(`${path}: expected a top-level "rules" list`);
    const rules = doc.rules.map((raw, i) => {
      const r = raw as Partial<Rule>;
      const where = `${path}: rule ${r.id ?? i + 1}`;
      if (!r.id || !r.rating || !RATING_ORDER.includes(r.rating) || r.rating === ('none' as Rating)) {
        throw new Error(`${where}: needs an id and a rating of critical, high, medium or low`);
      }
      for (const key of Object.keys(r.when ?? {})) {
        if (!FACT_KEYS.has(key as keyof RuleFacts)) throw new Error(`${where}: unknown condition "${key}"`);
      }
      return { id: r.id, rating: r.rating, fallback: r.fallback === true, when: r.when ?? {}, reasons: r.reasons ?? [r.id] };
    });
    return new RuleSet(rules);
  }

  private static matches(rule: Rule, facts: RuleFacts): boolean {
    for (const [key, want] of Object.entries(rule.when)) {
      const have = facts[key as keyof RuleFacts];
      if (key === 'sri' && want === false) {
        if (have === true) return false;
      } else if (Array.isArray(want)) {
        if (!want.includes(have)) return false;
      } else if (want !== have) {
        return false;
      }
    }
    return true;
  }

  evaluate(facts: RuleFacts): { rating: Rating; reasons: string[]; ruleIds: string[] } {
    const matched = this.rules.filter((r) => !r.fallback && RuleSet.matches(r, facts));
    const hits = matched.length > 0 ? matched : this.rules.filter((r) => r.fallback && RuleSet.matches(r, facts)).slice(0, 1);
    if (hits.length === 0) return { rating: 'none', reasons: [], ruleIds: [] };
    const reasons: string[] = [];
    for (const r of hits) for (const reason of r.reasons) if (!reasons.includes(reason)) reasons.push(reason);
    return { rating: hits[0].rating, reasons, ruleIds: hits.map((r) => r.id) };
  }
}

export function maxRating(ratings: Rating[]): Rating {
  let best = RATING_ORDER.length - 1;
  for (const r of ratings) best = Math.min(best, RATING_ORDER.indexOf(r));
  return RATING_ORDER[best];
}
