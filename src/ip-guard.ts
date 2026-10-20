/**
 * Network-level rate limiting for public votes, runtime-agnostic (Web Crypto:
 * Deno, Node 20+, Workers).
 *
 * Two mistakes this module exists to avoid:
 * 1. Trusting the *first* `X-Forwarded-For` entry. The client writes that
 *    one: a voter can send any value and get a fresh rate-limit bucket per
 *    request. The address worth using is the one appended by *your* proxy,
 *    counted from the right.
 * 2. A hard-coded fallback salt. If the secret is missing, hashes become
 *    predictable and an IP can be recovered by brute force over the IPv4
 *    space. Fail closed instead.
 */

export interface RateLimitConfig {
  /** Votes allowed per network per window. Size it for a whole office voting every category. */
  maxVotes: number;
  windowMinutes: number;
}

export const DEFAULT_LIMIT: RateLimitConfig = { maxVotes: 45, windowMinutes: 10 };

/**
 * Client IP as seen by the last `trustedHops` proxies you control.
 * Prefer a header your edge sets itself (e.g. `cf-connecting-ip`) when available.
 */
export function clientIp(headers: Headers, opts: { trustedHops?: number; preferHeader?: string } = {}): string | null {
  if (opts.preferHeader) {
    const v = headers.get(opts.preferHeader)?.trim();
    if (v) return v;
  }
  const chain = (headers.get("x-forwarded-for") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const hops = opts.trustedHops ?? 1;
  if (chain.length < hops) return null;
  return chain[chain.length - hops] || null;
}

/** Keyed HMAC-SHA256 of the address, hex. Throws if the secret is missing or weak. */
export async function hashIp(ip: string, secret: string | undefined): Promise<string> {
  if (!secret || secret.length < 32) throw new Error("IP hash secret missing or shorter than 32 characters: refusing to hash with a guessable key");
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(ip)));
  return [...mac].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function windowStart(now: Date, cfg: RateLimitConfig = DEFAULT_LIMIT): Date {
  return new Date(now.getTime() - cfg.windowMinutes * 60_000);
}

export function decide(countInWindow: number, cfg: RateLimitConfig = DEFAULT_LIMIT): { allowed: boolean; remaining: number } {
  return { allowed: countInWindow < cfg.maxVotes, remaining: Math.max(0, cfg.maxVotes - countInWindow - 1) };
}

/** Storage port so the check works with Supabase, Redis, or an in-memory map in tests. */
export interface IpLogStore {
  countSince(ipHash: string, since: Date): Promise<number>;
  record(ipHash: string, nomineeId: string): Promise<void>;
}

export type VoteCheck =
  | { allowed: true; remaining: number }
  | { allowed: false; reason: "rate_limited" | "no_client_ip" };

/** Count, decide, and record the attempt only when it is allowed. */
export async function checkVote(
  headers: Headers,
  nomineeId: string,
  store: IpLogStore,
  opts: { secret: string | undefined; limit?: RateLimitConfig; trustedHops?: number; preferHeader?: string; now?: Date },
): Promise<VoteCheck> {
  const ip = clientIp(headers, opts);
  if (!ip) return { allowed: false, reason: "no_client_ip" };
  const ipHash = await hashIp(ip, opts.secret);
  const count = await store.countSince(ipHash, windowStart(opts.now ?? new Date(), opts.limit));
  const verdict = decide(count, opts.limit);
  if (!verdict.allowed) return { allowed: false, reason: "rate_limited" };
  await store.record(ipHash, nomineeId);
  return { allowed: true, remaining: verdict.remaining };
}
