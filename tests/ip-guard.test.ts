import assert from "node:assert/strict";
import { test } from "node:test";
import { checkVote, clientIp, decide, hashIp, type IpLogStore } from "../src/ip-guard.ts";

const SECRET = "x".repeat(40);

test("client IP is taken from the right of X-Forwarded-For, not the spoofable left", () => {
  const h = new Headers({ "x-forwarded-for": "6.6.6.6, 203.0.113.9" }); // client-supplied, then our proxy's view
  assert.equal(clientIp(h), "203.0.113.9");
  assert.equal(clientIp(h, { trustedHops: 2 }), "6.6.6.6");
  assert.equal(clientIp(new Headers()), null);
  assert.equal(clientIp(new Headers({ "cf-connecting-ip": "198.51.100.4", "x-forwarded-for": "1.1.1.1" }), { preferHeader: "cf-connecting-ip" }), "198.51.100.4");
});

test("IP hashing is keyed, stable, and refuses a missing or short secret", async () => {
  const a = await hashIp("203.0.113.9", SECRET);
  assert.equal(a, await hashIp("203.0.113.9", SECRET));
  assert.notEqual(a, await hashIp("203.0.113.9", "y".repeat(40)));
  assert.match(a, /^[0-9a-f]{64}$/);
  await assert.rejects(hashIp("203.0.113.9", undefined));
  await assert.rejects(hashIp("203.0.113.9", "short"));
});

test("limit decision", () => {
  assert.deepEqual(decide(0, { maxVotes: 3, windowMinutes: 10 }), { allowed: true, remaining: 2 });
  assert.equal(decide(3, { maxVotes: 3, windowMinutes: 10 }).allowed, false);
});

function memoryStore() {
  const rows: Array<{ ipHash: string; at: number }> = [];
  let clock = Date.parse("2026-09-20T12:00:00Z");
  const store: IpLogStore = {
    async countSince(ipHash, since) { return rows.filter((r) => r.ipHash === ipHash && r.at >= since.getTime()).length; },
    async record(ipHash) { rows.push({ ipHash, at: clock }); },
  };
  return { store, rows, tick: (min: number) => (clock += min * 60_000), now: () => new Date(clock) };
}

test("a shared network is throttled inside the window and released after it", async () => {
  const m = memoryStore();
  const headers = new Headers({ "x-forwarded-for": "203.0.113.9" });
  const opts = () => ({ secret: SECRET, limit: { maxVotes: 3, windowMinutes: 10 }, now: m.now() });
  for (let i = 0; i < 3; i++) assert.equal((await checkVote(headers, "n1", m.store, opts())).allowed, true);
  assert.deepEqual(await checkVote(headers, "n1", m.store, opts()), { allowed: false, reason: "rate_limited" });
  assert.equal(m.rows.length, 3, "rejected attempts are not recorded");
  m.tick(11);
  assert.equal((await checkVote(headers, "n1", m.store, opts())).allowed, true);
});

test("spoofing the left-most X-Forwarded-For value does not reset the bucket", async () => {
  const m = memoryStore();
  const opts = { secret: SECRET, limit: { maxVotes: 2, windowMinutes: 10 }, now: m.now() };
  for (const fake of ["1.1.1.1", "2.2.2.2"]) {
    assert.equal((await checkVote(new Headers({ "x-forwarded-for": `${fake}, 203.0.113.9` }), "n1", m.store, opts)).allowed, true);
  }
  const third = await checkVote(new Headers({ "x-forwarded-for": "3.3.3.3, 203.0.113.9" }), "n1", m.store, opts);
  assert.equal(third.allowed, false);
});
