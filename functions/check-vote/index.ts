// Supabase Edge Function (Deno). Call it right before inserting into `votes`.
// The insert itself still goes through RLS, which enforces one vote per
// category and the deadline; this function only adds the network limit.
//
// Secrets: VOTE_IP_SECRET (>= 32 random chars). Automatic: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY.
// Set TRUSTED_PROXY_HOPS to the number of proxies in front of the function (default 1).

import { createClient } from "jsr:@supabase/supabase-js@2";
import { checkVote, type IpLogStore } from "../../src/ip-guard.ts";

const cors = {
  "Access-Control-Allow-Origin": Deno.env.get("ALLOWED_ORIGIN") ?? "*",
  "Access-Control-Allow-Headers": "authorization, content-type, apikey, x-client-info",
};
const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } });

const db = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

const store: IpLogStore = {
  async countSince(ipHash, since) {
    const { count, error } = await db.from("vote_ip_log").select("id", { count: "exact", head: true })
      .eq("ip_hash", ipHash).gte("created_at", since.toISOString());
    if (error) throw error;
    return count ?? 0;
  },
  async record(ipHash, nomineeId) {
    const { error } = await db.from("vote_ip_log").insert({ ip_hash: ipHash, nominee_id: nomineeId });
    if (error) throw error;
  },
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: cors });
  try {
    const { nominee_id } = await req.json();
    if (typeof nominee_id !== "string") return json({ allowed: false, reason: "bad_request" }, 400);
    const result = await checkVote(req.headers, nominee_id, store, {
      secret: Deno.env.get("VOTE_IP_SECRET"),
      trustedHops: Number(Deno.env.get("TRUSTED_PROXY_HOPS") ?? 1),
    });
    return json(result, result.allowed ? 200 : 429);
  } catch (err) {
    console.error("[check-vote]", err);
    return json({ allowed: false, reason: "server_error" }, 500);
  }
});
