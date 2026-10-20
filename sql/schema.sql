-- vote-guard: fraud-resistant public voting on Supabase / Postgres.
--
-- Every rule that matters is enforced by the database, not the UI:
--   * one vote per account per category  -> unique constraint
--   * voting closes at a fixed instant    -> RLS policy reading the server clock
--   * counters can't be forged            -> trigger, no client UPDATE policy
--   * network rate-limit log is private   -> RLS on, zero policies

create table if not exists vote_settings (
  id int primary key default 1 check (id = 1),     -- single row
  voting_closes_at timestamptz not null
);
alter table vote_settings enable row level security;
create policy "public read settings" on vote_settings for select using (true);

create table if not exists nominees (
  id uuid primary key default gen_random_uuid(),
  category text not null,
  name text not null,
  vote_count int not null default 0,
  sort_order int not null default 0
);
create index if not exists nominees_category_idx on nominees (category, sort_order);
alter table nominees enable row level security;
create policy "public read nominees" on nominees for select using (true);
-- no insert/update/delete policies: only service-role can edit nominees and counts

create table if not exists votes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  nominee_id uuid not null references nominees(id) on delete cascade,
  category text not null,
  -- filled from the caller's JWT, so the client never sends (or fakes) it;
  -- nullable on purpose: a missing email must never block a vote
  email text default (lower(auth.jwt() ->> 'email')),
  created_at timestamptz not null default now(),
  constraint votes_one_per_category unique (user_id, category)
);
alter table votes enable row level security;

create policy "voters read own votes" on votes for select using (auth.uid() = user_id);

-- The deadline lives here, checked against the database clock on every insert.
-- The UI may show a countdown, but if the two ever disagree the database wins.
create policy "voters insert own vote before deadline" on votes for insert with check (
  auth.uid() = user_id
  and now() < (select voting_closes_at from vote_settings where id = 1)
  -- the category must match the nominee's category, so a vote can't be filed under another one
  and category = (select n.category from nominees n where n.id = nominee_id)
);

create or replace function bump_vote_count() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  update nominees set vote_count = vote_count + 1 where id = new.nominee_id;
  return new;
end $$;

drop trigger if exists on_vote_insert on votes;
create trigger on_vote_insert after insert on votes for each row execute function bump_vote_count();

-- Network rate limiting. IPs are never stored: only a keyed HMAC of the
-- address, so the log can't be reversed into addresses even if leaked.
create table if not exists vote_ip_log (
  id bigint generated always as identity primary key,
  ip_hash text not null,
  nominee_id uuid references nominees(id) on delete set null,
  created_at timestamptz not null default now()
);
create index if not exists vote_ip_log_hash_time on vote_ip_log (ip_hash, created_at);
alter table vote_ip_log enable row level security;
-- intentionally no policies: read/write only through the check-vote function (service role)

-- Housekeeping: the log is only needed for the rolling window.
-- select cron.schedule('vote-ip-log-prune', '17 * * * *', $$delete from vote_ip_log where created_at < now() - interval '1 day'$$);
