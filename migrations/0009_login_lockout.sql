-- ============================================================================
-- elh-health — per-account login lockout (Iron Dome I-2)
-- Migration: 0009_login_lockout.sql
--
-- Defends against distributed brute-force (botnets bypass per-IP limits).
-- Counts failed attempts per user; locks account after threshold.
-- Reset on successful login.
-- ============================================================================

create table if not exists user_login_failures (
  -- elh-health uses uuid on users.id
  user_id          uuid primary key references users(id) on delete cascade,
  fail_count       integer not null default 0,
  last_fail_at     timestamptz,
  locked_until     timestamptz,
  updated_at       timestamptz not null default now()
);

create index if not exists idx_user_login_failures_locked
  on user_login_failures (locked_until)
  where locked_until is not null;

-- RLS — service-role only. elh-health uses Supabase Auth's auth.uid()
-- elsewhere, but this table is purely server-side accounting; we don't
-- want clients reading their own failure counts (could aid attackers).
alter table user_login_failures enable row level security;
-- No permissive policies = deny by default for non-service-role.

-- updated_at trigger
create or replace function _bump_login_failures_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists tr_login_failures_updated_at on user_login_failures;
create trigger tr_login_failures_updated_at
  before update on user_login_failures
  for each row execute function _bump_login_failures_updated_at();
