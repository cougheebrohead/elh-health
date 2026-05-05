-- ELH Health — sales-demo org extensions.
--
-- The onboarding wizard scrapes a prospect's website, stands up a
-- branded org, and hands sales a private preview URL. These columns
-- mark such orgs, gate access, and let us auto-prune stale ones.
--
-- Why is_demo lives on orgs (not a separate table): the rest of the
-- platform — RLS, dashboards, member views — already keys off org_id.
-- Reusing the same row means a demo IS a real, fully-rendered tenant
-- (which is the whole point) — we just flag it so it never accidentally
-- gets billed, indexed, or shown in production rollups.

alter table orgs add column if not exists is_demo            boolean      not null default false;
alter table orgs add column if not exists demo_password_hash text;
alter table orgs add column if not exists demo_expires_at    timestamptz;
alter table orgs add column if not exists created_via        text         not null default 'manual';
alter table orgs add column if not exists source_url         text;
alter table orgs add column if not exists scraped_brand      jsonb;
alter table orgs add column if not exists prospect_contact   text;        -- "Marcus Hale, COO" — for cover slide
alter table orgs add column if not exists sales_owner        text;        -- internal: which sales person owns this demo

-- Speed up demo-list queries in the admin pitch console
create index if not exists orgs_is_demo_idx on orgs (is_demo) where is_demo = true;
create index if not exists orgs_demo_expires_idx on orgs (demo_expires_at) where demo_expires_at is not null;
