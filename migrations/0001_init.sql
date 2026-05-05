-- ELH Health — enterprise health platform schema.
--
-- Hierarchy: organization → site → trainer → member.
-- An "org" is a customer (24 Hour Fitness, F45 HQ, Equinox).
-- A "site" is a physical location or virtual cohort under that org.
-- Each site has its own coaches/trainers and members.
-- Members are individuals with PHI.
--
-- Designed for HIPAA: every PHI read is logged with a tamper-evident
-- audit chain, every table is RLS-locked by org_id, encryption at rest
-- via Supabase managed keys.

create extension if not exists pgcrypto;

-- ─── orgs (the enterprise tenant) ────────────────────────────────
create table orgs (
    id              uuid primary key default gen_random_uuid(),
    slug            text not null unique check (slug ~ '^[a-z0-9-]{2,60}$'),
    legal_name      text not null,
    display_name    text not null,
    logo_url        text,
    brand_primary   text not null default '#1F2A3A',
    brand_accent    text not null default '#0E7C66',
    plan            text not null default 'enterprise' check (plan in ('enterprise','enterprise_plus')),
    -- Compliance
    baa_signed_at   timestamptz,         -- BAA timestamp; required before any PHI write
    baa_signer      text,
    soc2_in_scope   boolean default true,
    -- SSO config (per-org)
    sso_provider    text,                -- 'okta','azuread','google','onelogin','generic-saml'
    sso_idp_entity_id  text,
    sso_idp_sso_url    text,
    sso_idp_cert_pem   text,
    sso_required    boolean default false,  -- if true, password login disabled for org users
    -- Limits
    max_sites       int default 1000,
    max_members     bigint default 1000000,
    -- Billing (invoiced — NOT Stripe Checkout for enterprise)
    invoicing_email text,
    contract_starts date,
    contract_ends   date,
    contract_term_months int,
    contract_value_usd numeric(12,2),
    --
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

-- ─── sites (locations within an org) ─────────────────────────────
create table sites (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    slug            text not null,
    name            text not null,
    timezone        text default 'America/New_York',
    address         text,
    member_seat_cap int default 5000,
    created_at      timestamptz not null default now(),
    unique (org_id, slug)
);
create index sites_org_idx on sites (org_id);

-- ─── users ────────────────────────────────────────────────────────
-- Roles:
--   org_admin    — full read/write across the org
--   site_admin   — full read/write within their site_id
--   trainer      — read/write members on their roster (their site)
--   member       — only their own data
-- An employee can be assigned multiple sites via user_sites; their default
-- site lives on users.site_id.
create table users (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    site_id         uuid references sites(id) on delete set null,
    email           text not null,
    password_hash   text,                  -- nullable when SSO-only
    sso_subject     text,                  -- sub claim from IdP
    role            text not null check (role in ('org_admin','site_admin','trainer','member')),
    name            text not null,
    employee_id     text,                  -- HR/SCIM external id
    is_active       boolean not null default true,
    last_login_at   timestamptz,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    unique (org_id, email),
    unique (org_id, sso_subject)
);
create index users_org_role_idx on users (org_id, role);
create index users_site_idx on users (site_id) where site_id is not null;

-- ─── user_sites (multi-site staff) ────────────────────────────────
create table user_sites (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    user_id         uuid not null references users(id) on delete cascade,
    site_id         uuid not null references sites(id) on delete cascade,
    role_at_site    text not null check (role_at_site in ('site_admin','trainer')),
    unique (user_id, site_id)
);

-- ─── trainer rosters ─────────────────────────────────────────────
create table trainer_members (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    site_id         uuid not null references sites(id) on delete cascade,
    trainer_id      uuid not null references users(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    started_at      timestamptz not null default now(),
    ended_at        timestamptz,
    status          text not null default 'active' check (status in ('active','paused','ended')),
    unique (trainer_id, member_id)
);
create index trainer_members_lookup_idx on trainer_members (org_id, trainer_id, status);

-- ─── PHI: member health profile ──────────────────────────────────
create table member_profiles (
    user_id         uuid primary key references users(id) on delete cascade,
    org_id          uuid not null references orgs(id) on delete cascade,
    site_id         uuid references sites(id) on delete set null,
    age             int check (age between 1 and 120),
    sex             text check (sex in ('male','female')),
    weight_kg       numeric(6,2),
    height_cm       numeric(6,2),
    activity        text default 'moderate',
    goal            text default 'maintain',
    conditions      text,
    allergies_json  jsonb default '[]'::jsonb,
    medications_json jsonb default '[]'::jsonb,
    last_period_iso date,
    cycle_length    int default 28,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now()
);

-- ─── PHI: glucose readings, BP, HR (member-owned, time-series) ────
create table biometrics (
    id              bigserial primary key,
    org_id          uuid not null references orgs(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    reading_at      timestamptz not null,
    glucose_mgdl    int,
    bp_systolic     int,
    bp_diastolic    int,
    heart_rate_bpm  int,
    weight_kg       numeric(6,2),
    source          text default 'manual'
);
create index biometrics_member_time_idx on biometrics (member_id, reading_at desc);

-- ─── PHI: meals (mirrored from FitApp via fitapp-core types) ─────
create table meals (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    eaten_at        timestamptz not null default now(),
    log_date        date not null,
    items_json      jsonb not null,
    totals_json     jsonb not null,
    source          text default 'manual'
);
create index meals_member_date_idx on meals (member_id, log_date desc);

-- ─── audit_log: tamper-evident chain ─────────────────────────────
-- Every PHI read must be inserted here. `digest` is sha256 of
-- (prev_digest || canonical-json-of-row); a tampered chain breaks at
-- the first altered row.
create table audit_log (
    id              bigserial primary key,
    org_id          uuid references orgs(id) on delete cascade,
    actor_id        uuid,
    actor_role      text,
    action          text not null,            -- 'read_profile','read_biometric','export_data','update_member',...
    resource_type   text not null,
    resource_id     text,
    member_subject  uuid,                     -- the member whose PHI was touched
    ip_hash         text,
    user_agent      text,
    details_json    jsonb,
    digest          text not null,
    prev_digest     text,
    created_at      timestamptz not null default now()
);
create index audit_log_org_time_idx on audit_log (org_id, created_at desc);
create index audit_log_member_idx on audit_log (member_subject) where member_subject is not null;

-- ─── sessions ────────────────────────────────────────────────────
create table sessions (
    token_hash      text primary key,
    user_id         uuid not null references users(id) on delete cascade,
    org_id          uuid not null references orgs(id) on delete cascade,
    issued_at       timestamptz not null default now(),
    expires_at      timestamptz not null,
    last_seen_at    timestamptz not null default now(),
    ip_hash         text,
    user_agent      text,
    sso_session_id  text                  -- correlates to IdP session for logout fanout
);
create index sessions_user_idx on sessions (user_id);

-- ─── SCIM provisioning state ─────────────────────────────────────
-- We don't store the SCIM secrets here; only the per-org config + last
-- sync cursor. Secrets live in env or KMS.
create table scim_config (
    org_id          uuid primary key references orgs(id) on delete cascade,
    enabled         boolean default false,
    bearer_token_hash text,                   -- sha256 of the SCIM bearer
    last_sync_at    timestamptz,
    last_sync_status text
);

-- ─── enable RLS on every table that holds PHI or org data ────────
alter table orgs              enable row level security;
alter table sites             enable row level security;
alter table users             enable row level security;
alter table user_sites        enable row level security;
alter table trainer_members   enable row level security;
alter table member_profiles   enable row level security;
alter table biometrics        enable row level security;
alter table meals             enable row level security;
alter table audit_log         enable row level security;
alter table sessions          enable row level security;
alter table scim_config       enable row level security;
