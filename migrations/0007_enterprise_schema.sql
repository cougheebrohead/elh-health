-- ELH Health v2 — enterprise extensions for the buyer-demo platform.
--
-- Adds:
--   • regions          (between org and site for multi-region chains)
--   • programs         (workout + nutrition + content campaigns)
--   • content_items    (educational drops trainers can assign)
--   • schedule_sessions (1:1 + group sessions)
--   • wearable_connections + lab_results
--   • progress_photos (member self-serve)
--   • trainer_notes (private to trainer)
--   • saved_views (per-user analytical bookmarks)
--   • api_keys + webhook_subscriptions + webhook_deliveries
--   • sales_admins + impersonation_log + crm_leads
--   • consent_log (GDPR/CCPA granular consent)
--   • engagement_score (materialised per-member rollup)
--   • demo_leads
--   • messages (org-internal; mirrors CoachHQ shape)
--
-- Every PHI column lives behind RLS via app.org_id GUC.

-- ─── regions ──────────────────────────────────────────────────────
create table if not exists regions (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    slug            text not null,
    name            text not null,
    manager_user_id uuid references users(id) on delete set null,
    created_at      timestamptz not null default now(),
    unique (org_id, slug)
);
create index if not exists regions_org_idx on regions (org_id);

-- Add region_id to sites
alter table sites add column if not exists region_id uuid references regions(id) on delete set null;
create index if not exists sites_region_idx on sites (region_id) where region_id is not null;

-- Extend role enum to allow region_manager + sales_admin (postgres
-- doesn't expand check constraints in place — drop+re-add).
alter table users drop constraint if exists users_role_check;
alter table users add constraint users_role_check check (
    role in ('org_admin','region_manager','site_admin','trainer','member','sales_admin')
);

-- ─── programs (the campaigns + templates layer) ──────────────────
create table if not exists programs (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    site_id         uuid references sites(id) on delete set null,
    created_by      uuid references users(id) on delete set null,
    name            text not null,
    slug            text not null,
    program_type    text not null check (program_type in ('campaign','workout_template','nutrition_template','combined')),
    duration_days   int default 28,
    description     text,
    nutrition_json  jsonb default '{}'::jsonb,    -- {calories, protein, carbs, fat, water_l}
    workouts_json   jsonb default '[]'::jsonb,    -- [{day, name, exercises:[{name,sets,reps,rpe}]}]
    content_ids     uuid[] default '{}',
    target_segment  text,                          -- 'glp1', 'postpartum', 'pre-diabetes', 'general'
    is_org_wide     boolean default false,
    is_archived     boolean default false,
    created_at      timestamptz not null default now(),
    updated_at      timestamptz not null default now(),
    unique (org_id, slug)
);
create index if not exists programs_org_type_idx on programs (org_id, program_type) where not is_archived;

create table if not exists program_enrollments (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    program_id      uuid not null references programs(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    assigned_by     uuid references users(id) on delete set null,
    started_at      date not null default current_date,
    ends_at         date,
    status          text not null default 'active' check (status in ('active','completed','dropped','paused')),
    adherence_pct   int,                           -- 0..100, computed nightly
    created_at      timestamptz not null default now(),
    unique (program_id, member_id, started_at)
);
create index if not exists program_enrollments_member_idx on program_enrollments (member_id, status);
create index if not exists program_enrollments_program_idx on program_enrollments (program_id, status);

create table if not exists program_outcomes (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    enrollment_id   uuid not null references program_enrollments(id) on delete cascade,
    metric          text not null,                 -- 'weight_kg','bmi','hba1c','ldl','sbp','dbp','vo2max','adherence'
    value_start     numeric(8,2),
    value_end       numeric(8,2),
    delta           numeric(8,2),
    captured_at     timestamptz not null default now()
);
create index if not exists program_outcomes_enrollment_idx on program_outcomes (enrollment_id, metric);

-- ─── content (educational drops) ─────────────────────────────────
create table if not exists content_items (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    title           text not null,
    body_md         text,                          -- markdown article body
    media_url       text,
    media_type      text check (media_type in ('article','video','pdf','image','podcast')),
    duration_min    int,
    tags            text[] default '{}',
    is_published    boolean default true,
    created_at      timestamptz not null default now()
);

-- ─── schedule (1:1 sessions, classes) ────────────────────────────
create table if not exists schedule_sessions (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    site_id         uuid references sites(id) on delete set null,
    trainer_id      uuid not null references users(id) on delete cascade,
    member_id       uuid references users(id) on delete cascade,   -- null = group class
    title           text,
    location        text,                          -- 'in-person', 'zoom://...', 'meet.google.com/...'
    starts_at       timestamptz not null,
    ends_at         timestamptz not null,
    status          text not null default 'scheduled'
        check (status in ('scheduled','completed','cancelled','no_show')),
    notes           text,
    created_at      timestamptz not null default now()
);
create index if not exists schedule_sessions_trainer_starts_idx on schedule_sessions (trainer_id, starts_at);
create index if not exists schedule_sessions_member_starts_idx on schedule_sessions (member_id, starts_at) where member_id is not null;

-- ─── wearables (token storage, encrypted at rest by Supabase) ────
create table if not exists wearable_connections (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    provider        text not null check (provider in ('apple_health','whoop','oura','garmin','fitbit','withings','dexcom','libre')),
    external_id     text,                          -- provider's user id
    access_token_enc text,                         -- pgsodium-encrypted on insert (cryptography enabled in app)
    refresh_token_enc text,
    expires_at      timestamptz,
    last_sync_at    timestamptz,
    last_sync_status text,                         -- 'ok','token_expired','rate_limit','disconnected'
    scopes          text[],
    is_active       boolean default true,
    created_at      timestamptz not null default now(),
    unique (member_id, provider)
);

create table if not exists wearable_samples (
    id              bigserial primary key,
    org_id          uuid not null references orgs(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    provider        text not null,
    sample_type     text not null,                 -- 'sleep','hrv','rhr','steps','workout','activity'
    started_at      timestamptz not null,
    ended_at        timestamptz,
    value_json      jsonb not null
);
create index if not exists wearable_samples_member_time_idx on wearable_samples (member_id, started_at desc);

-- ─── lab results (Quest, LabCorp, manual upload) ─────────────────
create table if not exists lab_results (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    panel_name      text not null,                 -- 'Lipid Panel','HbA1c','Comprehensive Metabolic'
    drawn_at        date not null,
    provider        text default 'manual',         -- 'quest','labcorp','manual','epic_fhir','cerner_fhir'
    results_json    jsonb not null,                -- [{marker,value,unit,low,high,status}]
    raw_pdf_url     text,
    created_at      timestamptz not null default now()
);
create index if not exists lab_results_member_drawn_idx on lab_results (member_id, drawn_at desc);

-- ─── progress photos ─────────────────────────────────────────────
create table if not exists progress_photos (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    photo_url       text not null,
    angle           text check (angle in ('front','side','back','other')),
    taken_at        timestamptz not null default now(),
    weight_kg       numeric(6,2)
);
create index if not exists progress_photos_member_taken_idx on progress_photos (member_id, taken_at desc);

-- ─── trainer notes (private to trainer + org admins) ─────────────
create table if not exists trainer_notes (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    trainer_id      uuid not null references users(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    body            text not null,
    created_at      timestamptz not null default now()
);
create index if not exists trainer_notes_member_idx on trainer_notes (member_id, created_at desc);

-- ─── messages (trainer ↔ member thread) ──────────────────────────
create table if not exists messages (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    trainer_id      uuid not null references users(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    sender_id       uuid not null references users(id) on delete cascade,
    body            text not null,
    sent_at         timestamptz not null default now(),
    read_at         timestamptz,
    is_nudge        boolean default false,
    attachment_url  text
);
create index if not exists messages_thread_idx on messages (trainer_id, member_id, sent_at desc);

-- ─── saved views (per-user filter/sort presets) ──────────────────
create table if not exists saved_views (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    user_id         uuid not null references users(id) on delete cascade,
    surface         text not null,                 -- 'roster','clubs','at_risk', etc.
    name            text not null,
    config_json     jsonb not null,
    is_shared       boolean default false,
    created_at      timestamptz not null default now()
);

-- ─── api keys + webhooks (Brand tier) ────────────────────────────
create table if not exists api_keys (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    name            text not null,
    key_prefix      text not null,                 -- 'vsk_live_' + 6 visible chars
    key_hash        text not null,                 -- sha256 of the secret
    scopes          text[] default '{members:read}',
    last_used_at    timestamptz,
    revoked_at      timestamptz,
    created_at      timestamptz not null default now()
);
create index if not exists api_keys_org_idx on api_keys (org_id) where revoked_at is null;

create table if not exists webhook_subscriptions (
    id              uuid primary key default gen_random_uuid(),
    org_id          uuid not null references orgs(id) on delete cascade,
    url             text not null,
    secret_hash     text not null,                 -- HMAC signing secret hash
    events          text[] not null,
    is_active       boolean default true,
    last_delivery_at timestamptz,
    failure_count   int default 0,
    created_at      timestamptz not null default now()
);

create table if not exists webhook_deliveries (
    id              bigserial primary key,
    org_id          uuid not null references orgs(id) on delete cascade,
    subscription_id uuid not null references webhook_subscriptions(id) on delete cascade,
    event_type      text not null,
    payload_json    jsonb not null,
    response_code   int,
    response_body   text,
    delivered_at    timestamptz default now()
);
create index if not exists webhook_deliveries_sub_idx on webhook_deliveries (subscription_id, delivered_at desc);

-- ─── sales-side super-admin ──────────────────────────────────────
-- These are NOT scoped to a single org. RLS skipped here because the
-- SECURITY DEFINER RPC enforces that only role='sales_admin' can read.
create table if not exists sales_admins (
    id              uuid primary key default gen_random_uuid(),
    email           text not null unique,
    name            text not null,
    password_hash   text not null,
    is_active       boolean default true,
    last_login_at   timestamptz,
    created_at      timestamptz not null default now()
);

create table if not exists impersonation_log (
    id              bigserial primary key,
    sales_admin_id  uuid not null references sales_admins(id) on delete cascade,
    org_id          uuid not null references orgs(id) on delete cascade,
    target_user_id  uuid references users(id) on delete set null,
    reason          text,
    started_at      timestamptz default now(),
    ended_at        timestamptz
);
create index if not exists impersonation_log_admin_idx on impersonation_log (sales_admin_id, started_at desc);

create table if not exists crm_leads (
    id              uuid primary key default gen_random_uuid(),
    company_name    text not null,
    contact_name    text,
    contact_email   text,
    members_estimate int,
    notes           text,
    status          text default 'new'
        check (status in ('new','demo_scheduled','negotiating','won','lost','cold')),
    next_action_at  date,
    won_org_id      uuid references orgs(id),
    arr_usd         numeric(12,2),
    created_at      timestamptz default now(),
    updated_at      timestamptz default now()
);

-- ─── consent log ─────────────────────────────────────────────────
create table if not exists consent_log (
    id              bigserial primary key,
    org_id          uuid not null references orgs(id) on delete cascade,
    member_id       uuid not null references users(id) on delete cascade,
    consent_type    text not null,                 -- 'research','ai_training','marketing','data_share'
    granted         boolean not null,
    captured_at     timestamptz default now(),
    ip_hash         text
);
create index if not exists consent_log_member_idx on consent_log (member_id, consent_type);

-- ─── engagement_score (materialised, refreshed nightly) ──────────
create table if not exists engagement_score (
    member_id       uuid primary key references users(id) on delete cascade,
    org_id          uuid not null references orgs(id) on delete cascade,
    score           int not null check (score between 0 and 100),
    components_json jsonb not null,                -- {meals:int, workouts:int, logins:int, msgs:int}
    risk_tier       text not null check (risk_tier in ('crushing','on_track','slipping','ghosting')),
    last_login_at   timestamptz,
    days_active_30  int default 0,
    computed_at     timestamptz default now()
);
create index if not exists engagement_score_org_tier_idx on engagement_score (org_id, risk_tier);

-- ─── demo_leads (apex-scope, may pre-exist from server.py auto-DDL) ──
create table if not exists demo_leads (
    id              bigserial primary key,
    email           text not null,
    org_name        text,
    note            text,
    ip_hash         text,
    created_at      timestamptz default now()
);
alter table demo_leads add column if not exists status text default 'new';

-- ─── audit_chain_verifier_runs ───────────────────────────────────
create table if not exists audit_chain_verifier_runs (
    id              bigserial primary key,
    org_id          uuid references orgs(id) on delete cascade,
    n_rows          bigint not null,
    is_valid        boolean not null,
    broken_at_id    bigint,
    started_at      timestamptz default now(),
    finished_at     timestamptz
);

-- RLS — every PHI/business table
alter table regions             enable row level security;
alter table programs            enable row level security;
alter table program_enrollments enable row level security;
alter table program_outcomes    enable row level security;
alter table content_items       enable row level security;
alter table schedule_sessions   enable row level security;
alter table wearable_connections enable row level security;
alter table wearable_samples    enable row level security;
alter table lab_results         enable row level security;
alter table progress_photos     enable row level security;
alter table trainer_notes       enable row level security;
alter table messages            enable row level security;
alter table saved_views         enable row level security;
alter table api_keys            enable row level security;
alter table webhook_subscriptions enable row level security;
alter table webhook_deliveries  enable row level security;
alter table sales_admins        enable row level security;
alter table impersonation_log   enable row level security;
alter table crm_leads           enable row level security;
alter table consent_log         enable row level security;
alter table engagement_score    enable row level security;
alter table audit_chain_verifier_runs enable row level security;
-- demo_leads is apex-scoped (no org_id) so it intentionally has no RLS;
-- only service_role accesses it via the marketing endpoints.

-- Org-scoped policies (read+write for members of the org).
-- Sales-admin tables (sales_admins, impersonation_log, crm_leads) have
-- no policies → only SECURITY DEFINER service_role can touch them.
do $policy$
declare t text;
begin
  for t in select unnest(array[
      'regions','programs','program_enrollments','program_outcomes',
      'content_items','schedule_sessions','wearable_connections',
      'wearable_samples','lab_results','progress_photos','trainer_notes',
      'messages','saved_views','api_keys','webhook_subscriptions',
      'webhook_deliveries','consent_log','engagement_score',
      'audit_chain_verifier_runs'])
  loop
      execute format('drop policy if exists %I_org on %I', t, t);
      execute format(
          'create policy %I_org on %I for all using (org_id = app_current_org()) with check (org_id = app_current_org())',
          t, t
      );
  end loop;
end $policy$;
