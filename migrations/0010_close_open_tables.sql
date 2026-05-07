-- ============================================================================
-- elh-health — close two RLS-disabled tables (Iron Dome I-3)
-- Migration: 0010_close_open_tables.sql
--
-- Audit found 2 tables with RLS disabled, reachable via the anon key:
--   demo_leads      — public demo-signup capture (email harvest risk)
--   sales_sessions  — internal sales-admin session tokens (impersonation
--                     pivot if anon could insert)
--
-- Lock both down. demo_leads keeps a narrow anon-INSERT for the public
-- demo form (mirrors quiz_sessions_anon_insert pattern). sales_sessions
-- becomes service-role-only — anon role gets nothing.
-- ============================================================================

-- ── demo_leads ────────────────────────────────────────────────────
alter table demo_leads enable row level security;

-- Allow public form to insert (existing flow). Validation in server.py.
drop policy if exists demo_leads_anon_insert on demo_leads;
create policy demo_leads_anon_insert on demo_leads
  for insert to anon
  with check (true);

-- No SELECT/UPDATE/DELETE policy => deny by default for non-service-role.
-- Admin paths use service-role and bypass RLS.

-- ── sales_sessions ────────────────────────────────────────────────
alter table sales_sessions enable row level security;
-- Service-role only. No permissive policies. Anon + authenticated
-- roles get nothing.

-- ── sales_admins ──────────────────────────────────────────────────
-- Already has RLS enabled but no policies (admin only via service-role).
-- Confirm + lock down. This table holds password_hash for sales staff,
-- so a misconfigured policy would leak credentials.
alter table sales_admins enable row level security;
-- No permissive policies; deny-by-default.

-- ── crm_leads ─────────────────────────────────────────────────────
-- Same — already deny-by-default. Confirm.
alter table crm_leads enable row level security;
-- No permissive policies; deny-by-default.

-- ── impersonation_log ─────────────────────────────────────────────
-- Append-only audit; service-role-only writes. Confirm.
alter table impersonation_log enable row level security;
