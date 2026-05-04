-- Vitalstack RLS — second line of defense behind app-layer org gating.
-- Reads use app.org_id / app.user_id / app.user_role / app.site_id,
-- which the app's RPCs SET LOCAL before user SQL runs.

create or replace function app_current_org() returns uuid language plpgsql stable as $$
declare v text := current_setting('app.org_id', true);
begin if v is null or v='' then return null; end if; return v::uuid;
exception when others then return null; end; $$;

create or replace function app_current_user() returns uuid language plpgsql stable as $$
declare v text := current_setting('app.user_id', true);
begin if v is null or v='' then return null; end if; return v::uuid;
exception when others then return null; end; $$;

create or replace function app_current_role() returns text language plpgsql stable as $$
begin return coalesce(nullif(current_setting('app.user_role', true), ''), ''); end; $$;

create or replace function app_current_site() returns uuid language plpgsql stable as $$
declare v text := current_setting('app.site_id', true);
begin if v is null or v='' then return null; end if; return v::uuid;
exception when others then return null; end; $$;

-- ─── orgs ────────────────────────────────────────────────────────
create policy orgs_select on orgs for select using (id = app_current_org());
create policy orgs_update on orgs for update
  using (id = app_current_org() and app_current_role() = 'org_admin')
  with check (id = app_current_org() and app_current_role() = 'org_admin');

-- ─── sites ───────────────────────────────────────────────────────
create policy sites_select on sites for select
  using (org_id = app_current_org());
create policy sites_modify on sites for all
  using (org_id = app_current_org() and app_current_role() in ('org_admin','site_admin'))
  with check (org_id = app_current_org() and app_current_role() in ('org_admin','site_admin'));

-- ─── users ───────────────────────────────────────────────────────
-- org_admin    sees all org users
-- site_admin   sees users in their site (and themselves)
-- trainer      sees themselves + members on their roster
-- member       sees only themselves
create policy users_select on users for select
  using (
    org_id = app_current_org() and (
      app_current_role() = 'org_admin'
      or id = app_current_user()
      or (app_current_role() = 'site_admin' and site_id = app_current_site())
      or (app_current_role() = 'trainer' and exists (
        select 1 from trainer_members tm
        where tm.org_id = users.org_id
          and tm.trainer_id = app_current_user()
          and tm.member_id = users.id
      ))
    )
  );
create policy users_modify on users for all
  using (org_id = app_current_org() and app_current_role() in ('org_admin','site_admin'))
  with check (org_id = app_current_org() and app_current_role() in ('org_admin','site_admin'));

-- ─── user_sites & trainer_members ────────────────────────────────
create policy user_sites_select on user_sites for select
  using (org_id = app_current_org() and (
    app_current_role() in ('org_admin','site_admin') or user_id = app_current_user()
  ));
create policy user_sites_modify on user_sites for all
  using (org_id = app_current_org() and app_current_role() in ('org_admin','site_admin'))
  with check (org_id = app_current_org());

create policy trainer_members_select on trainer_members for select
  using (org_id = app_current_org() and (
    app_current_role() in ('org_admin','site_admin')
    or trainer_id = app_current_user()
    or member_id = app_current_user()
  ));
create policy trainer_members_modify on trainer_members for all
  using (org_id = app_current_org() and app_current_role() in ('org_admin','site_admin','trainer'))
  with check (org_id = app_current_org());

-- ─── PHI tables (member_profiles, biometrics, meals) ─────────────
create policy member_profiles_rw on member_profiles for all
  using (org_id = app_current_org() and (
    app_current_role() = 'org_admin'
    or user_id = app_current_user()
    or (app_current_role() = 'site_admin' and site_id = app_current_site())
    or (app_current_role() = 'trainer' and exists (
      select 1 from trainer_members tm
      where tm.org_id = member_profiles.org_id
        and tm.trainer_id = app_current_user()
        and tm.member_id = member_profiles.user_id
    ))
  ))
  with check (org_id = app_current_org());

create policy biometrics_rw on biometrics for all
  using (org_id = app_current_org() and (
    app_current_role() = 'org_admin'
    or member_id = app_current_user()
    or (app_current_role() = 'trainer' and exists (
      select 1 from trainer_members tm
      where tm.org_id = biometrics.org_id
        and tm.trainer_id = app_current_user()
        and tm.member_id = biometrics.member_id
    ))
  ))
  with check (org_id = app_current_org());

create policy meals_rw on meals for all
  using (org_id = app_current_org() and (
    app_current_role() = 'org_admin'
    or member_id = app_current_user()
    or (app_current_role() = 'trainer' and exists (
      select 1 from trainer_members tm
      where tm.org_id = meals.org_id
        and tm.trainer_id = app_current_user()
        and tm.member_id = meals.member_id
    ))
  ))
  with check (org_id = app_current_org());

-- ─── audit_log ───────────────────────────────────────────────────
create policy audit_log_select on audit_log for select
  using (org_id = app_current_org() and app_current_role() = 'org_admin');

-- ─── sessions & scim_config: RPC-only ────────────────────────────
create policy sessions_deny on sessions for all using (false) with check (false);
create policy scim_config_select on scim_config for select
  using (org_id = app_current_org() and app_current_role() = 'org_admin');
