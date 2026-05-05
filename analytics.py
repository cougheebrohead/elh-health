"""ELH Health analytics — every query the dashboards depend on.

Each function returns plain dicts/lists (JSON-ready). Each is gated by org_id
and parameterised so the same code drives org-admin, region-manager,
site-admin, and trainer scopes.

The contract: every read of PHI must call audit_event() at the call site
(so the auditor sees who/why). These functions don't audit; the route
handlers do.
"""
from __future__ import annotations

from typing import Any, Optional
from datetime import date, datetime, timedelta, timezone

from db import db


# ────────────────────────────────────────────────────────────────────
#  Executive dashboard rollups
# ────────────────────────────────────────────────────────────────────

def exec_kpis(org_id: str) -> dict[str, Any]:
    rows = db.fetch_all(
        """select
            (select count(*) from users where org_id = $1 and role = 'member' and is_active) as members_total,
            (select count(*) from users
                where org_id = $1 and role = 'member'
                  and last_login_at > now() - interval '7 days') as members_7d,
            (select count(*) from users
                where org_id = $1 and role = 'member'
                  and last_login_at > now() - interval '30 days') as members_30d,
            (select count(*) from users
                where org_id = $1 and role = 'member'
                  and created_at > now() - interval '30 days') as new_30d,
            (select count(*) from users
                where org_id = $1 and role = 'member'
                  and created_at between now() - interval '60 days' and now() - interval '30 days') as new_prev_30d,
            (select count(*) from users where org_id = $1 and role = 'trainer' and is_active) as trainers_total,
            (select count(*) from sites where org_id = $1) as sites_total,
            (select round(avg(score)::numeric, 1)::float from engagement_score where org_id = $1) as avg_engagement,
            (select count(*) from engagement_score where org_id = $1 and risk_tier = 'ghosting') as ghosting,
            (select count(*) from engagement_score where org_id = $1 and risk_tier = 'slipping') as slipping,
            (select count(*) from engagement_score where org_id = $1 and risk_tier = 'on_track') as on_track,
            (select count(*) from engagement_score where org_id = $1 and risk_tier = 'crushing') as crushing
        """,
        org_id,
    )
    r = rows[0] if rows else {}
    new_30d = r.get("new_30d") or 0
    prev_30d = r.get("new_prev_30d") or 0
    growth_pct = round(((new_30d - prev_30d) / prev_30d * 100), 1) if prev_30d else None
    return {
        "members_total":   r.get("members_total") or 0,
        "members_7d":      r.get("members_7d") or 0,
        "members_30d":     r.get("members_30d") or 0,
        "new_30d":         new_30d,
        "growth_pct":      growth_pct,
        "trainers_total":  r.get("trainers_total") or 0,
        "sites_total":     r.get("sites_total") or 0,
        "avg_engagement":  r.get("avg_engagement") or 0,
        "risk_buckets": {
            "crushing":  r.get("crushing") or 0,
            "on_track":  r.get("on_track") or 0,
            "slipping":  r.get("slipping") or 0,
            "ghosting":  r.get("ghosting") or 0,
        },
    }


def member_growth_series(org_id: str, days: int = 90) -> list[dict]:
    """Daily count of new members for the last N days."""
    rows = db.fetch_all(
        """with days as (
            select generate_series(
                current_date - ($2::int - 1),
                current_date,
                interval '1 day'
            )::date as d
        )
        select d.d::text as date,
               coalesce(count(u.id), 0)::int as new_members
        from days d
        left join users u
            on u.org_id = $1
           and u.role = 'member'
           and u.created_at::date = d.d
        group by d.d
        order by d.d""",
        org_id, days,
    )
    return rows


def engagement_curve(org_id: str) -> list[dict]:
    """Histogram of engagement scores in 10-point buckets."""
    rows = db.fetch_all(
        """select bucket_min, bucket_max, count(*)::int as n
           from (
             select
               (score / 10) * 10 as bucket_min,
               ((score / 10) * 10) + 9 as bucket_max
             from engagement_score
             where org_id = $1
           ) b
           group by bucket_min, bucket_max
           order by bucket_min""",
        org_id,
    )
    return rows


def cohort_retention(org_id: str) -> list[dict]:
    """Retention by signup month — % active in current 30d window."""
    rows = db.fetch_all(
        """select
             to_char(date_trunc('month', u.created_at), 'YYYY-MM') as cohort,
             count(*) as cohort_size,
             count(*) filter (where u.last_login_at > now() - interval '30 days') as still_active,
             round(
               100.0 * count(*) filter (where u.last_login_at > now() - interval '30 days')
                     / nullif(count(*), 0)
             , 1) as retention_pct
           from users u
           where u.org_id = $1 and u.role = 'member'
             and u.created_at > now() - interval '12 months'
           group by date_trunc('month', u.created_at)
           order by cohort""",
        org_id,
    )
    return rows


# ────────────────────────────────────────────────────────────────────
#  Clubs leaderboard
# ────────────────────────────────────────────────────────────────────

def clubs_leaderboard(org_id: str) -> list[dict]:
    rows = db.fetch_all(
        """select
             s.id as site_id,
             s.name as site_name,
             s.timezone,
             r.name as region_name,
             count(distinct u.id) filter (where u.role = 'member') as members,
             count(distinct u.id) filter (where u.role = 'trainer') as trainers,
             count(distinct u.id) filter (where u.role = 'member' and u.last_login_at > now() - interval '7 days') as active_7d,
             round(coalesce(avg(es.score), 0)::numeric, 1)::float as avg_engagement,
             count(es.member_id) filter (where es.risk_tier = 'crushing') as crushing,
             count(es.member_id) filter (where es.risk_tier = 'ghosting') as ghosting
           from sites s
           left join regions r on r.id = s.region_id
           left join users u on u.site_id = s.id and u.org_id = $1
           left join engagement_score es on es.member_id = u.id and es.org_id = $1
           where s.org_id = $1
           group by s.id, s.name, s.timezone, r.name
           order by avg_engagement desc nulls last, members desc""",
        org_id,
    )
    return rows


# ────────────────────────────────────────────────────────────────────
#  Trainer performance
# ────────────────────────────────────────────────────────────────────

def trainer_performance(org_id: str, site_id: Optional[str] = None) -> list[dict]:
    args: list[Any] = [org_id]
    where = "u.org_id = $1 and u.role = 'trainer' and u.is_active"
    if site_id:
        args.append(site_id); where += " and u.site_id = $2"
    rows = db.fetch_all(
        f"""select
             u.id as trainer_id,
             u.name as trainer_name,
             u.email,
             s.name as site_name,
             count(distinct tm.member_id) filter (where tm.status = 'active') as roster,
             round(coalesce(avg(es.score), 0)::numeric, 1)::float as avg_client_engagement,
             count(es.member_id) filter (where es.risk_tier in ('slipping','ghosting')) as at_risk_clients,
             count(distinct ss.id) filter (where ss.starts_at > now() - interval '7 days'
                                            and ss.status = 'completed') as sessions_7d,
             count(distinct m.id) filter (where m.sender_id = u.id
                                           and m.sent_at > now() - interval '7 days') as messages_sent_7d
           from users u
           left join sites s on s.id = u.site_id
           left join trainer_members tm on tm.trainer_id = u.id
           left join engagement_score es on es.member_id = tm.member_id and es.org_id = $1
           left join schedule_sessions ss on ss.trainer_id = u.id
           left join messages m on m.trainer_id = u.id
           where {where}
           group by u.id, u.name, u.email, s.name
           order by avg_client_engagement desc, roster desc""",
        *args,
    )
    return rows


# ────────────────────────────────────────────────────────────────────
#  At-risk members
# ────────────────────────────────────────────────────────────────────

def at_risk_members(org_id: str, site_id: Optional[str] = None,
                    trainer_id: Optional[str] = None,
                    limit: int = 50) -> list[dict]:
    args: list[Any] = [org_id]
    where = "u.org_id = $1 and u.role = 'member' and es.risk_tier in ('slipping','ghosting')"
    n = 1
    if site_id:
        n += 1; args.append(site_id); where += f" and u.site_id = ${n}"
    if trainer_id:
        n += 1; args.append(trainer_id); where += f" and tm.trainer_id = ${n}"
    rows = db.fetch_all(
        f"""select
             u.id as member_id,
             u.name as member_name,
             u.email,
             s.name as site_name,
             es.score,
             es.risk_tier,
             es.last_login_at,
             es.days_active_30,
             tr.id as trainer_id,
             tr.name as trainer_name,
             es.components_json
           from users u
           join engagement_score es on es.member_id = u.id and es.org_id = $1
           left join sites s on s.id = u.site_id
           left join trainer_members tm on tm.member_id = u.id and tm.status = 'active'
           left join users tr on tr.id = tm.trainer_id
           where {where}
           order by es.score asc, es.last_login_at asc nulls first
           limit {int(limit)}""",
        *args,
    )
    return rows


# ────────────────────────────────────────────────────────────────────
#  Population health
# ────────────────────────────────────────────────────────────────────

def population_health(org_id: str) -> dict[str, Any]:
    weight = db.fetch_all(
        """with first_last as (
             select b.member_id,
                    (array_agg(b.weight_kg order by b.reading_at) filter (where b.weight_kg is not null))[1] as wt_first,
                    (array_agg(b.weight_kg order by b.reading_at desc) filter (where b.weight_kg is not null))[1] as wt_last
             from biometrics b
             where b.org_id = $1
             group by b.member_id
           )
           select
             count(*) filter (where wt_last < wt_first) as losing,
             count(*) filter (where wt_last > wt_first) as gaining,
             count(*) filter (where wt_last = wt_first) as steady,
             round(avg(wt_last - wt_first)::numeric, 2)::float as avg_delta_kg
           from first_last
           where wt_first is not null and wt_last is not null""",
        org_id,
    )
    glp1 = db.fetch_all(
        """select
             count(distinct e.member_id) as members_in_program,
             round(avg(o.delta) filter (where o.metric = 'weight_kg')::numeric, 2)::float as avg_weight_kg_delta,
             round(avg(o.delta) filter (where o.metric = 'hba1c')::numeric, 2)::float as avg_hba1c_delta,
             round(avg(o.delta) filter (where o.metric = 'ldl')::numeric, 2)::float as avg_ldl_delta
           from program_enrollments e
           join programs p on p.id = e.program_id and p.target_segment = 'glp1'
           left join program_outcomes o on o.enrollment_id = e.id
           where e.org_id = $1 and e.status in ('active','completed')""",
        org_id,
    )
    conditions = db.fetch_all(
        """select coalesce(nullif(trim(conditions), ''), 'none') as condition,
                  count(*)::int as n
           from member_profiles
           where org_id = $1
           group by 1
           order by n desc""",
        org_id,
    )
    return {
        "weight":     weight[0] if weight else {},
        "glp1":       glp1[0]   if glp1   else {},
        "conditions": conditions,
    }


# ────────────────────────────────────────────────────────────────────
#  Per-member drill-down
# ────────────────────────────────────────────────────────────────────

def member_overview(org_id: str, member_id: str) -> dict[str, Any]:
    user = db.fetch_one(
        """select u.id, u.name, u.email, u.role, u.created_at, u.last_login_at,
                  s.name as site_name, r.name as region_name,
                  tm.trainer_id, tr.name as trainer_name
           from users u
           left join sites s on s.id = u.site_id
           left join regions r on r.id = s.region_id
           left join trainer_members tm on tm.member_id = u.id and tm.status = 'active'
           left join users tr on tr.id = tm.trainer_id
           where u.org_id = $1 and u.id = $2""",
        org_id, member_id,
    )
    if not user: return {}
    profile = db.fetch_one(
        "select * from member_profiles where org_id = $1 and user_id = $2",
        org_id, member_id,
    )
    engagement = db.fetch_one(
        "select * from engagement_score where org_id = $1 and member_id = $2",
        org_id, member_id,
    )
    weight_series = db.fetch_all(
        """select reading_at::date::text as date, weight_kg::float
           from biometrics
           where org_id = $1 and member_id = $2 and weight_kg is not null
           order by reading_at desc limit 30""",
        org_id, member_id,
    )
    nutrition_30d = db.fetch_all(
        """select log_date::text as date,
                  (totals_json->>'calories')::int as calories,
                  (totals_json->>'protein')::int as protein,
                  (totals_json->>'carbs')::int as carbs,
                  (totals_json->>'fat')::int as fat
           from meals
           where org_id = $1 and member_id = $2
             and log_date > current_date - interval '30 days'
           order by log_date desc""",
        org_id, member_id,
    )
    enrollments = db.fetch_all(
        """select e.id, e.status, e.adherence_pct, e.started_at::text as started_at,
                  p.name as program_name, p.target_segment
           from program_enrollments e
           join programs p on p.id = e.program_id
           where e.org_id = $1 and e.member_id = $2
           order by e.started_at desc""",
        org_id, member_id,
    )
    last_messages = db.fetch_all(
        """select id, body, sender_id, sent_at::text as sent_at, is_nudge
           from messages
           where org_id = $1 and member_id = $2
           order by sent_at desc limit 10""",
        org_id, member_id,
    )
    return {
        "user":          user,
        "profile":       profile,
        "engagement":    engagement,
        "weight_series": weight_series,
        "nutrition_30d": nutrition_30d,
        "enrollments":   enrollments,
        "messages":      last_messages,
    }


def member_audit_trail(org_id: str, member_id: str, limit: int = 100) -> list[dict]:
    return db.fetch_all(
        """select id, action, resource_type, actor_id, actor_role,
                  ip_hash, user_agent, created_at::text as created_at
           from audit_log
           where org_id = $1 and member_subject = $2
           order by created_at desc
           limit $3""",
        org_id, member_id, limit,
    )


# ────────────────────────────────────────────────────────────────────
#  Programs
# ────────────────────────────────────────────────────────────────────

def list_programs(org_id: str) -> list[dict]:
    return db.fetch_all(
        """select p.id, p.name, p.slug, p.program_type, p.duration_days,
                  p.target_segment, p.is_org_wide, p.is_archived,
                  count(e.id) filter (where e.status = 'active') as active_enrollments,
                  count(e.id) filter (where e.status = 'completed') as completed
           from programs p
           left join program_enrollments e on e.program_id = p.id
           where p.org_id = $1
           group by p.id
           order by p.is_archived asc, p.created_at desc""",
        org_id,
    )


def program_detail(org_id: str, program_id: str) -> dict[str, Any]:
    program = db.fetch_one(
        "select * from programs where org_id = $1 and id = $2", org_id, program_id,
    )
    enrollments = db.fetch_all(
        """select e.*, u.name as member_name, u.email
           from program_enrollments e
           join users u on u.id = e.member_id
           where e.org_id = $1 and e.program_id = $2
           order by e.started_at desc""",
        org_id, program_id,
    )
    outcomes = db.fetch_all(
        """select metric,
                  count(*)::int as n,
                  round(avg(delta)::numeric, 2)::float as avg_delta,
                  round(min(delta)::numeric, 2)::float as min_delta,
                  round(max(delta)::numeric, 2)::float as max_delta
           from program_outcomes
           where org_id = $1
             and enrollment_id in (select id from program_enrollments
                                   where org_id = $1 and program_id = $2)
           group by metric""",
        org_id, program_id,
    )
    return {"program": program, "enrollments": enrollments, "outcomes": outcomes}


# ────────────────────────────────────────────────────────────────────
#  Roster (org-wide list with filters)
# ────────────────────────────────────────────────────────────────────

def roster(org_id: str, *,
           search: Optional[str] = None,
           site_id: Optional[str] = None,
           trainer_id: Optional[str] = None,
           risk_tier: Optional[str] = None,
           limit: int = 100, offset: int = 0) -> dict[str, Any]:
    args: list[Any] = [org_id]
    where = "u.org_id = $1 and u.role = 'member'"
    n = 1
    if site_id:
        n += 1; args.append(site_id); where += f" and u.site_id = ${n}"
    if trainer_id:
        n += 1; args.append(trainer_id); where += f" and tm.trainer_id = ${n}"
    if risk_tier:
        n += 1; args.append(risk_tier); where += f" and es.risk_tier = ${n}"
    if search:
        n += 1; args.append(f"%{search.lower()}%")
        where += f" and (lower(u.name) like ${n} or lower(u.email) like ${n})"

    total = db.fetch_one(
        f"""select count(distinct u.id)::int as n
            from users u
            left join trainer_members tm on tm.member_id = u.id and tm.status = 'active'
            left join engagement_score es on es.member_id = u.id and es.org_id = $1
            where {where}""",
        *args,
    )
    rows = db.fetch_all(
        f"""select u.id, u.name, u.email,
                  s.name as site_name,
                  tr.name as trainer_name,
                  es.score, es.risk_tier, es.last_login_at::text as last_login_at,
                  u.created_at::text as joined_at
            from users u
            left join sites s on s.id = u.site_id
            left join trainer_members tm on tm.member_id = u.id and tm.status = 'active'
            left join users tr on tr.id = tm.trainer_id
            left join engagement_score es on es.member_id = u.id and es.org_id = $1
            where {where}
            order by es.score desc nulls last, u.name
            limit {int(limit)} offset {int(offset)}""",
        *args,
    )
    return {"total": (total or {}).get("n", 0), "rows": rows}
