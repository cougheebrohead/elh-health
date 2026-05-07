"""Sales-side super-admin module.

Lives outside any org. Auth uses sales_admins table + SHA-256 hashed
bearer tokens (sessions table is org-scoped, so we issue a separate
sales-admin session via memory + DB).

Provides:
  POST /api/sales/login            (apex-handled — see server.py apex)
  POST /api/sales/logout
  GET  /api/sales/orgs             list all orgs with health/MRR
  POST /api/sales/orgs             provision new org
  GET  /api/sales/orgs/{id}        org detail incl. utilisation
  POST /api/sales/orgs/{id}/impersonate  start impersonation session
  POST /api/sales/impersonate/end  end the active impersonation
  GET  /api/sales/leads            CRM leads
  POST /api/sales/leads            create lead
  PATCH /api/sales/leads/{id}      update status
"""
from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from auth import hash_password, verify_password
from db import db


SALES_TOKEN_TTL_DAYS = 7


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def login(email: str, password: str) -> dict | None:
    row = db.fetch_one(
        "select id, password_hash, name, email, is_active from sales_admins where email = $1",
        email.lower(),
    )
    if not row or not row.get("is_active") or not verify_password(password, row["password_hash"]):
        return None
    token = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(days=SALES_TOKEN_TTL_DAYS)
    db.execute(
        """create table if not exists sales_sessions (
           token_hash text primary key,
           sales_admin_id uuid not null references sales_admins(id) on delete cascade,
           issued_at timestamptz default now(),
           expires_at timestamptz not null
        )""",
    )
    db.execute(
        "insert into sales_sessions (token_hash, sales_admin_id, expires_at) values ($1,$2,$3)",
        _hash(token), row["id"], expires.isoformat(),
    )
    db.execute(
        "update sales_admins set last_login_at = now() where id = $1", row["id"],
    )
    return {
        "token": token,
        "user": {"id": row["id"], "name": row["name"], "email": row["email"]},
    }


def validate(token: str) -> dict | None:
    if not token: return None
    row = db.fetch_one(
        """select sa.id, sa.email, sa.name
           from sales_sessions s
           join sales_admins sa on sa.id = s.sales_admin_id
           where s.token_hash = $1 and s.expires_at > now() and sa.is_active""",
        _hash(token),
    )
    return row


def logout(token: str) -> None:
    db.execute("delete from sales_sessions where token_hash = $1", _hash(token))


def _require_sales_admin(handler) -> dict | None:
    token = handler._bearer()
    sess = validate(token) if token else None
    if not sess:
        handler._err(401, "sales-admin auth required")
        return None
    return sess


def handle(handler, org: dict | None, method: str, path: str, url) -> None:
    """All /api/sales/* requests route here. The org argument is the
    Host-resolved org (often None when called from apex)."""

    if method == "POST" and path == "/api/sales/login":
        body = handler._read_body()
        out = login((body.get("email") or "").strip().lower(), body.get("password") or "")
        if not out: return handler._err(401, "invalid")
        return handler._json(200, out)

    if method == "POST" and path == "/api/sales/logout":
        t = handler._bearer()
        if t: logout(t)
        return handler._json(200, {"ok": True})

    sess = _require_sales_admin(handler)
    if not sess: return

    if method == "GET" and path == "/api/sales/orgs":
        rows = db.fetch_all(
            """select o.id, o.slug, o.display_name, o.plan, o.contract_value_usd,
                      o.contract_starts::text as contract_starts,
                      o.contract_ends::text as contract_ends,
                      (select count(*) from users where org_id = o.id and role = 'member' and is_active) as members,
                      (select count(*) from sites where org_id = o.id) as sites,
                      o.baa_signed_at::text as baa_signed_at,
                      o.created_at::text as created_at
               from orgs o order by o.contract_value_usd desc nulls last""",
        )
        total_arr = sum((r.get("contract_value_usd") or 0) for r in rows)
        return handler._json(200, {
            "orgs": rows,
            "total_arr": total_arr,
            "active_orgs": len(rows),
        })

    if method == "GET" and path.startswith("/api/sales/orgs/") and not "/impersonate" in path:
        org_id = path.split("/")[4]
        org = db.fetch_one("select * from orgs where id = $1", org_id)
        if not org: return handler._err(404, "not found")
        utilisation = db.fetch_one(
            """select
                 (select count(*) from sites where org_id = $1) as sites,
                 (select count(*) from users where org_id = $1 and role = 'member' and is_active) as members,
                 (select count(*) from users where org_id = $1 and role = 'trainer' and is_active) as trainers,
                 (select count(*) from program_enrollments where org_id = $1 and status = 'active') as active_enrollments
            """,
            org_id,
        )
        return handler._json(200, {"org": org, "utilisation": utilisation})

    if method == "POST" and path == "/api/sales/orgs":
        body = handler._read_body()
        slug = (body.get("slug") or "").lower()
        if not slug or not body.get("display_name"):
            return handler._err(400, "slug + display_name required")
        existing = db.fetch_one("select id from orgs where slug = $1", slug)
        if existing:
            return handler._err(409, f"slug '{slug}' already in use")
        org_row = db.fetch_one(
            """insert into orgs
               (slug, legal_name, display_name, plan, contract_value_usd,
                contract_starts, contract_ends, contract_term_months,
                invoicing_email, max_sites, max_members)
               values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
               returning id""",
            slug,
            body.get("legal_name") or body["display_name"],
            body["display_name"],
            body.get("plan") or "enterprise",
            body.get("contract_value_usd"),
            body.get("contract_starts"),
            body.get("contract_ends"),
            body.get("contract_term_months") or 12,
            body.get("invoicing_email"),
            body.get("max_sites") or 100,
            body.get("max_members") or 100000,
        )
        # Optional initial admin
        if body.get("admin_email") and body.get("admin_password"):
            db.execute(
                """insert into users (org_id, email, password_hash, role, name)
                   values ($1,$2,$3,'org_admin',$4)""",
                org_row["id"], body["admin_email"].lower(),
                hash_password(body["admin_password"]),
                body.get("admin_name") or body["admin_email"],
            )
        return handler._json(201, {"id": org_row["id"], "slug": slug})

    if method == "POST" and path.startswith("/api/sales/orgs/") and path.endswith("/impersonate"):
        org_id = path.split("/")[4]
        body = handler._read_body()
        target = body.get("target_user_id")
        # Issue a regular org session against any user the sales admin chose
        if target:
            user = db.fetch_one(
                "select id, org_id from users where id = $1 and org_id = $2",
                target, org_id,
            )
        else:
            user = db.fetch_one(
                "select id, org_id from users where org_id = $1 and role = 'org_admin' limit 1",
                org_id,
            )
        if not user: return handler._err(404, "no user to impersonate")
        from auth import issue_session
        token = issue_session(
            user_id=user["id"], org_id=user["org_id"],
            ip=handler.client_address[0],
            ua="sales-admin-impersonation",
            sso_session_id=None,
        )
        db.execute(
            """insert into impersonation_log (sales_admin_id, org_id, target_user_id, reason)
               values ($1,$2,$3,$4)""",
            sess["id"], org_id, user["id"],
            (body.get("reason") or "support investigation")[:500],
        )
        slug = db.fetch_one('select slug from orgs where id = $1', org_id)['slug']
        host = handler.headers.get('Host', 'elhhealth.app').split(':')[0]
        scheme = 'https' if 'onrender.com' in host or '.app' in host or '.com' in host else 'http'
        return handler._json(200, {
            "token": token,
            # Subdomain redirect (works once DNS is wired)
            "redirect_to": f"{scheme}://{slug}.{host}",
            # Apex fallback that works without DNS — uses ?org=slug override
            "redirect_to_apex": f"{scheme}://{host}/?org={slug}&token={token}",
        })

    if method == "GET" and path == "/api/sales/leads":
        rows = db.fetch_all(
            "select * from crm_leads order by created_at desc limit 200",
        )
        return handler._json(200, {"leads": rows})

    if method == "POST" and path == "/api/sales/leads":
        body = handler._read_body()
        if not body.get("company_name"):
            return handler._err(400, "company_name required")
        row = db.fetch_one(
            """insert into crm_leads
               (company_name, contact_name, contact_email, members_estimate,
                notes, status, next_action_at, arr_usd)
               values ($1,$2,$3,$4,$5,$6,$7,$8) returning id""",
            body["company_name"], body.get("contact_name"),
            body.get("contact_email"), body.get("members_estimate"),
            body.get("notes"), body.get("status") or "new",
            body.get("next_action_at"), body.get("arr_usd"),
        )
        return handler._json(201, {"id": row["id"]})

    if method == "PATCH" and path.startswith("/api/sales/leads/"):
        lead_id = path.split("/")[4]
        body = handler._read_body()
        sets: list[str] = []
        args: list[Any] = []
        for k in ("status", "next_action_at", "notes", "arr_usd", "won_org_id"):
            if k in body:
                args.append(body[k]); sets.append(f"{k} = ${len(args)}")
        if not sets:
            return handler._err(400, "nothing to update")
        args.append(lead_id)
        # SQL injection safe: `sets` is built from the hardcoded column
        # allowlist above; values are bound as positional parameters.
        # nosec B608 - reviewed, allowlist + parameterized
        db.execute(
            f"update crm_leads set {', '.join(sets)}, updated_at = now() where id = ${len(args)}",  # nosec B608
            *args,
        )
        return handler._json(200, {"ok": True})

    handler._err(404, "not found")
