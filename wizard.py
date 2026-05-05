"""Sales-engineering wizard endpoints — branded-demo onboarding.

Fronts the provisioner. All routes here are sales-admin-gated (re-uses
sales.validate from sales.py) and sit under /api/sales/wizard/*. The
HTML wizard lives at /admin/onboard.

Flow:
    POST /api/sales/wizard/scan      { url } -> brand kit
    POST /api/sales/wizard/provision { name, ...overrides } -> demo URL + creds
    GET  /api/sales/wizard/demos                 -> list active demos
    POST /api/sales/wizard/demos/{id}/extend     -> push expiry +30d
    DELETE /api/sales/wizard/demos/{id}          -> wipe early
"""

from __future__ import annotations

from typing import Any
from datetime import datetime, timedelta, timezone

from db import db
from fitapp_core import scrape_brand
import provisioner
import sales


def handle(handler, method: str, path: str, url) -> bool:
    """Route entry. Returns True if the path was handled (success or
    error), False if not — caller falls through to other routers."""

    # All wizard routes require sales-admin auth
    if not path.startswith("/api/sales/wizard"):
        return False

    sess = sales.validate(handler._bearer() or "")
    if not sess:
        handler._err(401, "sales-admin auth required")
        return True

    if method == "POST" and path == "/api/sales/wizard/scan":
        body = handler._read_body()
        target_url = (body.get("url") or "").strip()
        if not target_url or len(target_url) > 500:
            handler._err(400, "url required")
            return True
        try:
            kit = scrape_brand(target_url)
        except Exception as e:
            handler._err(500, f"scrape failed: {e}")
            return True
        handler._json(200, kit)
        return True

    if method == "POST" and path == "/api/sales/wizard/customer":
        body = handler._read_body()
        required = ("brand_name", "owner_email", "owner_name")
        missing = [k for k in required if not (body.get(k) or "").strip()]
        if missing:
            handler._err(400, f"missing: {', '.join(missing)}"); return True
        try:
            res = provisioner.provision_customer(
                brand_name=body["brand_name"],
                legal_name=body.get("legal_name"),
                primary_color=body.get("primary_color"),
                accent_color=body.get("accent_color"),
                logo_url=body.get("logo_url"),
                source_url=body.get("source_url"),
                scraped_brand=body.get("scraped_brand"),
                owner_email=body["owner_email"],
                owner_name=body["owner_name"],
                plan=(body.get("plan") or "enterprise"),
                invoicing_email=body.get("invoicing_email"),
                contract_value_usd=body.get("contract_value_usd"),
                custom_slug=body.get("custom_slug"),
                sales_owner=sess.get("email"),
            )
        except Exception as e:
            import traceback; traceback.print_exc()
            handler._err(500, f"provision failed: {e}"); return True
        if not res.get("ok"):
            handler._err(400, res.get("error") or "provision failed"); return True
        handler._json(200, res); return True

    if method == "POST" and path == "/api/sales/wizard/provision":
        body = handler._read_body()
        if not (body.get("brand_name") or "").strip():
            handler._err(400, "brand_name required")
            return True
        try:
            res = provisioner.provision_demo(
                brand_name=body["brand_name"],
                legal_name=body.get("legal_name"),
                primary_color=body.get("primary_color"),
                accent_color=body.get("accent_color"),
                logo_url=body.get("logo_url"),
                source_url=body.get("source_url"),
                scraped_brand=body.get("scraped_brand"),
                prospect_contact=body.get("prospect_contact"),
                sales_owner=sess.get("email"),
                member_count_hint=int(body["member_count_hint"]) if body.get("member_count_hint") else None,
                expiry_days=int(body["expiry_days"]) if body.get("expiry_days") else 30,
            )
        except Exception as e:
            import traceback; traceback.print_exc()
            handler._err(500, f"provision failed: {e}")
            return True
        if not res.get("ok"):
            handler._err(400, res.get("error") or "provision failed")
            return True
        handler._json(200, res)
        return True

    if method == "GET" and path == "/api/sales/wizard/demos":
        rows = provisioner.list_demos(active_only=False)
        handler._json(200, {"demos": rows})
        return True

    if method == "POST" and path.startswith("/api/sales/wizard/demos/") and path.endswith("/extend"):
        demo_id = path.split("/")[-2]
        body = handler._read_body()
        days = int(body.get("days") or 30)
        new_exp = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
        db.execute(
            "update orgs set demo_expires_at = $1 where id = $2 and is_demo = true",
            new_exp, demo_id,
        )
        handler._json(200, {"ok": True, "expires_at": new_exp})
        return True

    if method == "POST" and path == "/api/sales/wizard/expire-now":
        n = provisioner.expire_old_demos()
        handler._json(200, {"ok": True, "deleted": n})
        return True

    if method == "DELETE" and path.startswith("/api/sales/wizard/demos/"):
        demo_id = path.split("/")[-1]
        # Only allow deleting demos, never real customer orgs
        row = db.fetch_one("select id from orgs where id = $1 and is_demo = true", demo_id)
        if not row:
            handler._err(404, "demo not found")
            return True
        db.execute("delete from orgs where id = $1 and is_demo = true", demo_id)
        handler._json(200, {"ok": True})
        return True

    handler._err(404, "wizard route not found")
    return True
