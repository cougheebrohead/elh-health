"""ELH Health DB client — same shape as CoachHQ but ctx is org_id, user_id,
role, site_id (the four GUCs the RLS policies key off)."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_KEY", "") or os.environ.get("SUPABASE_KEY", "")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("[ELHHealth] WARNING: SUPABASE_URL and SUPABASE_SERVICE_KEY required", flush=True)


def _request(method: str, path: str, body: dict | None = None) -> Any:
    url = f"{SUPABASE_URL}/rest/v1/{path}"
    data = json.dumps(body).encode() if body is not None else None
    headers = {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=representation",
    }
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        msg = e.read().decode("utf-8", errors="replace")[:500]
        print(f"[ELHHealth] PostgREST {e.code}: {msg}", flush=True)
        raise


def _ctx(org_id: str | None, user_id: str | None, role: str | None,
         site_id: str | None) -> dict:
    c: dict[str, str] = {}
    if org_id:  c["org_id"]  = str(org_id)
    if user_id: c["user_id"] = str(user_id)
    if role:    c["role"]    = str(role)
    if site_id: c["site_id"] = str(site_id)
    return c


class _DB:
    def execute(self, sql: str, *params: Any,
                org_id: str | None = None, user_id: str | None = None,
                role: str | None = None, site_id: str | None = None) -> int:
        result = _request("POST", "rpc/app_exec", {
            "q": sql, "p": list(params), "ctx": _ctx(org_id, user_id, role, site_id)
        })
        if isinstance(result, int): return result
        if isinstance(result, list) and result: return int(result[0])
        return 0

    def fetch_one(self, sql: str, *params: Any,
                  org_id: str | None = None, user_id: str | None = None,
                  role: str | None = None, site_id: str | None = None) -> dict | None:
        rows = _request("POST", "rpc/app_query", {
            "q": sql, "p": list(params), "ctx": _ctx(org_id, user_id, role, site_id)
        })
        return rows[0] if rows else None

    def fetch_all(self, sql: str, *params: Any,
                  org_id: str | None = None, user_id: str | None = None,
                  role: str | None = None, site_id: str | None = None) -> list[dict]:
        return _request("POST", "rpc/app_query", {
            "q": sql, "p": list(params), "ctx": _ctx(org_id, user_id, role, site_id)
        }) or []


db = _DB()
