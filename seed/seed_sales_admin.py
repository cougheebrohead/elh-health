#!/usr/bin/env python3
"""Seed the Heads Health Platform sales-admin user (Head's super-admin)."""
import os, sys, json, urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("SUPABASE_URL", "https://skrxpiwhmafescfmlnrz.supabase.co")
os.environ.setdefault(
    "SUPABASE_SERVICE_KEY",
    open("/tmp/hhp_keys.env").read().split("SUPABASE_SERVICE_KEY=", 1)[1].strip(),
)
from auth import hash_password

URL = os.environ["SUPABASE_URL"]
KEY = os.environ["SUPABASE_SERVICE_KEY"]
HDR = {"apikey": KEY, "Authorization": f"Bearer {KEY}", "Content-Type": "application/json"}


def call(fn, q, p):
    body = json.dumps({"q": q, "p": p, "ctx": {}}).encode()
    req = urllib.request.Request(f"{URL}/rest/v1/rpc/{fn}", data=body, headers=HDR, method="POST")
    with urllib.request.urlopen(req, timeout=15) as r:
        raw = r.read().decode()
        return json.loads(raw) if raw else None


email = "head@deanslist.net"
pw = "VS-Admin-Empire-2026!"

existing = call("app_query", "select id from sales_admins where email = $1", [email])
if existing:
    print(f"sales_admin exists: {existing[0]['id']}")
else:
    rows = call(
        "app_query",
        """insert into sales_admins (email, name, password_hash)
           values ($1, $2, $3) returning id""",
        [email, "Head (ELH)", hash_password(pw)],
    )
    print(f"created sales_admin: {rows[0]['id']}")

print(f"Login at /admin: {email} / {pw}")
