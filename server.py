"""Vitalstack — enterprise health platform server (stdlib HTTP).

Same shape as FitApp/CoachHQ — BaseHTTPRequestHandler, no framework. The
key shape change vs CoachHQ is org_id/site_id GUC handling and the
PHI-read audit log on every member-data endpoint.

Endpoints
─────────
APEX (vitalstack.app):
  GET  /                          marketing site
  GET  /pricing | /security | /demo
  POST /api/demo                  schedule a demo (writes lead)
  POST /api/admin/orgs            ELH-only: provision a new org

ORG-SCOPED ({slug}.vitalstack.app):
  GET  /                          dashboard SPA (org-themed)
  POST /api/login                 password sign-in (if !sso_required)
  GET  /api/sso/login             302 to IdP (SAML/OIDC)
  POST /api/sso/acs               SAML assertion callback
  GET  /api/me                    session + org + role
  POST /api/logout

  GET  /api/sites                 site list (gated by role)
  GET  /api/sites/{id}/members
  POST /api/members/{id}/profile  (PHI write — audited)
  GET  /api/members/{id}/profile  (PHI read  — audited)
  GET  /api/members/{id}/biometrics

  /scim/v2/Users                  SCIM 2.0 (Bearer auth, per-org)
  /scim/v2/Users/{id}
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

# fitapp-core gives us cycle/glucose/macros/etc without re-implementing
try:
    import fitapp_core  # noqa: F401
except ImportError:
    print("[Vitalstack] WARNING: fitapp-core not installed — install via requirements.txt", flush=True)

try:
    import sentry_sdk  # type: ignore
except ImportError:
    sentry_sdk = None  # type: ignore
SENTRY_DSN = os.environ.get("SENTRY_DSN_SERVER", "")
if SENTRY_DSN and sentry_sdk:
    sentry_sdk.init(dsn=SENTRY_DSN, traces_sample_rate=0.1, send_default_pii=False)

from db import db
from auth import hash_password, verify_password, issue_session, validate_session, revoke_session
from orgs import org_resolver, APEX_HOST
from audit import audit_event
from sso import saml_login_url, saml_assert_callback, upsert_user_from_sso, issue_sso_session
from scim import (authenticate_scim_request, list_users, create_user,
                  replace_user, patch_user, deactivate_user)
from ratelimit import allow as rate_allow

PORT = int(os.environ.get("PORT", "10000"))
ENV  = os.environ.get("ENV", "development")
APEX = APEX_HOST


def _here(name: str) -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), name)


# ────────────────────────────────────────────────────────────────────
#  Response helpers
# ────────────────────────────────────────────────────────────────────

class H(BaseHTTPRequestHandler):
    server_version = "Vitalstack/1.0"
    sys_version = ""

    def log_message(self, fmt: str, *args: Any) -> None:
        # Standard access log via stdout (Render captures it)
        sys.stderr.write(f"{self.address_string()} - {fmt % args}\n")

    # ---- helpers
    def _hdrs(self, status: int, ctype: str = "text/html; charset=utf-8",
              extra: dict | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store" if ctype.startswith("text/html") else "public, max-age=300")
        self.send_header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        # CSP — strict; SPA pages eval no remote scripts
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; img-src 'self' data: https:; "
                         "style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; "
                         "connect-src 'self' https://*.supabase.co; "
                         "frame-ancestors 'none'")
        if extra:
            for k, v in extra.items(): self.send_header(k, v)
        self.end_headers()

    def _json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload).encode()
        self._hdrs(status, "application/json")
        self.wfile.write(body)

    def _err(self, status: int, msg: str) -> None:
        self._json(status, {"error": msg})

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or "0")
        if not length: return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except Exception:
            return {}

    def _serve_static(self, path: str) -> None:
        full = _here(path)
        if not os.path.exists(full):
            self._hdrs(404); self.wfile.write(b"Not found"); return
        with open(full, "rb") as f:
            data = f.read()
        ctype = (
            "text/html; charset=utf-8" if path.endswith(".html") else
            "image/svg+xml" if path.endswith(".svg") else
            "text/css" if path.endswith(".css") else
            "application/javascript" if path.endswith(".js") else
            "application/octet-stream"
        )
        self._hdrs(200, ctype)
        self.wfile.write(data)

    def _bearer(self) -> str | None:
        auth = self.headers.get("Authorization", "")
        if auth.lower().startswith("bearer "):
            return auth.split(" ", 1)[1].strip()
        return None

    def _require_session(self) -> dict | None:
        token = self._bearer()
        if not token: self._err(401, "auth required"); return None
        sess = validate_session(token)
        if not sess: self._err(401, "invalid session"); return None
        return sess

    def _ip_hash(self) -> str:
        ip = self.headers.get("CF-Connecting-IP") or self.headers.get("X-Forwarded-For", "").split(",")[0].strip() or self.client_address[0]
        return hashlib.sha256(ip.encode()).hexdigest()[:32]

    # ---- routing
    def do_GET(self):  self._route("GET")
    def do_POST(self): self._route("POST")
    def do_PUT(self):  self._route("PUT")
    def do_PATCH(self):self._route("PATCH")
    def do_DELETE(self):self._route("DELETE")

    def _route(self, method: str):
        try:
            url = urlparse(self.path)
            host = (self.headers.get("Host") or "").lower().split(":")[0]
            org = org_resolver(host)
            path = url.path

            # Apex routes (marketing + ELH-admin)
            if not org:
                return self._apex(method, path, url)

            # Org-scoped routes
            return self._org(org, method, path, url)

        except Exception as e:
            if SENTRY_DSN and sentry_sdk:
                sentry_sdk.capture_exception(e)
            traceback.print_exc()
            self._err(500, "internal")

    # ────────────────────────────────────────────────
    #  APEX ROUTES (marketing site + ELH admin)
    # ────────────────────────────────────────────────
    def _apex(self, method: str, path: str, url):
        if method == "GET":
            if path in ("/", "/index", "/home"):
                return self._serve_static("marketing.html")
            if path == "/pricing":
                return self._serve_static("pricing.html")
            if path == "/security":
                return self._serve_static("security.html")
            if path == "/demo":
                return self._serve_static("demo.html")
            if path == "/terms":
                return self._serve_static("terms.html")
            if path == "/privacy":
                return self._serve_static("privacy.html")
            if path in ("/health", "/healthz"):
                return self._json(200, {"ok": True})
            if path == "/favicon.svg":
                return self._serve_static("favicon.svg")
            if path == "/robots.txt":
                return self._serve_static("robots.txt")

        if method == "POST" and path == "/api/demo":
            ip_key = f"demo:{self._ip_hash()}"
            if not rate_allow(ip_key, 5, 60 * 60):
                return self._err(429, "too many requests")
            body = self._read_body()
            email = (body.get("email") or "").strip().lower()
            org_name = (body.get("org_name") or "").strip()
            note = (body.get("note") or "").strip()[:1000]
            if "@" not in email or len(email) > 200 or not org_name:
                return self._err(400, "email and org_name required")
            try:
                db.execute(
                    """create table if not exists demo_leads (
                        id bigserial primary key,
                        email text not null,
                        org_name text,
                        note text,
                        ip_hash text,
                        created_at timestamptz default now()
                    )"""
                )
                db.execute(
                    "insert into demo_leads (email, org_name, note, ip_hash) values ($1,$2,$3,$4)",
                    email, org_name, note, self._ip_hash(),
                )
            except Exception as e:
                print("[Vitalstack] demo insert error:", e, flush=True)
            return self._json(200, {"ok": True})

        return self._err(404, "not found")

    # ────────────────────────────────────────────────
    #  ORG-SCOPED ROUTES
    # ────────────────────────────────────────────────
    def _org(self, org: dict, method: str, path: str, url):
        org_id = org["id"]

        if method == "GET" and path == "/health":
            return self._json(200, {"ok": True})

        # SCIM endpoints (Bearer auth, per-org)
        if path.startswith("/scim/v2/Users"):
            return self._scim(org, method, path, url)

        # SPA / static
        if method == "GET" and path in ("/", "/login", "/dashboard"):
            return self._serve_org_app(org)

        if method == "GET" and path == "/api/brand":
            return self._json(200, {
                "name": org["display_name"],
                "app_name": org["display_name"],
                "primary": org["brand_primary"],
                "accent": org["brand_accent"],
                "logo_url": org.get("logo_url"),
            })

        if method == "POST" and path == "/api/login":
            if org.get("sso_required"):
                return self._err(403, "password login disabled — use SSO")
            return self._login(org)

        if method == "GET" and path == "/api/sso/login":
            try:
                sp_entity = f"https://{org['slug']}.{APEX}/api/sso/metadata"
                acs = f"https://{org['slug']}.{APEX}/api/sso/acs"
                redir = saml_login_url(org, acs, sp_entity)
                self.send_response(302); self.send_header("Location", redir); self.end_headers()
                return
            except Exception as e:
                return self._err(400, str(e))

        if method == "POST" and path == "/api/sso/acs":
            return self._sso_acs(org)

        if method == "POST" and path == "/api/logout":
            t = self._bearer()
            if t: revoke_session(t)
            return self._json(200, {"ok": True})

        if method == "GET" and path == "/api/me":
            sess = self._require_session()
            if not sess: return
            return self._json(200, {
                "user":   {"id": sess["user_id"], "name": sess["name"],
                           "email": sess["email"], "role": sess["role"]},
                "org":    {"id": org["id"], "slug": org["slug"],
                           "name": org["display_name"], "plan": org["plan"]},
                "site_id": sess.get("site_id"),
            })

        if method == "GET" and path == "/api/sites":
            sess = self._require_session()
            if not sess: return
            rows = db.fetch_all(
                "select id, slug, name, timezone from sites where org_id = $1 order by name",
                org_id, org_id=org_id, user_id=sess["user_id"],
                role=sess["role"], site_id=sess.get("site_id"),
            )
            return self._json(200, {"sites": rows})

        if method == "GET" and path.startswith("/api/members/") and path.endswith("/profile"):
            sess = self._require_session()
            if not sess: return
            member_id = path.split("/")[3]
            row = db.fetch_one(
                "select * from member_profiles where org_id = $1 and user_id = $2",
                org_id, member_id,
                org_id=org_id, user_id=sess["user_id"],
                role=sess["role"], site_id=sess.get("site_id"),
            )
            if not row: return self._err(404, "not found")
            audit_event(
                org_id=org_id, actor_id=sess["user_id"], actor_role=sess["role"],
                action="read_profile", resource_type="member_profile",
                resource_id=member_id, member_subject=member_id,
                ip_hash=self._ip_hash(),
                user_agent=self.headers.get("User-Agent", "")[:300],
            )
            return self._json(200, {"profile": row})

        return self._err(404, "not found")

    def _serve_org_app(self, org: dict) -> None:
        """Inject the brand payload into app.html and serve."""
        full = _here("app.html")
        if not os.path.exists(full):
            return self._err(500, "app missing")
        with open(full, "r") as f:
            html = f.read()
        brand_js = (
            "<script>window.__BRAND__ = " + json.dumps({
                "name": org["display_name"],
                "app_name": org["display_name"],
                "primary": org["brand_primary"],
                "accent": org["brand_accent"],
                "logo_url": org.get("logo_url"),
                "sso_required": bool(org.get("sso_required")),
            }) + ";</script>"
        )
        html = html.replace("<!--BRAND_INJECT-->", brand_js)
        self._hdrs(200, "text/html; charset=utf-8")
        self.wfile.write(html.encode())

    def _login(self, org: dict) -> None:
        body = self._read_body()
        email = (body.get("email") or "").strip().lower()
        password = body.get("password") or ""
        ip_key = f"login:{org['id']}:{email}:{self._ip_hash()}"
        if not rate_allow(ip_key, 6, 5 * 60):
            return self._err(429, "too many attempts")
        u = db.fetch_one(
            "select id, password_hash, role, name, site_id, is_active from users "
            "where org_id = $1 and email = $2",
            org["id"], email,
        )
        if not u or not u.get("is_active") or not verify_password(password, u.get("password_hash")):
            return self._err(401, "invalid email or password")
        token = issue_session(
            user_id=u["id"], org_id=org["id"],
            ip=self.headers.get("CF-Connecting-IP") or self.client_address[0],
            ua=self.headers.get("User-Agent", "")[:300],
        )
        db.execute("update users set last_login_at = now() where id = $1", u["id"])
        return self._json(200, {
            "token": token,
            "user":  {"id": u["id"], "name": u["name"], "email": email, "role": u["role"]},
            "org":   {"id": org["id"], "slug": org["slug"], "name": org["display_name"], "plan": org["plan"]},
        })

    def _sso_acs(self, org: dict) -> None:
        length = int(self.headers.get("Content-Length") or "0")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        params = parse_qs(raw)
        saml_resp = (params.get("SAMLResponse") or [""])[0]
        try:
            attrs = saml_assert_callback(org, saml_resp,
                                         ip=self.client_address[0],
                                         ua=self.headers.get("User-Agent", ""))
        except NotImplementedError as e:
            return self._err(501, str(e))
        except Exception as e:
            return self._err(400, f"SAML: {e}")
        # Production: upsert + issue session here. Currently unreachable
        # (saml_assert_callback raises NotImplementedError) — guarded by
        # design until signature validation is wired.
        user_id = upsert_user_from_sso(
            org_id=org["id"], site_id=None,
            email=attrs["email"], name=attrs.get("name", attrs["email"]),
            sso_subject=attrs["sso_subject"],
        )
        token = issue_sso_session(
            user_id=user_id, org_id=org["id"],
            sso_session_id=attrs.get("sso_session_id", ""),
            ip=self.client_address[0], ua=self.headers.get("User-Agent", ""),
        )
        self.send_response(302)
        self.send_header("Location", f"/?token={token}")
        self.end_headers()

    # ----------------- SCIM -----------------
    def _scim(self, org: dict, method: str, path: str, url) -> None:
        cfg = db.fetch_one(
            "select * from scim_config where org_id = $1 and enabled = true", org["id"]
        )
        if not cfg or not authenticate_scim_request(cfg, self.headers.get("Authorization", "")):
            return self._err(401, "unauthorized")
        try:
            if path == "/scim/v2/Users":
                if method == "GET":
                    qs = parse_qs(url.query)
                    start = int((qs.get("startIndex") or ["1"])[0])
                    count = int((qs.get("count") or ["100"])[0])
                    flt = (qs.get("filter") or [""])[0]
                    email = None
                    if flt and "userName eq" in flt:
                        email = flt.split('"')[1].lower() if '"' in flt else None
                    return self._json(200, list_users(org["id"], start, count, email))
                if method == "POST":
                    body = self._read_body()
                    return self._json(201, create_user(org["id"], body))
            if path.startswith("/scim/v2/Users/"):
                user_id = path.split("/")[-1]
                if method == "PUT":
                    return self._json(200, replace_user(org["id"], user_id, self._read_body()))
                if method == "PATCH":
                    return self._json(200, patch_user(org["id"], user_id, self._read_body()))
                if method == "DELETE":
                    deactivate_user(org["id"], user_id)
                    return self._json(204, {})
            return self._err(404, "not found")
        except LookupError as e:
            return self._err(404, str(e))
        except ValueError as e:
            return self._err(400, str(e))


def main():
    print(f"[Vitalstack] starting on :{PORT} env={ENV} apex={APEX}", flush=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), H)
    server.serve_forever()


if __name__ == "__main__":
    main()
