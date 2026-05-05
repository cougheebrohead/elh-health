"""SAML 2.0 / OIDC SSO scaffolding.

Per-org SSO config lives in `orgs.sso_*` columns. Two flows are supported:

  1. SAML 2.0 (most enterprise IdPs): SP-initiated. We issue an AuthnRequest,
     accept the IdP's assertion via POST binding, validate signature against
     the per-org cert, and provision/issue a session.

  2. OIDC: standard authorization-code flow.

This module exposes:
    saml_login_url(org)            -> str  (issuer + base64-encoded request)
    saml_assert_callback(org, body) -> dict (validated subject, attrs)
    oidc_login_url(org, state)
    oidc_token_exchange(org, code)

For v1, only SAML is wired end-to-end. OIDC is a stub awaiting per-org
client_id/secret config (env-keyed). Both flows assume the org has been
resolved from Host header before calling.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import urllib.parse
import zlib
from datetime import datetime, timezone
from typing import Any

from db import db
from auth import issue_session


# ────────────────────────────────────────────────────────────────────
#  SAML 2.0
# ────────────────────────────────────────────────────────────────────

_AUTHN_REQUEST_TPL = """<samlp:AuthnRequest
  xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
  xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
  ID="{id}" Version="2.0" IssueInstant="{at}"
  Destination="{idp}"
  AssertionConsumerServiceURL="{acs}"
  ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>{sp_entity}</saml:Issuer>
  <samlp:NameIDPolicy
    Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
    AllowCreate="true"/>
</samlp:AuthnRequest>"""


def saml_login_url(org: dict[str, Any], acs_url: str, sp_entity_id: str) -> str:
    """Returns the IdP redirect URL for SP-initiated SSO."""
    if not org.get("sso_idp_sso_url"):
        raise RuntimeError("Org has no SSO configured")
    req_id = "_" + secrets.token_hex(16)
    at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    xml = _AUTHN_REQUEST_TPL.format(
        id=req_id, at=at,
        idp=org["sso_idp_sso_url"],
        acs=acs_url,
        sp_entity=sp_entity_id,
    ).strip()
    # SAML HTTP-Redirect binding: deflate, base64, urlencode
    deflated = zlib.compress(xml.encode())[2:-4]
    encoded = base64.b64encode(deflated).decode()
    qs = urllib.parse.urlencode({"SAMLRequest": encoded})
    sep = "&" if "?" in org["sso_idp_sso_url"] else "?"
    return f"{org['sso_idp_sso_url']}{sep}{qs}"


def saml_assert_callback(org: dict[str, Any], saml_response_b64: str,
                         ip: str | None = None, ua: str | None = None) -> str:
    """Validate the IdP's SAMLResponse and issue a ELH Health session.

    For brevity this scaffolding parses the email out of the assertion and
    upserts the user. Production must validate the XML signature against
    org.sso_idp_cert_pem before trusting any value — the cert validator is
    intentionally a TODO that hard-fails so the unsigned path can't ship.
    """
    raw = base64.b64decode(saml_response_b64)
    if not org.get("sso_idp_cert_pem"):
        raise RuntimeError("SAML cert not configured for this org")

    # TODO: validate XML signature with org['sso_idp_cert_pem'].
    # Until validate_signature is implemented, refuse to issue a session.
    raise NotImplementedError(
        "SAML signature verification is required before this can issue a session. "
        "Wire xmlsec via signxml or python3-saml; do NOT trust assertions otherwise."
    )


# ────────────────────────────────────────────────────────────────────
#  OIDC (stub)
# ────────────────────────────────────────────────────────────────────

def oidc_login_url(org: dict[str, Any], state: str, redirect_uri: str) -> str:
    """Build the IdP authorize URL. Reads client_id from env keyed by org slug."""
    if not org.get("sso_idp_sso_url"):
        raise RuntimeError("Org has no SSO configured")
    import os
    client_id = os.environ.get(f"OIDC_{org['slug'].upper()}_CLIENT_ID", "")
    if not client_id:
        raise RuntimeError("OIDC client not configured")
    qs = urllib.parse.urlencode({
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid email profile",
        "state": state,
        "code_challenge_method": "S256",
        "code_challenge": _pkce_challenge(state),
    })
    sep = "&" if "?" in org["sso_idp_sso_url"] else "?"
    return f"{org['sso_idp_sso_url']}{sep}{qs}"


def _pkce_challenge(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def upsert_user_from_sso(*, org_id: str, site_id: str | None, email: str,
                         name: str, sso_subject: str, role: str = "member") -> str:
    """Create or update a user from a validated SSO assertion. Returns user id."""
    existing = db.fetch_one(
        "select id from users where org_id = $1 and (sso_subject = $2 or email = $3)",
        org_id, sso_subject, email.lower(),
    )
    if existing:
        db.execute(
            """update users set name = $1, sso_subject = $2, last_login_at = now()
               where id = $3""",
            name, sso_subject, existing["id"],
        )
        return existing["id"]
    row = db.fetch_one(
        """insert into users (org_id, site_id, email, sso_subject, role, name)
           values ($1, $2, $3, $4, $5, $6) returning id""",
        org_id, site_id, email.lower(), sso_subject, role, name,
    )
    assert row is not None
    return row["id"]


def issue_sso_session(*, user_id: str, org_id: str,
                      sso_session_id: str, ip: str | None, ua: str | None) -> str:
    return issue_session(user_id=user_id, org_id=org_id, ip=ip, ua=ua,
                         sso_session_id=sso_session_id)
