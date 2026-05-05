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
from datetime import datetime, timedelta, timezone
from typing import Any

from db import db
from auth import issue_session


_SAML_NS = {
    "saml":  "urn:oasis:names:tc:SAML:2.0:assertion",
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "ds":    "http://www.w3.org/2000/09/xmldsig#",
}

# Common SAML attribute name URIs the major IdPs emit (Okta, Azure AD, OneLogin,
# Google, generic). We map any of these to their conceptual key.
_ATTR_ALIASES = {
    "name": (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",  # fallback to first
        "name", "displayName", "displayname", "DisplayName",
        "http://schemas.microsoft.com/ws/2008/06/identity/claims/displayname",
        "User.DisplayName",
    ),
    "email": (
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "email", "mail", "Email", "User.email",
    ),
}

# Acceptable clock skew between IdP and SP. Most enterprise SAML guidance
# allows ~60s; we use 60s as a defensive default. RFC 5280 doesn't mandate.
_CLOCK_SKEW_SEC = 60


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


def saml_assert_callback(
    org: dict[str, Any],
    saml_response_b64: str,
    *,
    sp_entity_id: str | None = None,
    ip: str | None = None,
    ua: str | None = None,
) -> dict[str, Any]:
    """Validate an IdP's SAMLResponse and return the verified attrs.

    Returns: {"email": str, "name": str, "sso_subject": str, "sso_session_id": str}

    Validation pipeline (any failure = exception, do not trust the payload):
        1. Decode base64 → raw XML bytes
        2. Verify XML signature against org.sso_idp_cert_pem (XMLDSig)
        3. Locate the verified Assertion element (signature can be on the
           Response wrapping the Assertion, or directly on the Assertion)
        4. Validate Conditions (NotBefore / NotOnOrAfter ± clock skew)
        5. Validate AudienceRestriction (must list our SP entity ID, if provided)
        6. Validate Status code = Success
        7. Extract NameID, AttributeStatement, AuthnStatement.SessionIndex

    Per OASIS spec, Steps 4–6 are "MUST" checks for any production SP.
    """
    if not saml_response_b64:
        raise RuntimeError("SAML: missing SAMLResponse")
    if not org.get("sso_idp_cert_pem"):
        raise RuntimeError("SAML cert not configured for this org")

    try:
        raw = base64.b64decode(saml_response_b64)
    except Exception as e:
        raise RuntimeError(f"SAML: bad base64 — {e}")

    # Imports are local so the module loads even when signxml isn't yet
    # installed (e.g. during local stdlib-only unit tests of other helpers).
    try:
        from signxml import XMLVerifier
        from lxml import etree
    except ImportError as e:
        raise RuntimeError(
            f"SAML signature deps missing — install signxml + lxml: {e}"
        )

    # 1+2. Verify signature against the org's IdP cert
    try:
        verified = XMLVerifier().verify(raw, x509_cert=org["sso_idp_cert_pem"])
    except Exception as e:
        raise RuntimeError(f"SAML signature invalid: {e}")

    verified_xml = verified.signed_xml
    if verified_xml is None:
        raise RuntimeError("SAML: no signed XML element")

    # 3. Locate the Assertion. signxml returns the signed element — for
    #    signed-Response IdPs that's the Response, for signed-Assertion IdPs
    #    that's the Assertion directly.
    tag_local = etree.QName(verified_xml.tag).localname
    if tag_local == "Assertion":
        assertion = verified_xml
    else:
        assertion = verified_xml.find(".//saml:Assertion", _SAML_NS)
        if assertion is None:
            raise RuntimeError("SAML: no Assertion in verified payload")

    # 6. Status (when we have the Response wrapper)
    if tag_local == "Response":
        status_code_el = verified_xml.find(
            ".//samlp:Status/samlp:StatusCode", _SAML_NS,
        )
        if status_code_el is not None:
            sv = status_code_el.get("Value", "")
            if not sv.endswith(":status:Success"):
                raise RuntimeError(f"SAML: non-success status {sv}")

    # 4. Conditions / timing
    now = datetime.now(timezone.utc)
    conditions = assertion.find("saml:Conditions", _SAML_NS)
    if conditions is not None:
        nb = conditions.get("NotBefore")
        noa = conditions.get("NotOnOrAfter")
        if nb:
            nbt = _parse_iso(nb)
            if now + timedelta(seconds=_CLOCK_SKEW_SEC) < nbt:
                raise RuntimeError("SAML: assertion not yet valid (NotBefore)")
        if noa:
            noat = _parse_iso(noa)
            if now > noat + timedelta(seconds=_CLOCK_SKEW_SEC):
                raise RuntimeError("SAML: assertion expired (NotOnOrAfter)")

        # 5. Audience restriction — if the SP entity ID is supplied, our entity
        # MUST be listed. If not supplied, we skip the check.
        if sp_entity_id:
            audiences = [
                a.text.strip()
                for a in conditions.findall(
                    "saml:AudienceRestriction/saml:Audience", _SAML_NS,
                )
                if a.text
            ]
            if audiences and sp_entity_id not in audiences:
                raise RuntimeError(
                    f"SAML: audience mismatch (got {audiences!r}, want {sp_entity_id!r})"
                )

    # 7. NameID
    name_id_el = assertion.find("saml:Subject/saml:NameID", _SAML_NS)
    if name_id_el is None or not (name_id_el.text or "").strip():
        raise RuntimeError("SAML: missing NameID")
    name_id = name_id_el.text.strip()

    # SubjectConfirmationData NotOnOrAfter — additional timing
    scd = assertion.find(
        "saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData",
        _SAML_NS,
    )
    if scd is not None:
        scd_noa = scd.get("NotOnOrAfter")
        if scd_noa and now > _parse_iso(scd_noa) + timedelta(seconds=_CLOCK_SKEW_SEC):
            raise RuntimeError("SAML: subject confirmation expired")

    # AttributeStatement
    attrs: dict[str, str] = {}
    for attr in assertion.findall(
        "saml:AttributeStatement/saml:Attribute", _SAML_NS,
    ):
        name = attr.get("Name") or attr.get("FriendlyName") or ""
        values = [
            v.text.strip()
            for v in attr.findall("saml:AttributeValue", _SAML_NS)
            if v.text
        ]
        if name and values:
            attrs[name] = values[0]

    # Pick canonical email — prefer NameID if it looks like an email,
    # else look for an email-claim attribute, else fall back to NameID.
    email = name_id if "@" in name_id else ""
    for k in _ATTR_ALIASES["email"]:
        if not email and k in attrs and "@" in attrs[k]:
            email = attrs[k]
    if not email:
        # Some IdPs provide email via the unspecified-NameID + a separate attr.
        # If we still don't have one, treat as fatal (we need email to upsert).
        raise RuntimeError("SAML: no email on assertion or NameID")

    # Display name — fall through aliases
    display_name = ""
    for k in _ATTR_ALIASES["name"]:
        if k in attrs:
            display_name = attrs[k]
            break
    if not display_name:
        display_name = email

    # AuthnStatement -> SessionIndex
    session_index = ""
    authn = assertion.find("saml:AuthnStatement", _SAML_NS)
    if authn is not None:
        session_index = authn.get("SessionIndex", "") or ""

    return {
        "email":          email.lower(),
        "name":           display_name,
        "sso_subject":    name_id,
        "sso_session_id": session_index,
    }


def _parse_iso(s: str) -> datetime:
    """SAML uses 'Z' for UTC; Python's fromisoformat needs '+00:00'."""
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


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
