"""SAML assertion parsing tests.

We can't easily test signxml's signature-verification path without
generating a signed XML with a real keypair (that's signxml's own
contract — we trust it the same way we trust cryptography). What we
test here is the *post-signature* validation pipeline: timing,
audience, NameID/attribute extraction, error paths.

We monkey-patch XMLVerifier to bypass signature verification and
return the parsed XML element directly.
"""
from __future__ import annotations

import base64
import sys
import os
from datetime import datetime, timedelta, timezone

# Add parent dir to sys.path so `import sso` works
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _now_iso(delta_seconds: int = 0) -> str:
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)) \
        .strftime("%Y-%m-%dT%H:%M:%SZ")


def _wrap(saml_response_xml: str) -> str:
    return base64.b64encode(saml_response_xml.encode()).decode()


def _build_assertion(
    *,
    email: str = "marcus@equinox.com",
    name_id: str | None = None,
    name_attr: str = "Marcus Hale",
    audience: str = "https://atlas.elhhealth.app/api/sso/metadata",
    not_before_offset: int = -60,
    not_on_or_after_offset: int = 600,
    session_index: str = "abc-123",
    status_success: bool = True,
) -> str:
    """Build a SAML Response XML (unsigned — we patch the verifier)."""
    nb = _now_iso(not_before_offset)
    noa = _now_iso(not_on_or_after_offset)
    nameid_value = name_id if name_id is not None else email
    status_xml = (
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        if status_success else
        '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></samlp:Status>'
    )
    return f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                                ID="_resp1" Version="2.0" IssueInstant="{_now_iso()}">
  {status_xml}
  <saml:Assertion ID="_assert1" Version="2.0" IssueInstant="{_now_iso()}">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{nameid_value}</saml:NameID>
      <saml:SubjectConfirmation>
        <saml:SubjectConfirmationData NotOnOrAfter="{noa}"/>
      </saml:SubjectConfirmation>
    </saml:Subject>
    <saml:Conditions NotBefore="{nb}" NotOnOrAfter="{noa}">
      <saml:AudienceRestriction>
        <saml:Audience>{audience}</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>
    <saml:AuthnStatement AuthnInstant="{_now_iso()}" SessionIndex="{session_index}">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>
    <saml:AttributeStatement>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress">
        <saml:AttributeValue>{email}</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name">
        <saml:AttributeValue>{name_attr}</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>"""


class _FakeVerified:
    def __init__(self, xml_bytes: bytes):
        from lxml import etree
        self.signed_xml = etree.fromstring(xml_bytes)


class _FakeVerifier:
    """Stand-in for signxml.XMLVerifier — bypasses signature check."""
    def verify(self, raw_bytes, x509_cert=None, **kwargs):
        return _FakeVerified(raw_bytes)


def _patch_verifier(monkeypatch_target_module):
    """Patch sso's signxml import to return our fake verifier. Returns
    a context that restores it."""
    import sso
    # Pre-import so the local-import inside saml_assert_callback finds it
    import signxml as _real
    monkeypatch_target_module._FAKE_VERIFIER = _FakeVerifier  # noqa


def _run_with_patch(fn):
    """Run a test fn with XMLVerifier patched to bypass signature."""
    import signxml
    original = signxml.XMLVerifier
    signxml.XMLVerifier = _FakeVerifier
    try:
        fn()
    finally:
        signxml.XMLVerifier = original


def test_happy_path():
    import sso
    org = {"sso_idp_cert_pem": "fake-cert-pem-not-used-in-test"}
    xml = _build_assertion(email="marcus@equinox.com", name_attr="Marcus Hale")
    def go():
        attrs = sso.saml_assert_callback(
            org, _wrap(xml),
            sp_entity_id="https://atlas.elhhealth.app/api/sso/metadata",
        )
        assert attrs["email"] == "marcus@equinox.com"
        assert attrs["name"] == "Marcus Hale"
        assert attrs["sso_subject"] == "marcus@equinox.com"
        assert attrs["sso_session_id"] == "abc-123"
    _run_with_patch(go)


def test_expired_assertion_rejected():
    import sso
    org = {"sso_idp_cert_pem": "fake"}
    # NotOnOrAfter 10 minutes ago
    xml = _build_assertion(
        not_before_offset=-3600, not_on_or_after_offset=-600,
    )
    def go():
        try:
            sso.saml_assert_callback(org, _wrap(xml))
        except RuntimeError as e:
            assert "expired" in str(e).lower()
            return
        assert False, "expected expired-rejection"
    _run_with_patch(go)


def test_audience_mismatch_rejected():
    import sso
    org = {"sso_idp_cert_pem": "fake"}
    xml = _build_assertion(audience="https://wrong-audience.example/")
    def go():
        try:
            sso.saml_assert_callback(
                org, _wrap(xml),
                sp_entity_id="https://atlas.elhhealth.app/api/sso/metadata",
            )
        except RuntimeError as e:
            assert "audience" in str(e).lower()
            return
        assert False, "expected audience-mismatch"
    _run_with_patch(go)


def test_status_failure_rejected():
    import sso
    org = {"sso_idp_cert_pem": "fake"}
    xml = _build_assertion(status_success=False)
    def go():
        try:
            sso.saml_assert_callback(org, _wrap(xml))
        except RuntimeError as e:
            assert "non-success" in str(e).lower() or "status" in str(e).lower()
            return
        assert False, "expected status-rejection"
    _run_with_patch(go)


def test_missing_cert_rejected():
    import sso
    org = {}  # no cert
    try:
        sso.saml_assert_callback(org, _wrap(_build_assertion()))
    except RuntimeError as e:
        assert "cert" in str(e).lower()
        return
    assert False, "expected missing-cert rejection"


def test_email_from_attribute_when_nameid_unspecified():
    import sso
    org = {"sso_idp_cert_pem": "fake"}
    xml = _build_assertion(
        email="marcus@equinox.com",
        name_id="ms-uuid-not-an-email",  # NameID is opaque, not email
    )
    def go():
        attrs = sso.saml_assert_callback(org, _wrap(xml))
        # Email should come from the AttributeStatement, not NameID
        assert attrs["email"] == "marcus@equinox.com"
        assert attrs["sso_subject"] == "ms-uuid-not-an-email"
    _run_with_patch(go)


def test_session_index_optional():
    import sso
    org = {"sso_idp_cert_pem": "fake"}
    # Empty session index (some IdPs don't issue one)
    xml = _build_assertion(session_index="")
    def go():
        attrs = sso.saml_assert_callback(org, _wrap(xml))
        assert attrs["sso_session_id"] == ""
        assert attrs["email"]  # other fields still good
    _run_with_patch(go)


def test_bad_base64_rejected():
    import sso
    org = {"sso_idp_cert_pem": "fake"}
    try:
        sso.saml_assert_callback(org, "this is not valid base64 !!@@##")
    except RuntimeError as e:
        # Either base64 error or signxml error — both fine, both rejections
        assert "SAML" in str(e) or "base64" in str(e).lower() or "invalid" in str(e).lower()
        return
    assert False, "expected base64 rejection"


if __name__ == "__main__":
    import sys, traceback
    fns = [v for k, v in list(globals().items()) if k.startswith("test_") and callable(v)]
    fails = 0
    for fn in fns:
        try:
            fn(); print(f"  ✓ {fn.__name__}")
        except Exception:
            fails += 1
            print(f"  ✗ {fn.__name__}")
            traceback.print_exc()
    print(f"\n{len(fns) - fails}/{len(fns)} passed")
    sys.exit(1 if fails else 0)
