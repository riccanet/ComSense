from __future__ import annotations

import base64
import re
import secrets
import zlib
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlsplit

import pytest
from conftest import csrf_from, login
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lxml import etree
from signxml import XMLSigner
from sqlalchemy import select

from app.models import AuditLog, Role, SsoProvider, User
from app.security import hash_password
from app.services import sso

CONSOLE = "https://comsense.test"
IDP = "https://idp.example.com/saml"


def _keypair(cn="Test IdP"):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=365)).sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.PEM))


KEY, CERT = _keypair()
OTHER_KEY, OTHER_CERT = _keypair("Attacker")


def _t(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def make_response(provider_id, request_id, email="alice@example.com", *, sign="assertion", key=KEY, cert=CERT,
                  audience=None, recipient=None, issuer=IDP, not_after_min=5, status="Success",
                  assertion_id=None, attrs=None):
    now = datetime.now(timezone.utc)
    acs = recipient or f"{CONSOLE}/sso/{provider_id}/acs"
    aud = audience or f"{CONSOLE}/sso/{provider_id}/metadata"
    aid = assertion_id or "_a" + secrets.token_hex(8)
    attr_xml = "".join(
        f'<saml:Attribute Name="{n}"><saml:AttributeValue>{v}</saml:AttributeValue></saml:Attribute>'
        for n, v in (attrs or {}).items())
    assertion = (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}" Version="2.0" '
        f'IssueInstant="{_t(now)}"><saml:Issuer>{issuer}</saml:Issuer>'
        f'<saml:Subject><saml:NameID>{email}</saml:NameID>'
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData InResponseTo="{request_id}" Recipient="{acs}" '
        f'NotOnOrAfter="{_t(now + timedelta(minutes=not_after_min))}"/></saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{_t(now - timedelta(minutes=1))}" NotOnOrAfter="{_t(now + timedelta(minutes=not_after_min))}">'
        f'<saml:AudienceRestriction><saml:Audience>{aud}</saml:Audience></saml:AudienceRestriction></saml:Conditions>'
        f'<saml:AuthnStatement AuthnInstant="{_t(now)}"/>'
        + (f"<saml:AttributeStatement>{attr_xml}</saml:AttributeStatement>" if attr_xml else "")
        + "</saml:Assertion>"
    )
    signer = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#")
    if sign == "assertion":
        signed = signer.sign(etree.fromstring(assertion), key=key, cert=cert)
        assertion = etree.tostring(signed).decode()
    response = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r{secrets.token_hex(8)}" '
        f'Version="2.0" IssueInstant="{_t(now)}" Destination="{acs}" InResponseTo="{request_id}">'
        f'<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">{issuer}</saml:Issuer>'
        f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:{status}"/></samlp:Status>'
        f'{assertion}</samlp:Response>'
    )
    if sign == "response":
        response = etree.tostring(signer.sign(etree.fromstring(response), key=key, cert=cert)).decode()
    return base64.b64encode(response.encode()).decode()


@pytest.fixture
def provider(db):
    p = SsoProvider(kind="entra", name="Entra", enabled=True, idp_entity_id=IDP,
                    idp_sso_url="https://idp.example.com/sso", idp_cert=CERT.decode())
    db.add(p)
    db.commit()
    return p


def start(client, provider_id):
    r = client.get(f"/sso/{provider_id}/login", follow_redirects=False)
    assert r.status_code == 303
    q = parse_qs(urlsplit(r.headers["location"]).query)
    xml = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15)
    req = etree.fromstring(xml)
    assert req.get("AssertionConsumerServiceURL") == f"{CONSOLE}/sso/{provider_id}/acs"
    return req.get("ID")


def finish(client, provider_id, saml_response):
    return client.post(f"/sso/{provider_id}/acs", data={"SAMLResponse": saml_response}, follow_redirects=False)


def signed_in(client):
    return client.get("/devices", follow_redirects=False).status_code == 200


def test_sign_in_with_a_signed_assertion(client, db, provider):
    db.add(User(username="alice", email="Alice@Example.com", password_hash=hash_password("x" * 20), role=Role.operator))
    db.commit()
    assert "Entra" in client.get("/login").text
    rid = start(client, provider.id)
    r = finish(client, provider.id, make_response(provider.id, rid))
    assert r.status_code == 200 and 'http-equiv="refresh"' in r.text and "url=/" in r.text
    assert signed_in(client)
    assert db.scalar(select(AuditLog).where(AuditLog.action == "login")).detail == "mfa=sso:Entra"


def test_signed_response_and_metadata_import(client, db):
    metadata = f"""<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP}">
      <md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data>
          <ds:X509Certificate>{"".join(CERT.decode().splitlines()[1:-1])}</ds:X509Certificate>
        </ds:X509Data></ds:KeyInfo></md:KeyDescriptor>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.com/post"/>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.com/redirect"/>
      </md:IDPSSODescriptor></md:EntityDescriptor>"""
    csrf = login(client)
    r = client.post("/settings/sso", data={"kind": "google", "csrf_token": csrf}, follow_redirects=False)
    pid = int(r.headers["location"].rsplit("/", 1)[1])
    page = client.get(f"/settings/sso/{pid}").text
    assert f"{CONSOLE}/sso/{pid}/acs" in page and f"{CONSOLE}/sso/{pid}/metadata" in page
    client.post(f"/settings/sso/{pid}", data={"metadata": metadata, "name": "Google", "enabled": "true",
                                              "auto_create": "true", "default_role": "viewer", "csrf_token": csrf})
    db.expire_all()
    p = db.get(SsoProvider, pid)
    assert (p.idp_entity_id, p.idp_sso_url, p.enabled) == (IDP, "https://idp.example.com/redirect", True)
    assert "Test IdP" in client.get(f"/settings/sso/{pid}").text
    assert f'entityID="{CONSOLE}/sso/{pid}/metadata"' in client.get(f"/sso/{pid}/metadata").text

    client.post("/logout", data={"csrf_token": csrf_from(client.get("/devices").text)})
    rid = start(client, pid)
    finish(client, pid, make_response(pid, rid, email="new.person@example.com", sign="response"))
    assert signed_in(client)
    db.expire_all()
    created = db.scalar(select(User).where(User.email == "new.person@example.com"))
    assert created.role == Role.viewer and not created.must_change_password


@pytest.mark.parametrize("change, message", [
    ({"key": OTHER_KEY, "cert": OTHER_CERT}, "signature is not valid"),
    ({"audience": "https://other.example/sp"}, "different service"),
    ({"recipient": "https://evil.example/acs"}, "ACS URL"),
    ({"issuer": "https://other-idp.example"}, "different issuer"),
    ({"not_after_min": -10}, "expired"),
    ({"status": "Requester"}, "did not sign you in"),
])
def test_bad_responses_are_refused(client, db, provider, change, message):
    db.add(User(username="alice", email="alice@example.com", password_hash=hash_password("x" * 20)))
    db.commit()
    rid = start(client, provider.id)
    r = finish(client, provider.id, make_response(provider.id, rid, **change))
    assert "url=/login" in r.text and not signed_in(client)
    assert message in client.get("/login").text
    assert db.scalar(select(AuditLog).where(AuditLog.action == "login.sso_failed")) is not None


def test_unsolicited_replayed_and_unknown(client, db, provider):
    db.add(User(username="alice", email="alice@example.com", password_hash=hash_password("x" * 20)))
    db.commit()
    # Not started from this console (IdP-initiated or forged request id).
    finish(client, provider.id, make_response(provider.id, "_not-ours"))
    assert not signed_in(client)
    # A request started in another browser (no nonce cookie here).
    rid = start(client, provider.id)
    client.cookies.delete(sso.NONCE_COOKIE, path="/sso/")
    finish(client, provider.id, make_response(provider.id, rid))
    assert not signed_in(client)
    # Replay of a used assertion.
    rid = start(client, provider.id)
    resp = make_response(provider.id, rid, assertion_id="_same")
    finish(client, provider.id, resp)
    assert signed_in(client)
    client.cookies.clear()
    start(client, provider.id)
    finish(client, provider.id, resp)
    assert not signed_in(client)
    # Unknown user without automatic creation.
    client.cookies.clear()
    rid = start(client, provider.id)
    finish(client, provider.id, make_response(provider.id, rid, email="stranger@example.com"))
    assert not signed_in(client)
    assert "is not a ComSense user" in client.get("/login").text


def test_sso_counts_as_mfa(client, db, provider):
    from app.services.appsettings import SecuritySettings, save_security_settings

    save_security_settings(db, SecuritySettings(mfa_required="all", allow_totp=True, allow_email=False), "t")
    db.add(User(username="alice", email="alice@example.com", password_hash=hash_password("x" * 20)))
    db.commit()
    rid = start(client, provider.id)
    finish(client, provider.id, make_response(provider.id, rid, attrs={
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "alice@example.com"}))
    # No "set up two-factor sign-in" detour: the provider applied its MFA.
    assert client.get("/devices", follow_redirects=False).status_code == 200


def test_sso_settings_are_admin_only(client, db):
    db.add(User(username="op", password_hash=hash_password("operator-password-1"), role=Role.operator))
    db.commit()
    login(client, "op", "operator-password-1")
    assert client.get("/settings/sso").status_code == 403


def test_metadata_without_redirect_binding_is_refused():
    with pytest.raises(sso.SsoError, match="HTTP-Redirect"):
        sso.parse_idp_metadata(f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
                               f'entityID="x"><md:IDPSSODescriptor/></md:EntityDescriptor>')
    with pytest.raises(sso.SsoError):
        sso.parse_idp_metadata('<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>')
    assert re.search("BEGIN", sso.parse_idp_metadata(
        f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="x"><md:IDPSSODescriptor>'
        f'<md:KeyDescriptor><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>'
        f'{"".join(CERT.decode().splitlines()[1:-1])}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>'
        f'<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://i/s"/>'
        f'</md:IDPSSODescriptor></md:EntityDescriptor>')["cert"])


def test_signature_wrapping_cannot_change_the_user(client, db, provider):
    db.add_all([User(username="alice", email="alice@example.com", password_hash=hash_password("x" * 20)),
                User(username="boss", email="boss@example.com", password_hash=hash_password("x" * 20),
                     role=Role.admin)])
    db.commit()
    rid = start(client, provider.id)
    genuine = base64.b64decode(make_response(provider.id, rid, email="alice@example.com")).decode()
    # Put a forged, unsigned assertion for an admin in front of the signed one.
    forged = re.search(r"<saml:Assertion.*?</saml:Assertion>", genuine, re.S).group(0)
    forged = re.sub(r"<ds:Signature.*?</ds:Signature>", "", forged, flags=re.S)
    forged = forged.replace("alice@example.com", "boss@example.com").replace('ID="_a', 'ID="_forged')
    tampered = genuine.replace("<saml:Assertion", forged.replace("</saml:Assertion>", "</saml:Assertion>") + "<saml:Assertion", 1)
    finish(client, provider.id, base64.b64encode(tampered.encode()).decode())
    page = client.get("/account").text if signed_in(client) else ""
    assert "boss" not in page
