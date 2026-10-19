"""SAML 2.0 single sign-on (service provider side) for Google Workspace, Microsoft Entra ID, Cisco Duo
and other SAML identity providers.

Flow (SP-initiated, the only one accepted):
1. /sso/<id>/login sends the browser to the provider with an AuthnRequest (HTTP-Redirect binding).
   The request id is remembered with a random nonce, which is also set as a cookie in the browser.
2. The provider posts a signed SAMLResponse to /sso/<id>/acs (HTTP-POST binding).
3. validate_response() checks it: signature with the provider's certificate (signxml; only the signed
   part is used afterwards), issuer, status, audience, recipient, validity times, that it answers a
   request we sent from this browser, and that the assertion was not used before. Encrypted
   assertions are not supported.
4. The user is matched by email (or created, if the provider allows it) and signed in. The provider
   enforces its own MFA, so the sign-in counts as two-factor.

Pending requests and used assertion ids are kept in memory: the console runs as one process.
"""
from __future__ import annotations

import base64
import secrets
import threading
import time
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from lxml import etree

from ..models import SsoProvider

NS = {
    "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "ds": "http://www.w3.org/2000/09/xmldsig#",
}
SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
REDIRECT_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
CLOCK_SKEW = timedelta(minutes=3)
REQUEST_TTL = 600  # seconds to complete a sign-in at the provider
MAX_RESPONSE = 512 * 1024
NONCE_COOKIE = "csfm_sso"

# Setup defaults and help per kind of provider.
KINDS: dict[str, dict[str, str]] = {
    "google": {
        "label": "Google Workspace",
        "email_attribute": "",
        "help": "Google Admin console > Apps > Web and mobile apps > Add app > Add custom SAML app. "
                "Download the IdP metadata and paste it below. On the service provider step enter the ACS URL "
                "and Entity ID shown here, Name ID format EMAIL, Name ID Basic Information > Primary email. "
                "Turn the app on for the users or groups that may sign in.",
    },
    "entra": {
        "label": "Microsoft Entra ID",
        "email_attribute": "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        "help": "Entra admin center > Enterprise applications > New application > Create your own application "
                "(non-gallery) > Single sign-on > SAML. Identifier (Entity ID) and Reply URL (ACS URL): the "
                "values shown here. Download the Federation Metadata XML and paste it below. Assign the users "
                "or groups that may sign in; Conditional Access applies MFA.",
    },
    "duo": {
        "label": "Cisco Duo",
        "email_attribute": "",
        "help": "Duo Admin Panel > Applications > Protect an Application > Generic SAML Service Provider "
                "(Duo Single Sign-On). Entity ID and Assertion Consumer Service URL: the values shown here; "
                "NameID format: email address. Download the metadata XML and paste it below. Duo applies its "
                "MFA and policies to every sign-in.",
    },
    "saml": {
        "label": "Other SAML 2.0 provider",
        "email_attribute": "",
        "help": "Register ComSense as a SAML 2.0 service provider with the Entity ID and ACS URL shown here "
                "(HTTP-POST binding, signed responses or assertions, NameID or an attribute with the email "
                "address). Paste the provider's metadata XML, or fill in its entity ID, sign-in URL and "
                "signing certificate.",
    },
}
EMAIL_ATTRIBUTES = (
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "email", "Email", "mail", "emailAddress",
    "urn:oid:0.9.2342.19200300.100.1.3",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
)


class SsoError(ValueError):
    pass


def sp_entity_id(console_url: str, provider: SsoProvider) -> str:
    return f"{console_url}/sso/{provider.id}/metadata"


def acs_url(console_url: str, provider: SsoProvider) -> str:
    return f"{console_url}/sso/{provider.id}/acs"


def _parser() -> etree.XMLParser:
    return etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False, remove_comments=True)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as exc:
        raise SsoError(f"Invalid time in the response: {value}") from exc


# --------------------------------------------------------------- pending requests

@dataclass
class _Pending:
    provider_id: int
    nonce: str
    created: float


_pending: dict[str, _Pending] = {}
_used_assertions: dict[str, float] = {}
_lock = threading.Lock()


def _expire() -> None:
    now = time.monotonic()
    for key in [k for k, p in _pending.items() if now - p.created > REQUEST_TTL]:
        _pending.pop(key, None)
    for key in [k for k, t in _used_assertions.items() if now > t]:
        _used_assertions.pop(key, None)


def login_redirect(provider: SsoProvider, console_url: str) -> tuple[str, str]:
    """(URL to send the browser to, nonce to set as the NONCE_COOKIE)."""
    if not provider.idp_sso_url:
        raise SsoError("The provider has no sign-in URL configured")
    request_id = "_" + secrets.token_hex(20)
    nonce = secrets.token_urlsafe(24)
    xml = (
        f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{request_id}" '
        f'Version="2.0" IssueInstant="{_iso(_now())}" Destination="{_xml_attr(provider.idp_sso_url)}" '
        f'AssertionConsumerServiceURL="{_xml_attr(acs_url(console_url, provider))}" ProtocolBinding="{POST_BINDING}">'
        f"<saml:Issuer>{_xml_text(sp_entity_id(console_url, provider))}</saml:Issuer>"
        '<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" AllowCreate="true"/>'
        "</samlp:AuthnRequest>"
    )
    deflater = zlib.compressobj(9, zlib.DEFLATED, -15)
    encoded = base64.b64encode(deflater.compress(xml.encode()) + deflater.flush()).decode()
    with _lock:
        _expire()
        _pending[request_id] = _Pending(provider.id, nonce, time.monotonic())
    sep = "&" if "?" in provider.idp_sso_url else "?"
    return provider.idp_sso_url + sep + urlencode({"SAMLRequest": encoded}), nonce


def _xml_attr(value: str) -> str:
    return value.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")


def _xml_text(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;")


# --------------------------------------------------------------- the response

@dataclass
class SsoIdentity:
    email: str
    name_id: str
    display_name: str


def _certs(pem_text: str) -> list[str]:
    certs, block = [], []
    for line in pem_text.strip().splitlines():
        block.append(line.strip())
        if "END CERTIFICATE" in line:
            certs.append("\n".join(block))
            block = []
    if not certs and pem_text.strip():
        body = "".join(pem_text.split())
        certs.append(f"-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----")
    return certs


def _verify(data: bytes, provider: SsoProvider) -> etree._Element:
    """The signed element (Response or Assertion), verified with one of the provider's certificates."""
    from signxml import XMLVerifier
    from signxml.exceptions import InvalidInput, InvalidSignature

    certs = _certs(provider.idp_cert)
    if not certs:
        raise SsoError("The provider has no signing certificate configured")
    last: Exception | None = None
    for cert in certs:
        try:
            result = XMLVerifier().verify(data, x509_cert=cert)
            return result.signed_xml
        except (InvalidSignature, InvalidInput) as exc:
            last = exc
        except Exception as exc:  # noqa: BLE001 - malformed input of any kind is a failed sign-in
            last = exc
    raise SsoError(f"The response's signature is not valid for the configured certificate ({last})")


def _text(el: etree._Element | None) -> str:
    return (el.text or "").strip() if el is not None else ""


def validate_response(
    saml_response: str, provider: SsoProvider, console_url: str, nonce_cookie: str | None
) -> SsoIdentity:
    try:
        data = base64.b64decode(saml_response, validate=False)
    except (ValueError, TypeError) as exc:
        raise SsoError("The SAML response is not valid base64") from exc
    if not data or len(data) > MAX_RESPONSE:
        raise SsoError("The SAML response is empty or too large")
    try:
        doc = etree.fromstring(data, parser=_parser())
    except etree.XMLSyntaxError as exc:
        raise SsoError("The SAML response is not valid XML") from exc
    if doc.find(".//saml:EncryptedAssertion", NS) is not None:
        raise SsoError("Encrypted assertions are not supported; turn off assertion encryption at the provider")

    signed = _verify(data, provider)
    if signed.tag == f"{{{NS['samlp']}}}Response":
        assertions = signed.findall("saml:Assertion", NS)
        status_root = signed
    elif signed.tag == f"{{{NS['saml']}}}Assertion":
        assertions = [signed]
        status_root = doc
    else:
        raise SsoError("The signature covers neither the response nor the assertion")
    if len(assertions) != 1:
        raise SsoError("Expected exactly one assertion")
    assertion = assertions[0]

    status = status_root.find("samlp:Status/samlp:StatusCode", NS)
    if status is None or status.get("Value") != SUCCESS:
        detail = _text(status_root.find("samlp:Status/samlp:StatusMessage", NS))
        raise SsoError("The provider did not sign you in" + (f": {detail}" if detail else ""))

    if _text(assertion.find("saml:Issuer", NS)) != provider.idp_entity_id:
        raise SsoError("The assertion comes from a different issuer than the one configured")

    now = _now()
    conditions = assertion.find("saml:Conditions", NS)
    if conditions is None:
        raise SsoError("The assertion has no conditions")
    not_before = _parse_time(conditions.get("NotBefore"))
    not_after = _parse_time(conditions.get("NotOnOrAfter"))
    if not_before and now + CLOCK_SKEW < not_before:
        raise SsoError("The assertion is not valid yet (check the server clocks)")
    if not_after and now - CLOCK_SKEW >= not_after:
        raise SsoError("The assertion has expired")
    audiences = [_text(a) for a in conditions.findall("saml:AudienceRestriction/saml:Audience", NS)]
    if sp_entity_id(console_url, provider) not in audiences:
        raise SsoError("The assertion is meant for a different service (check the Entity ID at the provider)")

    acs = acs_url(console_url, provider)
    request_id = None
    for confirmation in assertion.findall("saml:Subject/saml:SubjectConfirmation", NS):
        if confirmation.get("Method") != BEARER:
            continue
        data_el = confirmation.find("saml:SubjectConfirmationData", NS)
        if data_el is None:
            continue
        expires = _parse_time(data_el.get("NotOnOrAfter"))
        if data_el.get("Recipient") == acs and expires and now - CLOCK_SKEW < expires:
            request_id = data_el.get("InResponseTo")
            break
    else:
        raise SsoError("The assertion is not addressed to this console's ACS URL, or has expired")

    with _lock:
        _expire()
        pending = _pending.pop(request_id or "", None)
        if pending is None or pending.provider_id != provider.id:
            raise SsoError("This sign-in was not started here or has timed out; start again from the sign-in page")
        if not nonce_cookie or not secrets.compare_digest(pending.nonce, nonce_cookie):
            raise SsoError("This sign-in was started in a different browser; start again from the sign-in page")
        assertion_id = assertion.get("ID") or ""
        if not assertion_id or assertion_id in _used_assertions:
            raise SsoError("This assertion was already used")
        _used_assertions[assertion_id] = time.monotonic() + 3600

    name_id = _text(assertion.find("saml:Subject/saml:NameID", NS))
    attributes: dict[str, str] = {}
    for attr in assertion.findall("saml:AttributeStatement/saml:Attribute", NS):
        value = _text(attr.find("saml:AttributeValue", NS))
        if value:
            attributes[attr.get("Name", "")] = value
            if attr.get("FriendlyName"):
                attributes.setdefault(attr.get("FriendlyName"), value)
    names = (provider.email_attribute,) if provider.email_attribute else EMAIL_ATTRIBUTES
    email = next((attributes[n] for n in names if attributes.get(n)), "") or name_id
    if "@" not in email:
        raise SsoError("The provider did not send an email address (set the email attribute or NameID to email)")
    display = attributes.get("http://schemas.microsoft.com/identity/claims/displayname") or attributes.get(
        "displayName", "")
    return SsoIdentity(email=email.strip().lower(), name_id=name_id, display_name=display)


# --------------------------------------------------------------- metadata

def parse_idp_metadata(xml: str) -> dict[str, str]:
    """entity_id, sso_url and cert (PEM) from a provider's SAML metadata."""
    try:
        root = etree.fromstring(xml.strip().encode(), parser=_parser())
    except etree.XMLSyntaxError as exc:
        raise SsoError("The metadata is not valid XML") from exc
    if root.tag == f"{{{NS['md']}}}EntitiesDescriptor":
        found = root.find("md:EntityDescriptor", NS)
        if found is None:
            raise SsoError("The metadata has no EntityDescriptor")
        root = found
    if root.tag != f"{{{NS['md']}}}EntityDescriptor":
        raise SsoError("This is not SAML metadata (no EntityDescriptor)")
    idp = root.find("md:IDPSSODescriptor", NS)
    if idp is None:
        raise SsoError("The metadata does not describe an identity provider (no IDPSSODescriptor)")
    sso_url = ""
    for service in idp.findall("md:SingleSignOnService", NS):
        if service.get("Binding") == REDIRECT_BINDING:
            sso_url = service.get("Location", "")
            break
    if not sso_url:
        raise SsoError("The provider offers no HTTP-Redirect sign-in URL")
    certs = []
    for key in idp.findall("md:KeyDescriptor", NS):
        if key.get("use") not in (None, "signing"):
            continue
        for cert in key.findall(".//ds:X509Certificate", NS):
            body = "".join((cert.text or "").split())
            if body:
                pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(
                    body[i:i + 64] for i in range(0, len(body), 64)) + "\n-----END CERTIFICATE-----"
                if pem not in certs:
                    certs.append(pem)
    if not certs:
        raise SsoError("The metadata has no signing certificate")
    return {"entity_id": root.get("entityID", ""), "sso_url": sso_url, "cert": "\n".join(certs)}


def cert_summary(pem_text: str) -> list[dict[str, Any]]:
    """Subject and expiry of each configured certificate, for the settings page."""
    from cryptography import x509

    out = []
    for pem in _certs(pem_text):
        try:
            cert = x509.load_pem_x509_certificate(pem.encode())
        except ValueError:
            out.append({"subject": "unreadable certificate", "expires": None})
            continue
        out.append({"subject": cert.subject.rfc4514_string(), "expires": cert.not_valid_after_utc})
    return out


def sp_metadata(console_url: str, provider: SsoProvider) -> str:
    return (
        f'<?xml version="1.0"?>\n<md:EntityDescriptor xmlns:md="{NS["md"]}" '
        f'entityID="{_xml_attr(sp_entity_id(console_url, provider))}">\n'
        f'  <md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
        f'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">\n'
        f'    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>\n'
        f'    <md:AssertionConsumerService Binding="{POST_BINDING}" '
        f'Location="{_xml_attr(acs_url(console_url, provider))}" index="0" isDefault="true"/>\n'
        f'  </md:SPSSODescriptor>\n</md:EntityDescriptor>\n'
    )
