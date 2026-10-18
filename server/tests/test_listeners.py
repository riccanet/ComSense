from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

from conftest import auth, enroll, make_key
from cryptography import x509

from app.enrollment import make_code, parse_code
from app.tls import RENEW_BEFORE, ensure_agent_tls


def test_web_listener_does_not_serve_agent_api(client, db):
    assert client.post("/api/agent/v1/enroll", json={"enrollment_key": make_key(db)}).status_code == 404
    assert client.get("/api/agent/v1/ping").status_code == 404


def test_agent_listener_serves_only_agent_api(agent):
    for path in ("/login", "/", "/devices", "/static/style.css", "/keys"):
        resp = agent.get(path)
        assert resp.status_code == 404, path
        assert resp.headers["content-type"].startswith("application/json")
    assert agent.get("/healthz").json() == {"status": "ok"}


def test_enrollment_code_round_trip():
    code = make_code("https://fw.example.com:10443", "csfm_enr_abc", "PIN=")
    assert parse_code(code) == {"url": "https://fw.example.com:10443", "key": "csfm_enr_abc", "pin": "PIN="}
    assert "pin" not in parse_code(make_code("https://x:10443", "k", None))


def test_self_issued_certificate_keeps_its_pin_across_renewal(settings):
    settings = replace(settings, public_url="https://comsense.example.com", agent_tls_names="203.0.113.7")
    first = ensure_agent_tls(settings)
    assert first.self_signed
    cert = x509.load_pem_x509_certificate(first.cert_file.read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "comsense.example.com" in san.get_values_for_type(x509.DNSName)
    assert [str(i) for i in san.get_values_for_type(x509.IPAddress)] == ["203.0.113.7"]
    assert (first.key_file.stat().st_mode & 0o777) == 0o600

    # Unchanged on restart; reissued with the same key when close to expiry.
    assert ensure_agent_tls(settings).cert_file.read_bytes() == first.cert_file.read_bytes()
    later = first.not_after - RENEW_BEFORE + timedelta(days=1)
    renewed = ensure_agent_tls(settings, now=later)
    assert renewed.not_after > first.not_after
    assert renewed.pin == first.pin


def test_provided_certificate_is_used_as_is(settings, tmp_path):
    generated = ensure_agent_tls(replace(settings, data_dir=tmp_path / "other"))
    provided = replace(
        settings, agent_tls_cert=str(generated.cert_file), agent_tls_key=str(generated.key_file)
    )
    tls = ensure_agent_tls(provided)
    assert not tls.self_signed
    assert tls.cert_file == generated.cert_file
    assert tls.not_after > datetime.now(timezone.utc)


def test_repeated_bad_tokens_are_blocked(agent, db):
    creds = enroll(agent, make_key(db))
    for _ in range(20):
        assert agent.post("/api/agent/v1/checkin", json={}, headers=auth("csfm_dev_wrong")).status_code == 401
    assert agent.post("/api/agent/v1/checkin", json={}, headers=auth("csfm_dev_wrong")).status_code == 429
    # The block is per address and applies to everything from it while it lasts.
    assert agent.post("/api/agent/v1/checkin", json={}, headers=auth(creds["token"])).status_code == 429
