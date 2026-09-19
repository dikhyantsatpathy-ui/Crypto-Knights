"""DigiLocker provider tests: mock is the default, live activates on creds,
consent is required before any holder data, and failures stay honest."""

import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

import digilocker_provider as dg  # noqa: E402


def _pop(*keys):
    for k in keys:
        os.environ.pop(k, None)


def test_mock_is_the_default():
    _pop("DIGILOCKER_CLIENT_ID", "DIGILOCKER_CLIENT_SECRET")
    out = dg.digilocker_lookup("pan", "ABCDP2234A", declared_name="[Aadhaar Redacted]")
    assert out["registered"] is True
    assert out["status"] == "ISSUED"
    assert out["holder_match"] is True
    assert out["sample_data"] is True
    assert out["live"] is False


def test_mock_unknown_document():
    _pop("DIGILOCKER_CLIENT_ID", "DIGILOCKER_CLIENT_SECRET")
    out = dg.digilocker_lookup("pan", "ZZZZZ0000Z")
    assert out["registered"] is False


def test_live_requires_holder_consent_token():
    os.environ["DIGILOCKER_CLIENT_ID"] = "cid"
    os.environ["DIGILOCKER_CLIENT_SECRET"] = "csec"
    try:
        out = dg.digilocker_lookup("aadhaar", "234512345670")
        assert out["registered"] is None
        assert "consent" in out["reason"]
        assert out["live"] is True
    finally:
        _pop("DIGILOCKER_CLIENT_ID", "DIGILOCKER_CLIENT_SECRET")


def test_live_issued_document_match(monkeypatch):
    seen = {}

    def fake_get(url, **kw):
        seen["auth"] = kw.get("headers", {}).get("Authorization")
        seen["params"] = kw.get("params")

        class R:
            status_code = 200

            def json(self):
                return {"documents": [
                    {"uri": "in.gov.uidai-ADHAR-234512345670",
                     "number": "234512345670", "name": "[Aadhaar Redacted]"}]}

        return R()

    monkeypatch.setattr(requests, "get", fake_get)
    os.environ["DIGILOCKER_CLIENT_ID"] = "cid"
    os.environ["DIGILOCKER_CLIENT_SECRET"] = "csec"
    try:
        out = dg.digilocker_lookup("aadhaar", "234512345670",
                                   declared_name="[Aadhaar Redacted]",
                                   access_token="holder-token")
        assert out["registered"] is True
        assert out["holder_match"] is True
        assert out["sample_data"] is False
        assert seen["auth"] == "Bearer holder-token"
    finally:
        _pop("DIGILOCKER_CLIENT_ID", "DIGILOCKER_CLIENT_SECRET")


def test_live_unreachable_stays_impartial(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("dns")

    monkeypatch.setattr(requests, "get", boom)
    os.environ["DIGILOCKER_CLIENT_ID"] = "cid"
    os.environ["DIGILOCKER_CLIENT_SECRET"] = "csec"
    try:
        out = dg.digilocker_lookup("pan", "ABCDP2234A", access_token="t")
        assert out["registered"] is None
        assert "unreachable" in out["reason"]
    finally:
        _pop("DIGILOCKER_CLIENT_ID", "DIGILOCKER_CLIENT_SECRET")


def test_coverage_shape():
    _pop("DIGILOCKER_CLIENT_ID", "DIGILOCKER_CLIENT_SECRET")
    cov = dg.digilocker_coverage()
    assert cov == {"configured": False, "live": False, "provider": "mock",
                   "mock": True, "doctypes": sorted(dg._MOCK_DOCS),
                   "auth_url_ready": False}
