"""Registry-provider layer tests: mock is the default, a configured
IDV_<REGKEY>_URL activates the live HTTP adapter, the response mapping is
correct, and a failing live registry degrades to an honest 'needs review'."""

import os
import sys
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "app"))

import verification_providers as vp  # noqa: E402

SAMPLE_PAN = "ABCDP2234" + vp._pan_check_char("ABCDP2234")


def _pop(key):
    os.environ.pop(key, None)


def test_mock_is_the_default_provider():
    _pop("IDV_PAN_NSDL_URL")
    assert isinstance(vp.get_provider("pan_nsdl"), vp.MockProvider)
    out = vp.registry_lookup("pan_nsdl", SAMPLE_PAN)
    assert out["registered"] is True
    assert out["sample_data"] is True
    assert out["provider"] == "mock"
    assert out["live"] is False


def test_unknown_registry_resolves_to_mock():
    _pop("IDV_VOTER_ID_FAKE_URL")
    out = vp.registry_lookup("voter_id_fake", "ABC1234567")
    assert out["registered"] is False


def test_live_provider_activates_when_url_configured():
    os.environ["IDV_PAN_NSDL_URL"] = "https://sandbox.example/pan/verify"
    try:
        assert isinstance(vp.get_provider("pan_nsdl"), vp.HttpRegistryProvider)
    finally:
        _pop("IDV_PAN_NSDL_URL")


def test_live_registry_mapping_and_name_match(monkeypatch):
    seen = {}

    def fake_post(url, **kw):
        seen["url"] = url
        seen["json"] = kw.get("json")
        seen["headers"] = kw.get("headers")

        class R:
            status_code = 200

            def json(self):
                return {"exists": True, "status": "ACTIVE", "name": "[Aadhaar Redacted]"}

        return R()

    monkeypatch.setattr(requests, "post", fake_post)
    os.environ["IDV_PAN_NSDL_URL"] = "https://sandbox.example/pan/verify"
    os.environ["IDV_PAN_NSDL_TOKEN"] = "tok-123"
    try:
        out = vp.registry_lookup("pan_nsdl", SAMPLE_PAN, declared_name="[Aadhaar Redacted]")
        assert out["registered"] is True
        assert out["status"] == "ACTIVE"
        assert out["holder_match"] is True
        assert out["sample_data"] is False
        assert out["live"] is True
        assert seen["json"] == {"number": SAMPLE_PAN, "name": "[Aadhaar Redacted]"}
        assert seen["headers"]["Authorization"] == "Bearer tok-123"
        assert seen["url"] == "https://sandbox.example/pan/verify"
    finally:
        _pop("IDV_PAN_NSDL_URL")
        _pop("IDV_PAN_NSDL_TOKEN")


def test_live_registry_name_mismatch_flagged(monkeypatch):
    def fake_post(url, **kw):
        class R:
            status_code = 200

            def json(self):
                return {"exists": True, "status": "ACTIVE", "name": "Some Other Name"}

        return R()

    monkeypatch.setattr(requests, "post", fake_post)
    os.environ["IDV_DL_PARIVAHAN_URL"] = "https://sandbox.example/dl/verify"
    try:
        out = vp.registry_lookup("dl_parivahan", "KA0120201234567", declared_name="[Aadhaar Redacted]")
        assert out["holder_match"] is False
    finally:
        _pop("IDV_DL_PARIVAHAN_URL")


def test_live_unreachable_returns_impartial_none(monkeypatch):
    def boom(*a, **kw):
        raise RuntimeError("connection refused")

    monkeypatch.setattr(requests, "post", boom)
    os.environ["IDV_RC_VAHAN_URL"] = "https://sandbox.example/rc/verify"
    try:
        out = vp.registry_lookup("rc_vahan", "KA01MJ1234")
        assert out["registered"] is None
        assert "unreachable" in out["reason"]
        assert out["live"] is True
    finally:
        _pop("IDV_RC_VAHAN_URL")


def test_lost_stolen_live_semantics(monkeypatch):
    def fake_post(url, **kw):
        class R:
            status_code = 200

            def json(self):
                return {"exists": False}

        return R()

    monkeypatch.setattr(requests, "post", fake_post)
    os.environ["IDV_PASSPORT_REGISTRY_URL"] = "https://sandbox.example/psk/verify"
    try:
        out = vp.registry_lookup("passport_registry", "A1234567")
        # Absence from a lost/stolen list is the GOOD outcome.
        assert out["registered"] is False
        assert out["lost_or_stolen"] is True
    finally:
        _pop("IDV_PASSPORT_REGISTRY_URL")


def test_coverage_reports_mock_live_per_registry():
    _pop("IDV_EPIC_EC_URL")
    os.environ["IDV_PAN_NSDL_URL"] = "https://sandbox.example/pan/verify"
    try:
        rows = {r["key"]: r for r in vp.registries_coverage()}
        assert len(rows) == 5
        assert all({"key", "label", "mock", "live", "provider"} <= set(r) for r in rows.values())
        assert rows["epic_ec"]["mock"] is True
        assert rows["pan_nsdl"]["mock"] is False
        assert rows["pan_nsdl"]["live"] is True
    finally:
        _pop("IDV_PAN_NSDL_URL")