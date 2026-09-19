"""
Unit tests for Cross-Border Syndicate & Recidivism Graph Analytics (app/syndicate.py).
"""

import os
import sys
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), os.pardir, "app"))

from syndicate import analyze_syndicate_patterns


def test_clean_document_no_alerts():
    curr = {
        "file_hash": "hash_111",
        "checkpoint": "Raxaul ICP",
        "doc_number": "P1234567",
        "name": "VIKRAM SHARMA",
        "verdict": "CLEAR",
        "risk_score": 10,
    }
    res = analyze_syndicate_patterns(curr, [])
    assert res["has_alerts"] is False
    assert res["syndicate_risk_bump"] == 0
    assert len(res["alerts"]) == 0


def test_identity_clash_detected():
    # Same passport number previously presented under a different name
    curr = {
        "file_hash": "hash_222",
        "checkpoint": "Panitanki ICP",
        "doc_number": "P9876543",
        "name": "AMIT KUMAR",
        "verdict": "CLEAR",
        "risk_score": 15,
    }
    history = [
        {
            "file_hash": "hash_111",
            "checkpoint": "Panitanki ICP",
            "doc_number": "P9876543",
            "name": "ROHIT VERMA",
            "verdict": "CLEAR",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    res = analyze_syndicate_patterns(curr, history)
    assert res["has_alerts"] is True
    assert any(a["type"] == "IDENTITY_CLASH" for a in res["alerts"])
    assert res["syndicate_risk_bump"] >= 35


def test_identity_clash_dob_detected():
    # Same passport number presented with contradictory Date of Birth
    curr = {
        "file_hash": "hash_444",
        "checkpoint": "Raxaul ICP",
        "doc_number": "P1230000",
        "name": "VIJAY VERMA",
        "dob": "1988-04-12",
        "verdict": "CLEAR",
        "risk_score": 10,
    }
    history = [
        {
            "file_hash": "hash_333",
            "checkpoint": "Raxaul ICP",
            "doc_number": "P1230000",
            "name": "VIJAY VERMA",
            "dob": "1995-11-23",
            "verdict": "CLEAR",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    res = analyze_syndicate_patterns(curr, history)
    assert res["has_alerts"] is True
    assert any(a["type"] == "IDENTITY_CLASH" and "Date of Birth" in a["title"] for a in res["alerts"])
    assert res["syndicate_risk_bump"] >= 35


def test_cross_checkpoint_recidivism():
    # Same passport presented across different border checkpoints
    curr = {
        "file_hash": "hash_333",
        "checkpoint": "Jaigaon ICP",
        "doc_number": "Z5551234",
        "name": "PRIYA SINGH",
        "verdict": "REVIEW",
        "risk_score": 45,
    }
    history = [
        {
            "file_hash": "hash_000",
            "checkpoint": "Raxaul ICP",
            "doc_number": "Z5551234",
            "name": "PRIYA SINGH",
            "verdict": "FLAGGED",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
    ]
    res = analyze_syndicate_patterns(curr, history)
    assert res["has_alerts"] is True
    assert any(a["type"] == "CROSS_CHECKPOINT_REPRESENTATION" for a in res["alerts"])
    assert res["syndicate_risk_bump"] >= 25


def test_checkpoint_burst_alert():
    now = datetime.now(timezone.utc)
    curr = {
        "file_hash": "hash_999",
        "checkpoint": "Jogbani ICP",
        "doc_number": "A1112223",
        "name": "DEVRAJ",
        "verdict": "FLAGGED",
        "risk_score": 80,
    }
    # 2 previous flagged reports within last 20 minutes at Jogbani ICP
    history = [
        {
            "file_hash": f"hash_prev_{i}",
            "checkpoint": "Jogbani ICP",
            "doc_number": f"B111222{i}",
            "verdict": "FLAGGED",
            "created_at": (now - timedelta(minutes=10 * i)).isoformat(),
        }
        for i in range(1, 3)
    ]
    res = analyze_syndicate_patterns(curr, history, burst_window_minutes=60)
    assert res["has_alerts"] is True
    assert any(a["type"] == "SECTOR_BURST_ALERT" for a in res["alerts"])
    assert res["syndicate_risk_bump"] >= 10


def test_syndicate_alerts_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    from sqlalchemy.orm import sessionmaker
    import main
    from main import app, make_session_token, Base

    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    monkeypatch.setattr(main, "SessionLocal", TestSession)

    client = TestClient(app, cookies={"nischay_session": make_session_token("officer@example.com")})
    resp = client.get("/api/screen/syndicate-alerts")
    assert resp.status_code == 200
    data = resp.json()
    assert "checkpoint_filter" in data
    assert "alerts" in data
    assert isinstance(data["alerts"], list)


def test_evidentiary_dossier_endpoint(monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.pool import StaticPool
    from sqlalchemy.orm import sessionmaker
    import main
    from main import app, make_session_token, Base, ScreeningReport, now_utc

    test_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=test_engine)
    TestSession = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    monkeypatch.setattr(main, "SessionLocal", TestSession)

    # Populate a test report in the in-memory SQLite DB
    db = TestSession()
    try:
        rep = ScreeningReport(
            id="test_dossier_rep1",
            file_hash="a1b2c3d4e5f67890",
            filename="passport_scan.jpg",
            doc_type="passport",
            checkpoint="Raxaul ICP",
            verdict="CLEAR",
            risk_score=12,
            confidence=0.96,
            extracted_fields='{"passport":"L898902C","name":"VIKRAM SHARMA"}',
            signals='["ICAO TD3 checksums valid"]',
            modules='{"extraction":{"ran":true},"validation":{"verdict":"PASS"},"tampering":{"verdict":"PASS"},"face":{"verdict":"PASS"}}',
            ledger_status="AUTHENTIC",
            screener="officer@example.com",
            created_at=now_utc(),
        )
        db.add(rep)
        db.commit()
    finally:
        db.close()

    client = TestClient(app, cookies={"nischay_session": make_session_token("officer@example.com")})
    resp = client.get("/api/screen/dossier/test_dossier_rep1")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "Evidentiary Forensic Dossier" in resp.text
    assert "CRYPTOGRAPHIC CUSTODY SEAL" in resp.text
    assert "Raxaul ICP" in resp.text

