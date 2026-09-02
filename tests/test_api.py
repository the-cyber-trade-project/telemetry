"""Tests for FastAPI endpoints, security headers, and underwriter verification."""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timezone

from cyber_trade_telemetry.api import app
from cyber_trade_telemetry.crypto import generate_keypair, export_public_key_pem
from cyber_trade_telemetry.models import ShiftWorkerRecord, ShiftRoster
from cyber_trade_telemetry.engine import TelemetryEngine

client = TestClient(app)


def test_healthz_endpoint():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert data["framework_version"] == "1.9.1"


def test_security_headers_present():
    resp = client.get("/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "Content-Security-Policy" in resp.headers


def test_submit_roster_and_verify_underwriter_flow():
    priv, pub = generate_keypair()
    pub_pem = export_public_key_pem(pub)

    roster_payload = {
        "shift_id": "SOC-SHIFT-ALPHA-101",
        "employer_id": "PEC-EMP-2026-0014",
        "district_code": "District 1 - Mid-Atlantic",
        "facility_type": "Commercial Enterprise",
        "shift_start": datetime.now(timezone.utc).isoformat(),
        "shift_end": datetime.now(timezone.utc).isoformat(),
        "workers": [
            {
                "practitioner_id": "CTP-MAS-2026-0001",
                "tier": "Master Practitioner",
                "is_supervisor": True,
                "is_master_of_record": True,
                "active_endorsements": ["SE-APP"],
                "hours_on_shift": 8.0,
                "hours_rest_prior": 14.0
            },
            {
                "practitioner_id": "CTP-APP-2026-0884",
                "tier": "Tier 2 Apprentice",
                "is_supervisor": False,
                "is_master_of_record": False,
                "active_endorsements": [],
                "hours_on_shift": 8.0,
                "hours_rest_prior": 14.0
            }
        ],
        "operational_domain": "Domain 2: Detection Engineering & Incident Triage / SOC",
        "emergency_surge_active": False
    }

    # Submit roster
    submit_resp = client.post("/api/v1/telemetry/submit-roster", json=roster_payload)
    assert submit_resp.status_code == 200
    proof = submit_resp.json()
    assert proof["ratio_compliant"] is True
    assert proof["effective_ratio"] == 1.0
    assert proof["mor_active"] is True
    assert "proof_hash" in proof

    # Evaluate warranty
    war_resp = client.post("/api/v1/underwriter/evaluate-warranty", json={
        "employer_id": "PEC-EMP-2026-0014",
        "proofs": [proof],
        "base_annual_premium": 200000.0
    })
    assert war_resp.status_code == 200
    war_data = war_resp.json()
    assert war_data["qualifies_for_warranty_discount"] is True
    assert war_data["recommended_premium_discount_percent"] == 35.0
    assert war_data["estimated_annual_savings"] == 70000.0
