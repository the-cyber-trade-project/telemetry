"""Tests for ratio evaluation, fatigue limits, and actuarial warranty scoring."""

from datetime import datetime, timezone
import pytest
from cyber_trade_telemetry.models import ShiftRoster, ShiftWorkerRecord
from cyber_trade_telemetry.engine import TelemetryEngine
from cyber_trade_telemetry.crypto import generate_keypair


def create_mock_roster(supervisors: int, apprentices: int, max_hours: float = 8.0, has_mor: bool = True) -> ShiftRoster:
    workers = []
    if has_mor:
        workers.append(ShiftWorkerRecord(
            practitioner_id="CTP-MAS-2026-0001",
            tier="Master Practitioner",
            is_supervisor=True,
            is_master_of_record=True,
            hours_on_shift=max_hours,
            hours_rest_prior=14.0
        ))
        supervisors -= 1

    for i in range(supervisors):
        workers.append(ShiftWorkerRecord(
            practitioner_id=f"CTP-JRN-2026-{100 + i}",
            tier="Licensed Journeyman",
            is_supervisor=True,
            hours_on_shift=max_hours,
            hours_rest_prior=14.0
        ))

    for i in range(apprentices):
        workers.append(ShiftWorkerRecord(
            practitioner_id=f"CTP-APP-2026-{200 + i}",
            tier="Tier 2 Apprentice",
            is_supervisor=False,
            hours_on_shift=max_hours,
            hours_rest_prior=14.0
        ))

    return ShiftRoster(
        shift_id="TEST-SHIFT-001",
        employer_id="PEC-EMP-2026-0014",
        facility_type="Commercial Enterprise",
        shift_start=datetime.now(timezone.utc),
        shift_end=datetime.now(timezone.utc),
        workers=workers
    )


def test_compliant_two_to_one_ratio():
    engine = TelemetryEngine()
    priv, pub = generate_keypair()
    
    # 2 supervisors (1 MoR + 1 Journeyman) and 4 apprentices -> 2:1 ratio (Compliant)
    roster = create_mock_roster(supervisors=2, apprentices=4)
    proof = engine.evaluate_shift_roster(roster, private_key=priv)

    assert proof.ratio_compliant is True
    assert proof.effective_ratio == 2.0
    assert proof.journeyman_and_masters_count == 2
    assert proof.apprentice_count == 4
    assert proof.mor_active is True
    assert proof.fatigue_compliant is True

    valid, msg = engine.verify_proof(proof, pub)
    assert valid is True


def test_non_compliant_ratio_excess_apprentices():
    engine = TelemetryEngine()
    priv, pub = generate_keypair()

    # 1 supervisor and 5 apprentices -> 5:1 ratio (Violates 2:1 standard)
    roster = create_mock_roster(supervisors=1, apprentices=5)
    proof = engine.evaluate_shift_roster(roster, private_key=priv)

    assert proof.ratio_compliant is False
    assert proof.effective_ratio == 5.0

    valid, msg = engine.verify_proof(proof, pub)
    assert valid is True  # Proof is validly signed, but indicates non-compliance


def test_fatigue_limit_violation():
    engine = TelemetryEngine()
    priv, _ = generate_keypair()

    # 14-hour shift exceeds 12-hour statutory fatigue cap
    roster = create_mock_roster(supervisors=2, apprentices=2, max_hours=14.0)
    proof = engine.evaluate_shift_roster(roster, private_key=priv)

    assert proof.fatigue_compliant is False
    assert proof.max_shift_hours == 14.0


def test_actuarial_warranty_tier_one_discount():
    engine = TelemetryEngine()
    priv, _ = generate_keypair()

    # Generate 10 fully compliant shifts
    proofs = [
        engine.evaluate_shift_roster(create_mock_roster(supervisors=2, apprentices=3), private_key=priv)
        for _ in range(10)
    ]

    report = engine.evaluate_actuarial_warranty("PEC-EMP-2026-0014", proofs, base_annual_premium=100000.0)

    assert report.qualifies_for_warranty_discount is True
    assert report.recommended_premium_discount_percent == 35.0
    assert report.estimated_annual_savings == 35000.0
    assert report.warranty_status == "Fully Warranted (Tier 1 Preferred)"
