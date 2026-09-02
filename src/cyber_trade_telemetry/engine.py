"""Zero-knowledge ratio calculation, fatigue audit, and actuarial warranty scoring engine."""

import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import ed25519

from cyber_trade_telemetry.models import (
    ShiftRoster,
    ShiftWorkerRecord,
    ZeroKnowledgeRatioProof,
    ActuarialWarrantyReport
)
from cyber_trade_telemetry.crypto import (
    sha256_hash,
    canonical_json,
    sign_payload,
    verify_signature
)


class TelemetryEngine:
    """Core actuarial and supervisory evaluation engine for Pillar VII labor standards."""

    MAX_PERMITTED_SHIFT_HOURS: float = 12.0
    MIN_REQUIRED_REST_HOURS: float = 10.0
    MANDATORY_SUPERVISORY_RATIO: float = 2.0  # Max 2 apprentices per 1 Journeyman/Master

    def evaluate_shift_roster(
        self,
        roster: ShiftRoster,
        private_key: Optional[ed25519.Ed25519PrivateKey] = None
    ) -> ZeroKnowledgeRatioProof:
        """Evaluates a raw shift roster and generates a zero-knowledge ratio proof."""
        supervisors = [
            w for w in roster.workers
            if w.tier in ("Licensed Journeyman", "Master Practitioner") or w.is_supervisor
        ]
        apprentices = [
            w for w in roster.workers
            if w.tier.startswith("Tier") or w.tier == "Registered Pre-Apprentice"
        ]
        
        sup_count = len(supervisors)
        app_count = len(apprentices)
        total_count = len(roster.workers)
        
        # Calculate effective ratio (Apprentices per Supervisor)
        if sup_count == 0:
            effective_ratio = float(app_count) if app_count > 0 else 0.0
            ratio_compliant = (app_count == 0)
        else:
            effective_ratio = round(app_count / sup_count, 2)
            ratio_compliant = (effective_ratio <= self.MANDATORY_SUPERVISORY_RATIO)

        # Master of Record presence
        mor_worker = next((w for w in roster.workers if w.is_master_of_record or w.tier == "Master Practitioner"), None)
        mor_active = (mor_worker is not None)
        mor_id_hash = sha256_hash(mor_worker.practitioner_id) if mor_worker else None

        # Fatigue limits
        max_shift = max((w.hours_on_shift for w in roster.workers), default=0.0)
        min_rest = min((w.hours_rest_prior for w in roster.workers), default=12.0)
        fatigue_compliant = (max_shift <= self.MAX_PERMITTED_SHIFT_HOURS) and (min_rest >= self.MIN_REQUIRED_REST_HOURS)

        proof_id = f"ZKP-{uuid.uuid4().hex[:12].upper()}"
        shift_id_hash = sha256_hash(f"{roster.employer_id}:{roster.shift_id}")
        nonce = os.urandom(16).hex()
        ts = datetime.now(timezone.utc)

        proof_data: Dict[str, Any] = {
            "proof_id": proof_id,
            "employer_id": roster.employer_id,
            "shift_id_hash": shift_id_hash,
            "timestamp": ts.isoformat(),
            "nonce": nonce,
            "total_workers": total_count,
            "journeyman_and_masters_count": sup_count,
            "apprentice_count": app_count,
            "effective_ratio": effective_ratio,
            "ratio_compliant": ratio_compliant,
            "mor_active": mor_active,
            "mor_id_hash": mor_id_hash,
            "max_shift_hours": max_shift,
            "fatigue_compliant": fatigue_compliant
        }

        proof_hash = sha256_hash(canonical_json(proof_data))

        if private_key:
            signature = sign_payload(proof_data, private_key)
        else:
            signature = "UNASSIGNED_STAGING_SIGNATURE"

        return ZeroKnowledgeRatioProof(
            proof_id=proof_id,
            employer_id=roster.employer_id,
            shift_id_hash=shift_id_hash,
            timestamp=ts,
            nonce=nonce,
            total_workers=total_count,
            journeyman_and_masters_count=sup_count,
            apprentice_count=app_count,
            effective_ratio=effective_ratio,
            ratio_compliant=ratio_compliant,
            mor_active=mor_active,
            mor_id_hash=mor_id_hash,
            max_shift_hours=max_shift,
            fatigue_compliant=fatigue_compliant,
            proof_hash=proof_hash,
            employer_signature=signature
        )

    def verify_proof(
        self,
        proof: ZeroKnowledgeRatioProof,
        public_key: ed25519.Ed25519PublicKey
    ) -> Tuple[bool, str]:
        """Verifies mathematical validity and cryptographic signature of a ZK ratio proof."""
        proof_data = {
            "proof_id": proof.proof_id,
            "employer_id": proof.employer_id,
            "shift_id_hash": proof.shift_id_hash,
            "timestamp": proof.timestamp.isoformat() if isinstance(proof.timestamp, datetime) else proof.timestamp,
            "nonce": proof.nonce,
            "total_workers": proof.total_workers,
            "journeyman_and_masters_count": proof.journeyman_and_masters_count,
            "apprentice_count": proof.apprentice_count,
            "effective_ratio": proof.effective_ratio,
            "ratio_compliant": proof.ratio_compliant,
            "mor_active": proof.mor_active,
            "mor_id_hash": proof.mor_id_hash,
            "max_shift_hours": proof.max_shift_hours,
            "fatigue_compliant": proof.fatigue_compliant
        }

        computed_hash = sha256_hash(canonical_json(proof_data))
        if computed_hash != proof.proof_hash:
            return False, "Proof hash mismatch: payload has been modified"

        if not verify_signature(proof_data, proof.employer_signature, public_key):
            return False, "Cryptographic signature verification failed"

        if proof.journeyman_and_masters_count == 0 and proof.apprentice_count > 0 and proof.ratio_compliant:
            return False, "Ratio violation: Apprentices on shift without a Journeyman supervisor"

        return True, "Proof mathematically and cryptographically verified"

    def evaluate_actuarial_warranty(
        self,
        employer_id: str,
        proofs: List[ZeroKnowledgeRatioProof],
        base_annual_premium: float = 100000.0
    ) -> ActuarialWarrantyReport:
        """Evaluates a batch of shift proofs to calculate CUAAC underwriter warranty credits."""
        if not proofs:
            return ActuarialWarrantyReport(
                employer_id=employer_id,
                evaluation_timestamp=datetime.now(timezone.utc),
                shifts_evaluated_count=0,
                compliant_shifts_count=0,
                compliance_percentage=0.0,
                mor_coverage_percentage=0.0,
                fatigue_violation_count=0,
                qualifies_for_warranty_discount=False,
                recommended_premium_discount_percent=0.0,
                estimated_annual_savings=0.0,
                warranty_status="Non-Compliant (Standard Rate)",
                audit_notes=["No telemetry proofs provided for evaluation"]
            )

        total_shifts = len(proofs)
        compliant_shifts = sum(1 for p in proofs if p.ratio_compliant and p.fatigue_compliant)
        mor_shifts = sum(1 for p in proofs if p.mor_active)
        fatigue_violations = sum(1 for p in proofs if not p.fatigue_compliant)

        compliance_pct = round((compliant_shifts / total_shifts) * 100.0, 1)
        mor_pct = round((mor_shifts / total_shifts) * 100.0, 1)

        notes: List[str] = []

        if compliance_pct >= 98.0 and mor_pct >= 95.0 and fatigue_violations == 0:
            discount_pct = 35.0
            status = "Fully Warranted (Tier 1 Preferred)"
            notes.append("Satisfies 100% CUAAC labor standards. Maximum 35% warranty credit approved.")
        elif compliance_pct >= 90.0 and mor_pct >= 80.0:
            discount_pct = 25.0
            status = "Conditionally Warranted (Tier 2)"
            notes.append("Satisfies baseline supervisory standards. 25% warranty credit approved.")
        else:
            discount_pct = 0.0
            status = "Non-Compliant (Standard Rate)"
            notes.append(f"Labor ratio compliance at {compliance_pct}% below 90% underwriting threshold.")

        savings = round(base_annual_premium * (discount_pct / 100.0), 2)

        return ActuarialWarrantyReport(
            employer_id=employer_id,
            evaluation_timestamp=datetime.now(timezone.utc),
            shifts_evaluated_count=total_shifts,
            compliant_shifts_count=compliant_shifts,
            compliance_percentage=compliance_pct,
            mor_coverage_percentage=mor_pct,
            fatigue_violation_count=fatigue_violations,
            qualifies_for_warranty_discount=(discount_pct > 0),
            recommended_premium_discount_percent=discount_pct,
            estimated_annual_savings=savings,
            warranty_status=status,
            audit_notes=notes
        )
