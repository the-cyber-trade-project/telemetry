"""Pydantic v2 models for telemetry payloads, shift rosters, and underwriter attestations."""

from datetime import datetime
from typing import List, Optional, Dict, Any, Literal
from pydantic import BaseModel, Field, field_validator


class ShiftWorkerRecord(BaseModel):
    """Anonymized worker record within an active operational shift."""
    practitioner_id: str = Field(..., description="Canonical NCTB ID or masked hash")
    tier: Literal[
        "Registered Pre-Apprentice",
        "Tier 1 Apprentice",
        "Tier 2 Apprentice",
        "Tier 3 Apprentice",
        "Tier 4 Apprentice",
        "Licensed Journeyman",
        "Master Practitioner"
    ]
    is_supervisor: bool = False
    is_master_of_record: bool = False
    active_endorsements: List[str] = Field(default_factory=list)
    hours_on_shift: float = Field(..., ge=0.0, le=24.0)
    hours_rest_prior: float = Field(default=12.0, ge=0.0)


class ShiftRoster(BaseModel):
    """Operational shift roster submitted by enterprise SOC / MSSP."""
    shift_id: str = Field(..., description="Unique enterprise shift identifier")
    employer_id: str = Field(..., description="PEC Employer Identifier, e.g. PEC-EMP-2026-0014")
    district_code: str = Field(default="District 1 - Mid-Atlantic")
    facility_type: Literal["Commercial Enterprise", "MSSP / Managed SOC", "Critical Infrastructure / SCIF", "Healthcare / Clinical"]
    shift_start: datetime
    shift_end: datetime
    workers: List[ShiftWorkerRecord] = Field(default_factory=list)
    operational_domain: str = Field(default="Domain 2: Detection Engineering & Incident Triage / SOC")
    emergency_surge_active: bool = False


class ZeroKnowledgeRatioProof(BaseModel):
    """Cryptographically verifiable mathematical assertion for insurance underwriters.
    
    Contains zero internal hostnames, client names, IP addresses, or worker PII.
    """
    proof_id: str
    employer_id: str
    shift_id_hash: str
    timestamp: datetime
    nonce: str
    
    # Mathematical assertions
    total_workers: int
    journeyman_and_masters_count: int
    apprentice_count: int
    effective_ratio: float = Field(..., description="Apprentice-to-Supervisor ratio, e.g., 1.5 means 1.5 apprentices per supervisor")
    ratio_compliant: bool = Field(..., description="True if effective_ratio <= 2.0 (mandatory 2:1 standard)")
    
    # Master of Record presence
    mor_active: bool
    mor_id_hash: Optional[str] = None
    
    # Fatigue and safety checks
    max_shift_hours: float
    fatigue_compliant: bool
    
    # Cryptographic integrity
    proof_hash: str
    employer_signature: str
    nctb_root_anchor: Optional[str] = None


class ActuarialWarrantyReport(BaseModel):
    """Evaluation summary for cyber liability underwriters determining premium credits."""
    employer_id: str
    evaluation_timestamp: datetime
    shifts_evaluated_count: int
    compliant_shifts_count: int
    compliance_percentage: float
    mor_coverage_percentage: float
    fatigue_violation_count: int
    
    # Actuarial pricing impacts
    qualifies_for_warranty_discount: bool
    recommended_premium_discount_percent: float = Field(..., ge=0.0, le=35.0)
    estimated_annual_savings: float
    warranty_status: Literal["Fully Warranted (Tier 1 Preferred)", "Conditionally Warranted (Tier 2)", "Non-Compliant (Standard Rate)"]
    audit_notes: List[str] = Field(default_factory=list)
