"""Microsoft Sentinel SOC operator audit log extractor and sanitizer."""

from datetime import datetime, timezone
from typing import Dict, Any, List
from cyber_trade_telemetry.connectors.base import BaseSiemConnector
from cyber_trade_telemetry.models import ShiftRoster, ShiftWorkerRecord


class SentinelConnector(BaseSiemConnector):
    """Parses Microsoft Sentinel `SecurityIncident` operator tracking tables into sanitized ShiftRoster models."""

    def parse_audit_log(self, raw_log: Dict[str, Any]) -> ShiftRoster:
        shift_id = raw_log.get("ShiftExecutionId", "AZURE-SENTINEL-SHIFT-01")
        employer_id = raw_log.get("TenantTradeId", "PEC-EMP-2026-0014")
        facility = raw_log.get("EnvironmentCategory", "MSSP / Managed SOC")
        
        start_str = raw_log.get("ShiftStartTimeUtc")
        end_str = raw_log.get("ShiftEndTimeUtc")
        
        shift_start = datetime.fromisoformat(start_str) if start_str else datetime.now(timezone.utc)
        shift_end = datetime.fromisoformat(end_str) if end_str else datetime.now(timezone.utc)

        raw_operators = raw_log.get("AssignedOperators", [])
        workers: List[ShiftWorkerRecord] = []

        for op in raw_operators:
            worker = ShiftWorkerRecord(
                practitioner_id=op.get("TradeLicenseId", "CTP-ANON-0000"),
                tier=op.get("LicensureTier", "Licensed Journeyman"),
                is_supervisor=op.get("IsOperationalSupervisor", False),
                is_master_of_record=op.get("IsDesignatedMoR", False),
                active_endorsements=op.get("SpecialtyCertifications", []),
                hours_on_shift=float(op.get("ShiftLoggedHours", 8.0)),
                hours_rest_prior=float(op.get("PriorRestIntervalHours", 16.0))
            )
            workers.append(worker)

        return ShiftRoster(
            shift_id=shift_id,
            employer_id=employer_id,
            facility_type=facility,
            shift_start=shift_start,
            shift_end=shift_end,
            workers=workers,
            operational_domain=raw_log.get("PrimaryWorkDomain", "Domain 2: Detection Engineering & Incident Triage / SOC"),
            emergency_surge_active=raw_log.get("CrisisModeActive", False)
        )
