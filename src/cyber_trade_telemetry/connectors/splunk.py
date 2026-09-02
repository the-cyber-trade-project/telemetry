"""Splunk Enterprise Security SOC audit log extractor and sanitizer."""

from datetime import datetime, timezone
from typing import Dict, Any, List
from cyber_trade_telemetry.connectors.base import BaseSiemConnector
from cyber_trade_telemetry.models import ShiftRoster, ShiftWorkerRecord


class SplunkConnector(BaseSiemConnector):
    """Parses Splunk ES `audit_soc_shift_roster` search results into sanitized ShiftRoster models."""

    def parse_audit_log(self, raw_log: Dict[str, Any]) -> ShiftRoster:
        shift_id = raw_log.get("shift_id", "SPLUNK-SHIFT-UNKNOWN")
        employer_id = raw_log.get("employer_id", "PEC-EMP-2026-0001")
        facility = raw_log.get("facility_type", "Commercial Enterprise")
        
        start_str = raw_log.get("shift_start")
        end_str = raw_log.get("shift_end")
        
        shift_start = datetime.fromisoformat(start_str) if start_str else datetime.now(timezone.utc)
        shift_end = datetime.fromisoformat(end_str) if end_str else datetime.now(timezone.utc)

        raw_workers = raw_log.get("roster_entries", [])
        workers: List[ShiftWorkerRecord] = []

        for entry in raw_workers:
            worker = ShiftWorkerRecord(
                practitioner_id=entry.get("nctb_id", "CTP-ANON-0000"),
                tier=entry.get("trade_tier", "Tier 1 Apprentice"),
                is_supervisor=entry.get("is_lead", False),
                is_master_of_record=entry.get("is_mor", False),
                active_endorsements=entry.get("endorsements", []),
                hours_on_shift=float(entry.get("duration_hours", 8.0)),
                hours_rest_prior=float(entry.get("prior_rest_hours", 14.0))
            )
            workers.append(worker)

        return ShiftRoster(
            shift_id=shift_id,
            employer_id=employer_id,
            facility_type=facility,
            shift_start=shift_start,
            shift_end=shift_end,
            workers=workers,
            operational_domain=raw_log.get("domain", "Domain 2: Detection Engineering & Incident Triage / SOC"),
            emergency_surge_active=raw_log.get("is_surge", False)
        )
