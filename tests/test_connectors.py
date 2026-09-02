"""Tests for SIEM / SOAR log adapters (Splunk and Sentinel)."""

from cyber_trade_telemetry.connectors.splunk import SplunkConnector
from cyber_trade_telemetry.connectors.sentinel import SentinelConnector
from cyber_trade_telemetry.engine import TelemetryEngine


def test_splunk_connector_parsing():
    raw_splunk = {
        "shift_id": "SPLUNK-2026-SOC-882",
        "employer_id": "PEC-EMP-2026-0042",
        "facility_type": "Critical Infrastructure / SCIF",
        "shift_start": "2026-09-01T08:00:00Z",
        "shift_end": "2026-09-01T16:00:00Z",
        "domain": "Domain 2: Detection Engineering & Incident Triage / SOC",
        "is_surge": False,
        "roster_entries": [
            {
                "nctb_id": "CTP-MAS-2026-0004",
                "trade_tier": "Master Practitioner",
                "is_lead": True,
                "is_mor": True,
                "endorsements": ["SE-ICS"],
                "duration_hours": 8.0,
                "prior_rest_hours": 16.0
            },
            {
                "nctb_id": "CTP-APP-2026-0120",
                "trade_tier": "Tier 1 Apprentice",
                "is_lead": False,
                "is_mor": False,
                "endorsements": [],
                "duration_hours": 8.0,
                "prior_rest_hours": 16.0
            }
        ]
    }

    connector = SplunkConnector()
    roster = connector.parse_audit_log(raw_splunk)
    assert roster.shift_id == "SPLUNK-2026-SOC-882"
    assert len(roster.workers) == 2

    engine = TelemetryEngine()
    proof = engine.evaluate_shift_roster(roster)
    assert proof.ratio_compliant is True
    assert proof.effective_ratio == 1.0
    assert proof.mor_active is True


def test_sentinel_connector_parsing():
    raw_sentinel = {
        "ShiftExecutionId": "AZURE-SENTINEL-MSFT-491",
        "TenantTradeId": "PEC-EMP-2026-0014",
        "EnvironmentCategory": "MSSP / Managed SOC",
        "ShiftStartTimeUtc": "2026-09-01T00:00:00Z",
        "ShiftEndTimeUtc": "2026-09-01T08:00:00Z",
        "AssignedOperators": [
            {
                "TradeLicenseId": "CTP-JRN-2026-0412",
                "LicensureTier": "Licensed Journeyman",
                "IsOperationalSupervisor": True,
                "IsDesignatedMoR": False,
                "SpecialtyCertifications": ["SE-CLD"],
                "ShiftLoggedHours": 8.0,
                "PriorRestIntervalHours": 16.0
            },
            {
                "TradeLicenseId": "CTP-APP-2026-0991",
                "LicensureTier": "Tier 2 Apprentice",
                "IsOperationalSupervisor": False,
                "IsDesignatedMoR": False,
                "SpecialtyCertifications": [],
                "ShiftLoggedHours": 8.0,
                "PriorRestIntervalHours": 16.0
            }
        ]
    }

    connector = SentinelConnector()
    roster = connector.parse_audit_log(raw_sentinel)
    assert roster.shift_id == "AZURE-SENTINEL-MSFT-491"
    assert len(roster.workers) == 2

    engine = TelemetryEngine()
    proof = engine.evaluate_shift_roster(roster)
    assert proof.ratio_compliant is True
    assert proof.effective_ratio == 1.0
