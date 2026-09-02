"""Abstract interface for SIEM/SOAR telemetry extraction adapters."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List
from cyber_trade_telemetry.models import ShiftRoster


class BaseSiemConnector(ABC):
    """Abstract base class for extracting and sanitizing SOC shift rosters from SIEM audit logs."""

    @abstractmethod
    def parse_audit_log(self, raw_log: Dict[str, Any]) -> ShiftRoster:
        """Parses raw vendor audit log into standardized ShiftRoster, scrubbing sensitive telemetry."""
        pass
