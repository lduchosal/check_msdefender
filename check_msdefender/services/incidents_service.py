"""Incidents service implementation."""

from __future__ import annotations

from typing import Optional

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.core.models import (
    AlertDict,
    DefenderClientProtocol,
    ServiceResult,
)

# Ranking used to surface the most severe alert of an incident.
_SEVERITY_ORDER = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}


class IncidentsService:
    """Service for checking incidents (correlated alert groups) on a machine."""

    def __init__(
        self, defender_client: DefenderClientProtocol, verbose_level: int = 0
    ) -> None:
        """Initialize with Defender client."""
        self.defender = defender_client
        self.logger = get_verbose_logger(__name__, verbose_level)

    def get_result(
        self, machine_id: Optional[str] = None, dns_name: Optional[str] = None
    ) -> ServiceResult:
        """Get incidents result with value and details for a machine.

        Raises:
            ValidationError: If neither machine_id nor dns_name is provided,
                or the machine cannot be resolved.
        """
        self.logger.method_entry("get_result", machine_id=machine_id, dns_name=dns_name)

        if not machine_id and not dns_name:
            raise ValidationError("Either machine_id or dns_name must be provided")

        target_dns_name = dns_name
        target_machine_id = machine_id

        if machine_id:
            # Get DNS name from machine_id
            machine_details = self.defender.get_machine_by_id(machine_id)
            target_dns_name = machine_details.get("computerDnsName", "Unknown")
        elif dns_name:
            # Get machine_id from dns_name
            dns_response = self.defender.get_machine_by_dns_name(dns_name)
            machines = dns_response.get("value", [])
            if not machines:
                raise ValidationError(f"Machine not found with DNS name: {dns_name}")
            target_machine_id = machines[0].get("id")
            target_dns_name = dns_name

        if not target_machine_id:
            raise ValidationError("Could not resolve a machine id for the request")

        # Alerts are the building blocks of incidents; each alert carries the
        # incidentId of the incident it was correlated into. Query the
        # device-scoped alerts endpoint so no alert is dropped behind a page cap.
        self.logger.info("Fetching alerts from Microsoft Defender")
        machine_alerts = self.defender.get_machine_alerts(target_machine_id).get(
            "value", []
        )

        unresolved_alerts = [
            alert for alert in machine_alerts if alert.get("status") != "Resolved"
        ]

        # Group the unresolved alerts by incident to count distinct active incidents.
        incidents: dict[int, list[AlertDict]] = {}
        for alert in unresolved_alerts:
            incident_id = alert.get("incidentId")
            if incident_id is None:
                continue
            incidents.setdefault(incident_id, []).append(alert)

        details = self._build_details(target_dns_name, incidents)
        value = len(incidents)

        result: ServiceResult = {
            "value": value,
            "details": details,
        }

        self.logger.info(f"Incident analysis complete: {value} unresolved incidents")
        self.logger.method_exit("get_result", result)
        return result

    def _build_details(
        self,
        target_dns_name: Optional[str],
        incidents: "dict[int, list[AlertDict]]",
    ) -> "list[str]":
        """Format a summary line plus one line per incident (limited to 10)."""
        details: list[str] = []
        if not incidents:
            return details

        details.append(f"Unresolved incidents for {target_dns_name}")

        for incident_id in sorted(incidents)[:10]:
            alerts = incidents[incident_id]
            severity = max(
                (alert.get("severity", "Unknown") for alert in alerts),
                key=lambda sev: _SEVERITY_ORDER.get(sev, -1),
            )
            titles = ", ".join(alert.get("title", "Unknown alert") for alert in alerts)
            details.append(
                f"Incident {incident_id} - {len(alerts)} alert(s) "
                f"({severity.lower()}): {titles}"
            )
        return details
