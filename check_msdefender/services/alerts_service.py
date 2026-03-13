"""Alerts service implementation."""

from typing import Any, Dict, Optional

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.core.logging_config import get_verbose_logger


class AlertsService:
    """Service for checking machine alerts."""

    def __init__(self, defender_client: Any, verbose_level: int = 0) -> None:
        """Initialize with Defender client."""
        self.defender = defender_client
        self.logger = get_verbose_logger(__name__, verbose_level)

    def get_result(
        self, machine_id: Optional[str] = None, dns_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get alerts result with value and details for a machine."""
        self.logger.method_entry("get_result", machine_id=machine_id, dns_name=dns_name)

        if not machine_id and not dns_name:
            raise ValidationError("Either machine_id or dns_name must be provided")

        # Get machine information
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

        # Get all alerts
        self.logger.info("Fetching alerts from Microsoft Defender")
        all_alerts = self.defender.get_alerts().get("value", [])

        # Filter alerts for the specific machine
        machine_alerts = [
            alert
            for alert in all_alerts
            if alert.get("machineId") == target_machine_id
            or alert.get("computerDnsName") == target_dns_name
        ]

        self.logger.info(
            f"Found {len(machine_alerts)} alerts for machine {target_dns_name}"
        )

        # Categorize alerts by status and severity
        unresolved_alerts = [
            alert for alert in machine_alerts if alert.get("status") != "Resolved"
        ]
        informational_alerts = [
            alert
            for alert in unresolved_alerts
            if alert.get("severity") == "Informational"
        ]
        critical_warning_alerts = [
            alert
            for alert in unresolved_alerts
            if alert.get("severity") in ("High", "Medium", "Low")
        ]

        # Create details for output
        details = []
        if unresolved_alerts:
            summary_line = f"Unresolved alerts for {target_dns_name}"
            if informational_alerts and not critical_warning_alerts:
                summary_line = f"Unresolved informational alerts for {target_dns_name}"
            elif critical_warning_alerts:
                summary_line = f"Unresolved alerts for {target_dns_name}"
            details.append(summary_line)

            # Add individual alerts (limit to 10)
            for alert in unresolved_alerts[:10]:
                creation_time = alert.get("alertCreationTime", "Unknown")
                title = alert.get("title", "Unknown alert")
                status = alert.get("status", "Unknown")
                severity = alert.get("severity", "Unknown")
                details.append(
                    f"{creation_time} - {title} ({status} {severity.lower()})"
                )

        # Return the number of unresolved alerts as the value
        # This will be used by Nagios plugin for determining status based on thresholds
        value = len(unresolved_alerts)

        result = {
            "value": value,
            "details": details,
        }

        self.logger.info(
            f"Alert analysis complete: {len(unresolved_alerts)} unresolved alerts"
        )
        self.logger.method_exit("get_result", result)
        return result
