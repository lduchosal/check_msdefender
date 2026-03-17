"""Machines service implementation."""

from __future__ import annotations

from typing import Optional

from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.services.models import (
    DefenderClientProtocol,
    ServiceResult,
)


class MachinesService:
    """Service for listing machines."""

    def __init__(
        self, defender_client: DefenderClientProtocol, verbose_level: int = 0
    ) -> None:
        """Initialize with Defender client."""
        self.defender = defender_client
        self.logger = get_verbose_logger(__name__, verbose_level)

    def get_result(
        self, machine_id: Optional[str] = None, dns_name: Optional[str] = None
    ) -> ServiceResult:
        """Get machine count result with value and details."""
        self.logger.method_entry("get_result")

        # Get all machines
        self.logger.info("Fetching all machines from Defender API")
        machines_data = self.defender.list_machines()

        if not machines_data.get("value"):
            self.logger.info("No machines found")
            result: ServiceResult = {
                "value": 0,
                "details": ["No machines found in Microsoft Defender"],
            }
            self.logger.method_exit("get_result", result)
            return result

        machines = machines_data["value"]
        machine_count = len(machines)

        # Create detailed output
        details: list[str] = [f"Total machines: {machine_count}"]

        # List machines
        # Define the sort order
        status_priority: dict[str, int] = {
            "Onboarded": 1,
            "InsufficientInfo": 2,
            "Unsupported": 3,
            "CanBeOnboarded": 4,
        }

        # Sort by priority (unknown statuses get priority 99)
        sorted_machines = sorted(
            machines,
            key=lambda x: (
                status_priority.get(x.get("onboardingStatus", "") or "", 99),
                x.get("computerDnsName", "") or "",
            ),
        )
        for machine in sorted_machines:
            onboarded = (
                "\u2713"
                if machine.get("onboardingStatus") == "Onboarded"
                else "\u2717"
            )
            details.append(
                f"{machine.get('id', '')}: {machine.get('computerDnsName', '')} ({machine.get('osPlatform', '')}) {onboarded}"
            )

        result2: ServiceResult = {"value": machine_count, "details": details}

        self.logger.info(f"Found {machine_count} machines")
        self.logger.method_exit("get_result", result2)
        return result2

    def get_details(self) -> list[str]:
        """Get detailed machine information."""
        self.logger.method_entry("get_details")

        # Get all machines
        self.logger.info("Fetching all machines from Defender API")
        machines_data = self.defender.list_machines()

        if not machines_data.get("value"):
            self.logger.info("No machines found")
            self.logger.method_exit("get_details", [])
            return []

        machines = machines_data["value"]
        details: list[str] = []

        for machine in machines:
            machine_id = machine.get("id", "unknown")[:10]  # Truncate ID for display
            dns_name = machine.get("computerDnsName", "unknown")
            status = machine.get("onboardingStatus", "unknown")
            platform = machine.get("osPlatform", "unknown")

            details.append(f"{machine_id} {dns_name} {status} {platform}")

        self.logger.info(f"Prepared details for {len(details)} machines")
        self.logger.method_exit("get_details", details)
        return details
