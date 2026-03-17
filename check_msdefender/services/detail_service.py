"""Detail service implementation."""

from __future__ import annotations

import json
from typing import Optional

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.services.models import (
    DefenderClientProtocol,
    MachineDict,
    ServiceResult,
)


class DetailService:
    """Service for getting machine details."""

    def __init__(
        self, defender_client: DefenderClientProtocol, verbose_level: int = 0
    ) -> None:
        """Initialize with Defender client."""
        self.defender = defender_client
        self.logger = get_verbose_logger(__name__, verbose_level)
        self._machine_details: Optional[MachineDict] = None

    def get_result(
        self, machine_id: Optional[str] = None, dns_name: Optional[str] = None
    ) -> ServiceResult:
        """
        Get machine details result with value and details.

        Returns:
            dict: Result with value (1 or 0) and details list
        """
        self.logger.method_entry("get_result", machine_id=machine_id, dns_name=dns_name)

        if not machine_id and not dns_name:
            raise ValidationError("Either machine_id or dns_name must be provided")

        try:
            # Get machine information
            if dns_name:
                self.logger.info(f"Fetching machine data by DNS name: {dns_name}")
                machines_data = self.defender.get_machine_by_dns_name(dns_name)
                if not machines_data.get("value"):
                    self.logger.info(f"Machine not found with DNS name: {dns_name}")
                    result: ServiceResult = {
                        "value": 0,
                        "details": [f"Machine not found with DNS name: {dns_name}"],
                    }
                    self.logger.method_exit("get_result", result)
                    return result
                machine_data = machines_data["value"][0]
                self.logger.debug(f"Found machine: {machine_data.get('id', 'unknown')}")
                machine_id = machine_data.get("id")

            # Get detailed machine information by ID
            self.logger.info(f"Fetching detailed machine data by ID: {machine_id}")
            assert machine_id is not None
            machine_details = self.defender.get_machine_by_id(machine_id)

            # Store the details for output formatting
            self._machine_details = machine_details

            # Create detailed output
            details: list[str] = []
            details.extend(
                (
                    f"Machine ID: {machine_details.get('id', 'Unknown')}",
                    f"Computer Name: {machine_details.get('computerDnsName', 'Unknown')}",
                    f"OS Platform: {machine_details.get('osPlatform', 'Unknown')}",
                    f"OS Version: {machine_details.get('osVersion', 'Unknown')}",
                    f"Health Status: {machine_details.get('healthStatus', 'Unknown')}",
                    f"Risk Score: {machine_details.get('riskScore', 'Unknown')}",
                )
            )

            result2: ServiceResult = {"value": 1, "details": details}

            self.logger.info("Machine details retrieved successfully")
            self.logger.method_exit("get_result", result2)
            return result2

        except Exception as e:
            self.logger.debug(f"Failed to get machine details: {e}")
            raise

    def get_machine_details_json(self) -> Optional[str]:
        """Get the machine details as formatted JSON string."""
        if self._machine_details is None:
            return None
        return json.dumps(self._machine_details, indent=2)
