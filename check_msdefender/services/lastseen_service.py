"""Last seen service implementation."""

import re
from datetime import datetime
from typing import Any, Dict, Optional

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.core.logging_config import get_verbose_logger


class LastSeenService:
    """Service for checking last seen status."""

    def __init__(self, defender_client: Any, verbose_level: int = 0) -> None:
        """Initialize with Defender client."""
        self.defender = defender_client
        self.logger = get_verbose_logger(__name__, verbose_level)

    def get_result(
        self, machine_id: Optional[str] = None, dns_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get last seen result with value and details for a machine."""
        self.logger.method_entry("get_result", machine_id=machine_id, dns_name=dns_name)

        if not machine_id and not dns_name:
            raise ValidationError("Either machine_id or dns_name must be provided")

        # Get machine information
        if dns_name:
            self.logger.info(f"Fetching machine data by DNS name: {dns_name}")
            machines_data = self.defender.get_machine_by_dns_name(dns_name)
            if not machines_data.get("value"):
                raise ValidationError(f"Machine not found with DNS name: {dns_name}")
            machine_data = machines_data["value"][0]
            self.logger.debug(f"Found machine: {machine_data.get('id', 'unknown')}")
            machine_id = machine_data.get("id")

        # Extract last seen timestamp
        machine_details = self.defender.get_machine_by_id(machine_id)
        last_seen_str = machine_details.get("lastSeen")
        if not last_seen_str:
            raise ValidationError("No lastSeen data available for machine")

        self.logger.debug(f"Last seen timestamp from API: {last_seen_str}")

        # Parse timestamp and calculate days difference
        try:
            # Handle high-precision microseconds by truncating to 6 digits
            timestamp_str = last_seen_str.replace("Z", "+00:00")
            # Regex to find and truncate microseconds longer than 6 digits
            timestamp_str = re.sub(r"\.(\d{6})\d+", r".\1", timestamp_str)

            last_seen = datetime.fromisoformat(timestamp_str)
            now = datetime.now(last_seen.tzinfo)
            days_diff = (now - last_seen).days

            # Create detailed output
            computer_name = machine_details.get("computerDnsName", "Unknown")
            last_seen_formatted = last_seen.strftime("%Y-%m-%d %H:%M:%S %Z")
            details = [
                f"Machine: {computer_name} - Last seen {days_diff} days ago ({last_seen_formatted})"
            ]

            result = {"value": days_diff, "details": details}

            self.logger.info(
                f"Machine last seen {days_diff} days ago ({last_seen_str})"
            )
            self.logger.method_exit("get_result", result)
            return result
        except (ValueError, TypeError) as e:
            self.logger.debug(f"Failed to parse timestamp: {e}")
            raise ValidationError(f"Invalid lastSeen timestamp: {e}")
