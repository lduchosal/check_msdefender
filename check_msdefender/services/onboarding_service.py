"""Onboarding status service implementation."""

from typing import Any, Dict, Optional

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.services.models import OnboardingStatus


class OnboardingService:
    """Service for checking onboarding status."""

    def __init__(self, defender_client: Any, verbose_level: int = 0) -> None:
        """Initialize with Defender client."""
        self.defender = defender_client
        self.logger = get_verbose_logger(__name__, verbose_level)

    def get_result(
        self, machine_id: Optional[str] = None, dns_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get onboarding status result with value and details for a machine."""
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

        # Extract onboarding status
        machine_details = self.defender.get_machine_by_id(machine_id)
        onboarding_state = machine_details.get("onboardingStatus")
        self.logger.debug(f"Raw onboarding status from API: {onboarding_state}")

        if onboarding_state == "Onboarded":
            result_value = OnboardingStatus.ONBOARDED.value
            status_text = "Fully onboarded"
        elif onboarding_state == "InsufficientInfo":
            result_value = OnboardingStatus.INSUFFICIENT_INFO.value
            status_text = "Insufficient information for onboarding"
        else:
            result_value = OnboardingStatus.UNKNOWN.value
            status_text = f"Unknown onboarding status: {onboarding_state}"

        # Create detailed output
        computer_name = machine_details.get("computerDnsName", "Unknown")
        details = [f"Machine: {computer_name} - {status_text}"]

        result = {"value": result_value, "details": details}

        self.logger.info(
            f"Machine onboarding status: {onboarding_state} -> {result_value}"
        )
        self.logger.method_exit("get_result", result)
        return result
