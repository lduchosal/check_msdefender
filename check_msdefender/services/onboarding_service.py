"""Onboarding status service implementation."""

from typing import Any, Dict, Optional

from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.core.models import OnboardingStatus
from check_msdefender.services.machine_resolver import resolve_machine_id


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

        machine_id = resolve_machine_id(self.defender, machine_id, dns_name)

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
