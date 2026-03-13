"""Fixture tests for OnboardingService."""

import pytest

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.services.models import OnboardingStatus
from check_msdefender.services.onboarding_service import OnboardingService
from tests.fixtures.mock_defender_client import MockDefenderClient


class TestOnboardingServiceFixtures:
    """Fixture tests for OnboardingService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = MockDefenderClient()
        self.service = OnboardingService(self.mock_client)

    def test_get_result_by_machine_id_onboarded(self):
        """Test getting onboarding status by machine ID - Onboarded."""
        result = self.service.get_result(machine_id="test-machine-1")
        assert result["value"] == OnboardingStatus.ONBOARDED.value

    def test_get_result_by_machine_id_insufficient_info(self):
        """Test getting onboarding status by machine ID - InsufficientInfo."""
        result = self.service.get_result(machine_id="test-machine-2")
        assert result["value"] == OnboardingStatus.INSUFFICIENT_INFO.value

    def test_get_result_by_machine_id_unknown(self):
        """Test getting onboarding status by machine ID - Unknown."""
        result = self.service.get_result(machine_id="test-machine-3")
        assert result["value"] == OnboardingStatus.UNKNOWN.value

    def test_get_result_by_dns_name_onboarded(self):
        """Test getting onboarding status by DNS name - Onboarded."""
        result = self.service.get_result(dns_name="test-machine-1.domain.com")
        assert result["value"] == OnboardingStatus.ONBOARDED.value

    def test_get_result_by_dns_name_insufficient_info(self):
        """Test getting onboarding status by DNS name - InsufficientInfo."""
        result = self.service.get_result(dns_name="test-machine-2.domain.com")
        assert result["value"] == OnboardingStatus.INSUFFICIENT_INFO.value

    def test_get_result_no_parameters(self):
        """Test error when no parameters provided."""
        with pytest.raises(
            ValidationError, match="Either machine_id or dns_name must be provided"
        ):
            self.service.get_result()

    def test_get_result_nonexistent_dns_name(self):
        """Test error when DNS name doesn't exist."""
        with pytest.raises(ValidationError, match="Machine not found with DNS name"):
            self.service.get_result(dns_name="nonexistent.domain.com")

    def test_get_result_nonexistent_machine_id(self):
        """Test error when machine ID doesn't exist."""
        with pytest.raises(ValidationError, match="Machine not found"):
            self.service.get_result(machine_id="nonexistent-machine")

    def test_get_result_unknown_status_mapping(self):
        """Test handling of unknown onboarding status values."""

        # Create a mock client that returns unknown status
        class MockClientUnknownStatus:
            def get_machine_by_id(self, machine_id):
                return {"id": machine_id, "onboardingStatus": "SomeUnknownStatus"}

        result = OnboardingService(MockClientUnknownStatus()).get_result(
            machine_id="test-machine"
        )
        assert result["value"] == OnboardingStatus.UNKNOWN.value

    def test_get_result_missing_onboarding_status(self):
        """Test handling of missing onboardingStatus field."""

        # Create a mock client that returns no onboarding status
        class MockClientMissingStatus:
            def get_machine_by_id(self, machine_id):
                return {"id": machine_id}

        result = OnboardingService(MockClientMissingStatus()).get_result(
            machine_id="test-machine"
        )
        assert result["value"] == OnboardingStatus.UNKNOWN.value
