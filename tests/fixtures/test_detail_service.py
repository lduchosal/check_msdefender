"""Fixture tests for DetailService."""

import json

import pytest

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.services.detail_service import DetailService
from tests.fixtures.mock_defender_client import MockDefenderClient


class TestDetailServiceFixtures:
    """Fixture tests for DetailService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = MockDefenderClient()
        self.service = DetailService(self.mock_client)

    def test_get_result_by_machine_id(self):
        """Test getting machine details by machine ID."""
        result = self.service.get_result(machine_id="test-machine-1")
        assert result["value"] == 1  # Found

        # Check that details are stored
        details = self.service.get_machine_details_json()
        assert details is not None
        details_dict = json.loads(details)

        # Verify key fields from fixture data
        assert details_dict["id"] == "test-machine-1"
        assert details_dict["computerDnsName"] == "test-machine-1.domain.com"
        assert details_dict["osPlatform"] == "Windows10"
        assert details_dict["version"] == "1909"
        assert details_dict["osProcessor"] == "x64"
        assert details_dict["lastIpAddress"] == "192.168.1.100"
        assert details_dict["healthStatus"] == "Active"
        assert details_dict["riskScore"] == "Medium"

    def test_get_result_by_dns_name(self):
        """Test getting machine details by DNS name."""
        result = self.service.get_result(dns_name="test-machine-2.domain.com")
        assert result["value"] == 1  # Found

        # Check that details are stored
        details = self.service.get_machine_details_json()
        assert details is not None
        details_dict = json.loads(details)

        # Verify key fields for test-machine-2
        assert details_dict["id"] == "test-machine-2"
        assert details_dict["computerDnsName"] == "test-machine-2.domain.com"
        assert details_dict["osPlatform"] == "Windows11"
        assert details_dict["version"] == "22H2"
        assert details_dict["healthStatus"] == "Inactive"
        assert details_dict["riskScore"] == "Low"

    def test_get_result_no_parameters(self):
        """Test error when no parameters provided."""
        with pytest.raises(
            ValidationError, match="Either machine_id or dns_name must be provided"
        ):
            self.service.get_result()

    def test_get_result_nonexistent_dns_name(self):
        """Test when DNS name doesn't exist."""
        result = self.service.get_result(dns_name="nonexistent.domain.com")
        assert result["value"] == 0  # Not found

        # Details should not be available for non-existent machine
        details = self.service.get_machine_details_json()
        assert details is None

    def test_get_result_nonexistent_machine_id(self):
        """Test error when machine ID doesn't exist."""
        with pytest.raises(
            ValidationError, match="Machine not found: nonexistent-machine"
        ):
            self.service.get_result(machine_id="nonexistent-machine")

    def test_machine_details_comprehensive(self):
        """Test that all expected machine detail fields are present."""
        self.service.get_result(machine_id="test-machine-3")
        details = self.service.get_machine_details_json()
        assert details is not None
        details_dict = json.loads(details)

        # Verify all expected fields from the documentation are present
        expected_fields = [
            "id",
            "computerDnsName",
            "lastSeen",
            "osPlatform",
            "version",
            "osProcessor",
            "lastIpAddress",
            "lastExternalIpAddress",
            "healthStatus",
            "deviceValue",
            "rbacGroupId",
            "riskScore",
        ]

        for field in expected_fields:
            assert field in details_dict, (
                f"Field '{field}' missing from machine details"
            )

        # Verify specific values for test-machine-3
        assert details_dict["id"] == "test-machine-3"
        assert details_dict["osPlatform"] == "WindowsServer2019"
        assert details_dict["deviceValue"] == "High"
        assert details_dict["rbacGroupId"] == 789

    def test_get_machine_details_json_without_data(self):
        """Test getting JSON details when no data has been retrieved."""
        # Before calling get_result, details should be None
        details = self.service.get_machine_details_json()
        assert details is None

    def test_get_machine_details_json_formatting(self):
        """Test that JSON output is properly formatted."""
        self.service.get_result(machine_id="test-machine-1")
        details = self.service.get_machine_details_json()

        # Should be valid JSON
        assert details is not None
        details_dict = json.loads(details)
        assert isinstance(details_dict, dict)

        # Should be pretty-printed (contains newlines and indentation)
        assert "\n" in details
        assert "  " in details  # 2-space indentation
