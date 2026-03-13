"""Fixture tests for VulnerabilitiesService."""

import pytest

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.services.vulnerabilities_service import VulnerabilitiesService
from tests.fixtures.mock_defender_client import MockDefenderClient


class TestVulnerabilitiesServiceFixtures:
    """Fixture tests for VulnerabilitiesService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = MockDefenderClient()
        self.service = VulnerabilitiesService(self.mock_client)

    def test_get_result_by_machine_id_multiple_vulnerabilities(self):
        """Test getting vulnerability score by machine ID with multiple vulnerabilities."""
        # test-machine-1 has: 1 critical (100), 1 high (10), 1 medium (5) = 115 total
        result = self.service.get_result(machine_id="test-machine-1")
        assert result["value"] == 115

    def test_get_result_by_machine_id_low_vulnerabilities(self):
        """Test getting vulnerability score by machine ID with low severity vulnerabilities."""
        # test-machine-2 has: 1 low (1), 1 medium (5) = 6 total
        result = self.service.get_result(machine_id="test-machine-2")
        assert result["value"] == 6

    def test_get_result_by_machine_id_no_vulnerabilities(self):
        """Test getting vulnerability score by machine ID with no vulnerabilities."""
        # test-machine-3 has no vulnerabilities
        result = self.service.get_result(machine_id="test-machine-3")
        assert result["value"] == 0

    def test_get_result_by_dns_name(self):
        """Test getting vulnerability score by DNS name."""
        # test-machine-1.domain.com resolves to test-machine-1
        result = self.service.get_result(dns_name="test-machine-1.domain.com")
        assert result["value"] == 115

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
        """Test vulnerability score for nonexistent machine ID."""
        # Mock client returns empty vulnerabilities for unknown machines
        result = self.service.get_result(machine_id="nonexistent-machine")
        assert result["value"] == 0

    def test_vulnerability_score_calculation(self):
        """Test vulnerability score calculation weights."""

        # Create mock client with specific vulnerability counts
        class MockClientSpecificVulns:
            def get_machine_by_dns_name(self, dns_name):
                return {"value": []}

            def get_machine_vulnerabilities(self, machine_id):
                return {
                    "value": [
                        {"id": "vuln-1", "severity": "Critical"},
                        {"id": "vuln-2", "severity": "Critical"},
                        {"id": "vuln-3", "severity": "High"},
                        {"id": "vuln-4", "severity": "High"},
                        {"id": "vuln-5", "severity": "High"},
                        {"id": "vuln-6", "severity": "Medium"},
                        {"id": "vuln-7", "severity": "Low"},
                        {"id": "vuln-8", "severity": "Low"},
                        {"id": "vuln-9", "severity": "Low"},
                        {"id": "vuln-10", "severity": "Low"},
                    ]
                }

        result = VulnerabilitiesService(MockClientSpecificVulns()).get_result(
            machine_id="test-machine"
        )
        # 2 critical (200) + 3 high (30) + 1 medium (5) + 4 low (4) = 239
        assert result["value"] == 239

    def test_unknown_severity_handling(self):
        """Test handling of unknown severity values."""

        # Create mock client with unknown severity
        class MockClientUnknownSeverity:
            def get_machine_by_dns_name(self, dns_name):
                return {"value": []}

            def get_machine_vulnerabilities(self, machine_id):
                return {
                    "value": [
                        {"id": "vuln-1", "severity": "Unknown"},
                        {"id": "vuln-2", "severity": ""},
                        {"id": "vuln-3"},  # Missing severity field
                    ]
                }

        result = VulnerabilitiesService(MockClientUnknownSeverity()).get_result(
            machine_id="test-machine"
        )
        # Unknown severities should not contribute to score
        assert result["value"] == 0

    def test_case_insensitive_severity(self):
        """Test that severity matching is case insensitive."""

        # Create mock client with mixed case severities
        class MockClientMixedCase:
            def get_machine_by_dns_name(self, dns_name):
                return {"value": []}

            def get_machine_vulnerabilities(self, machine_id):
                return {
                    "value": [
                        {"id": "vuln-1", "severity": "CRITICAL"},
                        {"id": "vuln-2", "severity": "High"},
                        {"id": "vuln-3", "severity": "medium"},
                        {"id": "vuln-4", "severity": "LOW"},
                    ]
                }

        result = VulnerabilitiesService(MockClientMixedCase()).get_result(
            machine_id="test-machine"
        )
        # 1 critical (100) + 1 high (10) + 1 medium (5) + 1 low (1) = 116
        assert result["value"] == 116
