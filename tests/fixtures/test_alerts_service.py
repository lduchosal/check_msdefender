"""Fixture tests for AlertsService."""

import pytest

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.services.alerts_service import AlertsService
from tests.fixtures.mock_defender_client import MockDefenderClient


class TestAlertsServiceFixtures:
    """Fixture tests for AlertsService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = MockDefenderClient()
        self.service = AlertsService(self.mock_client)

    def test_get_result_by_machine_id_multiple_alerts(self):
        """Test getting alerts for machine with multiple alerts."""
        # test-machine-1 has 2 unresolved alerts: 1 High (New) + 1 Informational (New)
        result = self.service.get_result(machine_id="test-machine-1")

        # Should return 2 unresolved alerts
        assert result["value"] == 2
        assert len(result["details"]) == 3  # Summary line + 2 alert details

        # Check that details include both alerts
        details_text = "\n".join(result["details"])
        assert "Suspicious activity detected" in details_text
        assert "Automated investigation started manually" in details_text
        assert "test-machine-1.domain.com" in details_text

    def test_get_result_by_machine_id_resolved_alerts_only(self):
        """Test machine with only resolved alerts."""
        # test-machine-2 has 1 resolved alert
        result = self.service.get_result(machine_id="test-machine-2")

        # Should return 1 unresolved alert (InProgress status)
        assert result["value"] == 1
        assert len(result["details"]) == 2  # Summary line + 1 alert detail

        details_text = "\n".join(result["details"])
        assert "Manual investigation in progress" in details_text
        assert "test-machine-2.domain.com" in details_text

    def test_get_result_by_machine_id_low_severity_alert(self):
        """Test machine with low severity unresolved alert."""
        # test-machine-3 has 1 Low severity alert (New status)
        result = self.service.get_result(machine_id="test-machine-3")

        # Should return 1 unresolved alert
        assert result["value"] == 1
        assert len(result["details"]) == 2  # Summary line + 1 alert detail

        details_text = "\n".join(result["details"])
        assert "Suspicious file execution" in details_text
        assert "test-machine-3.domain.com" in details_text

    def test_get_result_by_dns_name(self):
        """Test getting alerts by DNS name."""
        # test-machine-2.domain.com should match alerts
        result = self.service.get_result(dns_name="test-machine-2.domain.com")

        # Should return 1 unresolved alert (InProgress)
        assert result["value"] == 1
        assert len(result["details"]) == 2  # Summary line + 1 alert detail

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

    def test_get_result_machine_without_alerts(self):
        """Test machine that exists but has no alerts."""
        # Create a machine that has no matching alerts in fixture data
        result = self.service.get_result(machine_id="test-machine-4")

        # Should return 0 alerts since test-machine-4 has no alerts in fixture
        assert result["value"] == 0
        assert result["details"] == []

    def test_alert_severity_categorization(self):
        """Test that alerts are properly categorized by severity."""
        # test-machine-1 has High + Informational alerts
        result = self.service.get_result(machine_id="test-machine-1")

        # Should count both as unresolved (High=1, Informational=1)
        assert result["value"] == 2

        # Check that summary mentions unresolved alerts (not specifically informational)
        details_text = "\n".join(result["details"])
        assert "Unresolved alerts for test-machine-1.domain.com" in details_text

    def test_alert_status_filtering(self):
        """Test that only unresolved alerts are counted."""
        # Based on fixture data, test-machine-1 has:
        # - 1 High/New (unresolved)
        # - 1 Informational/New (unresolved)
        # - 1 Medium/Resolved (resolved - should be filtered out)
        result = self.service.get_result(machine_id="test-machine-1")

        # Should only count the 2 unresolved alerts
        assert result["value"] == 2

        # Resolved alert should not appear in details
        details_text = "\n".join(result["details"])
        assert "Malware detected and remediated" not in details_text

    def test_alert_creation_time_format(self):
        """Test that alert creation times are properly formatted in output."""
        result = self.service.get_result(machine_id="test-machine-1")

        details_text = "\n".join(result["details"])

        # Should include timestamps in ISO format
        assert "2025-09-14T10:22:14.12Z" in details_text
        assert "2025-09-12T21:22:14.12Z" in details_text

    def test_alert_title_and_severity_in_output(self):
        """Test that alert titles and severities appear correctly in output."""
        result = self.service.get_result(machine_id="test-machine-1")

        details_text = "\n".join(result["details"])

        # Should include alert titles and severity/status
        assert "suspicious activity detected (new high)" in details_text.lower()
        assert (
            "automated investigation started manually (new informational)"
            in details_text.lower()
        )

    def test_dns_name_matching(self):
        """Test that alerts are matched by DNS name when provided."""
        # Use DNS name that should match alerts
        result = self.service.get_result(dns_name="test-machine-3.domain.com")

        # Should find the Low severity alert for test-machine-3
        assert result["value"] == 1

        details_text = "\n".join(result["details"])
        assert "Suspicious file execution" in details_text
