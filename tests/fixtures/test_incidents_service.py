"""Fixture tests for IncidentsService."""

import pytest

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.services.incidents_service import IncidentsService
from tests.fixtures.mock_defender_client import MockDefenderClient


class TestIncidentsServiceFixtures:
    """Fixture tests for IncidentsService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = MockDefenderClient()
        self.service = IncidentsService(self.mock_client)

    def test_machine_with_single_incident(self):
        """Test-machine-1 has 2 unresolved alerts under one incident (101)."""
        result = self.service.get_result(machine_id="test-machine-1")

        assert result["value"] == 1
        assert len(result["details"]) == 2  # Summary + 1 incident line

        details_text = "\n".join(result["details"])
        assert "Incident 101" in details_text
        assert "2 alert(s)" in details_text
        # Highest severity of the incident (High) surfaces
        assert "(high)" in details_text

    def test_machine_with_unresolved_incident(self):
        """Test-machine-2 has one unresolved (InProgress) incident (202)."""
        result = self.service.get_result(machine_id="test-machine-2")

        assert result["value"] == 1
        details_text = "\n".join(result["details"])
        assert "Incident 202" in details_text

    def test_machine_low_severity_incident(self):
        """Test-machine-3 has a single Low severity incident (301)."""
        result = self.service.get_result(machine_id="test-machine-3")

        assert result["value"] == 1
        details_text = "\n".join(result["details"])
        assert "Incident 301" in details_text

    def test_machine_without_alerts(self):
        """Test-machine-4 exists but has no alerts, so no incidents."""
        result = self.service.get_result(machine_id="test-machine-4")

        assert result["value"] == 0
        assert result["details"] == []

    def test_by_dns_name(self):
        """Resolving by DNS name yields the same incident count."""
        result = self.service.get_result(dns_name="test-machine-1.domain.com")

        assert result["value"] == 1

    def test_nonexistent_dns_name(self):
        """Unknown DNS name raises a validation error."""
        with pytest.raises(ValidationError, match="Machine not found with DNS name"):
            self.service.get_result(dns_name="nonexistent.domain.com")
