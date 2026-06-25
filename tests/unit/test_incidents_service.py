"""Unit tests for IncidentsService."""

from unittest.mock import Mock

import pytest

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.services.incidents_service import IncidentsService


class TestIncidentsService:
    """Unit tests for IncidentsService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.service = IncidentsService(self.mock_client)

    def test_init(self):
        """Test service initialization."""
        assert self.service.defender == self.mock_client
        assert hasattr(self.service, "logger")

    def test_get_result_no_parameters(self):
        """Test error when no parameters provided."""
        with pytest.raises(
            ValidationError, match="Either machine_id or dns_name must be provided"
        ):
            self.service.get_result()

        self.mock_client.get_machine_alerts.assert_not_called()

    def test_get_result_groups_alerts_by_incident(self):
        """Two unresolved alerts sharing an incidentId count as a single incident."""
        mock_alerts_data = {
            "value": [
                {
                    "severity": "Informational",
                    "status": "New",
                    "title": "Initial access detected",
                    "incidentId": 500,
                    "alertCreationTime": "2025-09-14T10:00:00.00Z",
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                },
                {
                    "severity": "High",
                    "status": "InProgress",
                    "title": "Malware goptaju found",
                    "incidentId": 500,
                    "alertCreationTime": "2025-09-14T10:05:00.00Z",
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                },
            ]
        }
        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_machine_alerts.return_value = mock_alerts_data
        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        result = self.service.get_result(machine_id="test-machine-123")

        # Two alerts, one incident
        assert result["value"] == 1
        assert len(result["details"]) == 2  # Summary + 1 incident line

        details_text = "\n".join(result["details"])
        assert "Incident 500" in details_text
        assert "2 alert(s)" in details_text
        # Most severe alert of the incident surfaces the severity
        assert "(high)" in details_text
        assert "Malware goptaju found" in details_text

    def test_get_result_multiple_incidents(self):
        """Distinct incidentIds are counted separately."""
        mock_alerts_data = {
            "value": [
                {
                    "severity": "High",
                    "status": "New",
                    "title": "Threat A",
                    "incidentId": 1,
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                },
                {
                    "severity": "Medium",
                    "status": "New",
                    "title": "Threat B",
                    "incidentId": 2,
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                },
            ]
        }
        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_machine_alerts.return_value = mock_alerts_data
        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        result = self.service.get_result(machine_id="test-machine-123")

        assert result["value"] == 2
        assert len(result["details"]) == 3  # Summary + 2 incident lines

    def test_get_result_resolved_incident_excluded(self):
        """Incidents whose alerts are all resolved are not counted."""
        mock_alerts_data = {
            "value": [
                {
                    "severity": "High",
                    "status": "Resolved",
                    "title": "Remediated threat",
                    "incidentId": 9,
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                }
            ]
        }
        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_machine_alerts.return_value = mock_alerts_data
        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        result = self.service.get_result(machine_id="test-machine-123")

        assert result["value"] == 0
        assert result["details"] == []

    def test_get_result_alert_without_incident_id_ignored(self):
        """Unresolved alerts without an incidentId do not create an incident."""
        mock_alerts_data = {
            "value": [
                {
                    "severity": "Low",
                    "status": "New",
                    "title": "Uncorrelated alert",
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                }
            ]
        }
        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_machine_alerts.return_value = mock_alerts_data
        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        result = self.service.get_result(machine_id="test-machine-123")

        assert result["value"] == 0
        assert result["details"] == []

    def test_get_result_by_dns_name(self):
        """Test retrieval by DNS name resolves to the device-scoped endpoint."""
        mock_dns_response = {"value": [{"id": "test-machine-456"}]}
        mock_alerts_data = {
            "value": [
                {
                    "severity": "High",
                    "status": "New",
                    "title": "Threat",
                    "incidentId": 77,
                    "machineId": "test-machine-456",
                    "computerDnsName": "test.example.com",
                }
            ]
        }

        self.mock_client.get_machine_by_dns_name.return_value = mock_dns_response
        self.mock_client.get_machine_alerts.return_value = mock_alerts_data

        result = self.service.get_result(dns_name="test.example.com")

        assert result["value"] == 1
        self.mock_client.get_machine_by_dns_name.assert_called_once_with(
            "test.example.com"
        )
        self.mock_client.get_machine_alerts.assert_called_once_with("test-machine-456")

    def test_get_result_dns_name_not_found(self):
        """Test error when DNS name doesn't exist."""
        self.mock_client.get_machine_by_dns_name.return_value = {"value": []}

        with pytest.raises(ValidationError, match="Machine not found with DNS name"):
            self.service.get_result(dns_name="nonexistent.domain.com")

        self.mock_client.get_machine_alerts.assert_not_called()
