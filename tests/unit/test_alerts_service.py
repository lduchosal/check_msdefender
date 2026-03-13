"""Unit tests for AlertsService."""

from unittest.mock import Mock

import pytest

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.services.alerts_service import AlertsService


class TestAlertsService:
    """Unit tests for AlertsService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.service = AlertsService(self.mock_client)

    def test_init(self):
        """Test service initialization."""
        assert self.service.defender == self.mock_client
        assert hasattr(self.service, "logger")

    def test_get_result_by_machine_id_success(self):
        """Test successful retrieval by machine ID."""
        # Mock the alerts API response
        mock_alerts_data = {
            "value": [
                {
                    "severity": "High",
                    "status": "New",
                    "title": "Suspicious activity detected",
                    "alertCreationTime": "2025-09-14T10:22:14.12Z",
                    "firstEventTime": "2025-09-14T10:22:13.7175652Z",
                    "lastEventTime": "2025-09-14T10:22:13.7175652Z",
                    "lastUpdateTime": "2025-09-14T10:24:04.42Z",
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                },
                {
                    "severity": "Informational",
                    "status": "Resolved",
                    "title": "Investigation completed",
                    "alertCreationTime": "2025-09-13T15:30:45.67Z",
                    "firstEventTime": "2025-09-13T15:30:44.1234567Z",
                    "lastEventTime": "2025-09-13T15:30:44.1234567Z",
                    "lastUpdateTime": "2025-09-13T16:15:22.89Z",
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                },
            ]
        }

        # Mock machine details API response
        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_alerts.return_value = mock_alerts_data
        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        result = self.service.get_result(machine_id="test-machine-123")

        # Should return 1 unresolved alert (High severity, New status)
        assert result["value"] == 1
        assert len(result["details"]) == 2  # Summary line + 1 alert detail

        # Should call the client methods
        self.mock_client.get_alerts.assert_called_once()
        self.mock_client.get_machine_by_id.assert_called_once_with("test-machine-123")

    def test_get_result_by_dns_name_success(self):
        """Test successful retrieval by DNS name."""
        # Mock DNS lookup response
        mock_dns_response = {"value": [{"id": "test-machine-456"}]}

        # Mock alerts API response
        mock_alerts_data = {
            "value": [
                {
                    "severity": "Medium",
                    "status": "InProgress",
                    "title": "Security scan in progress",
                    "alertCreationTime": "2025-09-14T12:00:00.00Z",
                    "firstEventTime": "2025-09-14T12:00:00.00Z",
                    "lastEventTime": "2025-09-14T12:00:00.00Z",
                    "lastUpdateTime": "2025-09-14T12:30:00.00Z",
                    "machineId": "test-machine-456",
                    "computerDnsName": "test.example.com",
                }
            ]
        }

        self.mock_client.get_machine_by_dns_name.return_value = mock_dns_response
        self.mock_client.get_alerts.return_value = mock_alerts_data

        result = self.service.get_result(dns_name="test.example.com")

        # Should return 1 unresolved alert
        assert result["value"] == 1
        assert len(result["details"]) == 2  # Summary line + 1 alert detail

        # Should call DNS lookup
        self.mock_client.get_machine_by_dns_name.assert_called_once_with(
            "test.example.com"
        )
        self.mock_client.get_alerts.assert_called_once()

    def test_get_result_by_dns_name_not_found(self):
        """Test error when DNS name doesn't exist."""
        # Mock empty DNS response
        mock_dns_response = {"value": []}
        self.mock_client.get_machine_by_dns_name.return_value = mock_dns_response

        with pytest.raises(ValidationError, match="Machine not found with DNS name"):
            self.service.get_result(dns_name="nonexistent.domain.com")

        self.mock_client.get_machine_by_dns_name.assert_called_once_with(
            "nonexistent.domain.com"
        )
        self.mock_client.get_alerts.assert_not_called()

    def test_get_result_no_parameters(self):
        """Test error when no parameters provided."""
        with pytest.raises(
            ValidationError, match="Either machine_id or dns_name must be provided"
        ):
            self.service.get_result()

        self.mock_client.get_machine_by_dns_name.assert_not_called()
        self.mock_client.get_machine_by_id.assert_not_called()
        self.mock_client.get_alerts.assert_not_called()

    def test_get_result_no_alerts_for_machine(self):
        """Test when no alerts exist for the machine."""
        # Mock alerts API response with no matching alerts
        mock_alerts_data = {
            "value": [
                {
                    "severity": "High",
                    "status": "New",
                    "title": "Alert for different machine",
                    "alertCreationTime": "2025-09-14T10:22:14.12Z",
                    "machineId": "different-machine",
                    "computerDnsName": "other.domain.com",
                }
            ]
        }

        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_alerts.return_value = mock_alerts_data
        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        result = self.service.get_result(machine_id="test-machine-123")

        # Should return 0 alerts
        assert result["value"] == 0
        assert result["details"] == []

    def test_get_result_only_resolved_alerts(self):
        """Test when machine has only resolved alerts."""
        mock_alerts_data = {
            "value": [
                {
                    "severity": "High",
                    "status": "Resolved",
                    "title": "Resolved security issue",
                    "alertCreationTime": "2025-09-14T10:22:14.12Z",
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                }
            ]
        }

        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_alerts.return_value = mock_alerts_data
        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        result = self.service.get_result(machine_id="test-machine-123")

        # Should return 0 unresolved alerts
        assert result["value"] == 0
        assert result["details"] == []

    def test_get_result_multiple_severity_alerts(self):
        """Test handling multiple alerts with different severities."""
        mock_alerts_data = {
            "value": [
                {
                    "severity": "High",
                    "status": "New",
                    "title": "Critical security threat",
                    "alertCreationTime": "2025-09-14T10:22:14.12Z",
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                },
                {
                    "severity": "Informational",
                    "status": "InProgress",
                    "title": "System scan running",
                    "alertCreationTime": "2025-09-14T11:00:00.00Z",
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                },
                {
                    "severity": "Medium",
                    "status": "New",
                    "title": "Suspicious file detected",
                    "alertCreationTime": "2025-09-14T12:00:00.00Z",
                    "machineId": "test-machine-123",
                    "computerDnsName": "test.domain.com",
                },
            ]
        }

        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_alerts.return_value = mock_alerts_data
        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        result = self.service.get_result(machine_id="test-machine-123")

        # Should return 3 unresolved alerts
        assert result["value"] == 3
        assert len(result["details"]) == 4  # Summary line + 3 alert details

    def test_get_result_api_exception_propagation(self):
        """Test that API exceptions are properly propagated."""
        self.mock_client.get_alerts.side_effect = Exception("API Error")

        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        with pytest.raises(Exception, match="API Error"):
            self.service.get_result(machine_id="test-machine-123")

    def test_logging_calls(self):
        """Test that logging methods are called appropriately."""
        # Mock logger
        mock_logger = Mock()
        self.service.logger = mock_logger

        # Mock successful response
        mock_alerts_data = {"value": []}
        mock_machine_data = {
            "id": "test-machine-123",
            "computerDnsName": "test.domain.com",
        }

        self.mock_client.get_alerts.return_value = mock_alerts_data
        self.mock_client.get_machine_by_id.return_value = mock_machine_data

        self.service.get_result(machine_id="test-machine-123")

        # Verify logging calls
        mock_logger.method_entry.assert_called_once()
        mock_logger.method_exit.assert_called_once()
        assert mock_logger.info.call_count >= 2  # At least 2 info calls expected
