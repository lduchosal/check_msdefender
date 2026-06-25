"""
Unit tests for the DefenderClient HTTP layer.

These tests patch ``requests.get`` so they exercise the real request-building code in
``DefenderClient`` (URL, query parameters, pagination, error handling) without any network access.
They are the regression guard for API-contract bugs that service-level tests (which mock the whole
client) cannot catch.
"""

from unittest.mock import Mock, patch

import pytest
import requests

from check_msdefender.core.defender import DefenderClient
from check_msdefender.core.exceptions import DefenderAPIError


def _make_client() -> DefenderClient:
    """Build a DefenderClient with a stubbed authenticator."""
    authenticator = Mock()
    token = Mock()
    token.token = "fake-token"
    token.expires_on = 0
    authenticator.get_token.return_value = token
    return DefenderClient(authenticator, region="api")


def _ok_response(payload: dict) -> Mock:
    """Create a mock 200 response returning ``payload`` from ``.json()``."""
    response = Mock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


class TestGetMachineAlerts:
    """Tests for the device-scoped alerts request."""

    @patch("check_msdefender.core.defender.requests.get")
    def test_uses_device_scoped_url_without_odata_params(self, mock_get):
        """
        The endpoint rejects OData options; the request must be sent bare.

        Regression guard for the HTTP 400 caused by ``$expand=evidence`` on
        ``/api/machines/{id}/alerts``.
        """
        mock_get.return_value = _ok_response({"value": [{"id": "a1"}]})

        result = _make_client().get_machine_alerts("MID-123")

        assert result == {"value": [{"id": "a1"}]}
        mock_get.assert_called_once()
        _, kwargs = mock_get.call_args
        url = mock_get.call_args.args[0]
        assert url == "https://api.security.microsoft.com/api/machines/MID-123/alerts"
        # No $expand / $select / $top — the device-scoped endpoint does not
        # support OData and returns 400 when any is supplied.
        assert kwargs["params"] is None

    @patch("check_msdefender.core.defender.requests.get")
    def test_follows_odata_nextlink_pagination(self, mock_get):
        """All pages are accumulated by following ``@odata.nextLink``."""
        next_link = "https://api.security.microsoft.com/api/machines/MID/alerts?page=2"
        page1 = _ok_response({"value": [{"id": "a1"}], "@odata.nextLink": next_link})
        page2 = _ok_response({"value": [{"id": "a2"}]})
        mock_get.side_effect = [page1, page2]

        result = _make_client().get_machine_alerts("MID")

        assert [a["id"] for a in result["value"]] == ["a1", "a2"]
        assert mock_get.call_count == 2
        # The second request targets the nextLink URL.
        assert mock_get.call_args_list[1].args[0] == next_link

    @patch("check_msdefender.core.defender.requests.get")
    def test_http_error_raises_defender_api_error(self, mock_get):
        """An HTTP 400 (or any HTTPError) surfaces as DefenderAPIError."""
        response = Mock()
        response.status_code = 400
        response.content = b"Bad Request"
        response.raise_for_status.side_effect = requests.HTTPError("400 Bad Request")
        mock_get.return_value = response

        client = _make_client()
        with pytest.raises(DefenderAPIError, match="Failed to query MS Defender API"):
            client.get_machine_alerts("MID")


class TestGetAlerts:
    """Tests for the tenant-wide alerts request."""

    @patch("check_msdefender.core.defender.requests.get")
    def test_requests_incident_id_and_evidence(self, mock_get):
        """The tenant-wide endpoint supports OData and must select incidentId."""
        mock_get.return_value = _ok_response({"value": []})

        client = _make_client()
        client.get_alerts()

        _, kwargs = mock_get.call_args
        params = kwargs["params"]
        assert params["$expand"] == "evidence"
        assert "incidentId" in params["$select"]
        # No artificial page cap that could silently drop alerts.
        assert "$top" not in params

    @patch("check_msdefender.core.defender.requests.get")
    def test_follows_pagination(self, mock_get):
        """Tenant-wide alerts also follow ``@odata.nextLink``."""
        next_link = "https://api.security.microsoft.com/api/alerts?page=2"
        page1 = _ok_response({"value": [{"id": "a1"}], "@odata.nextLink": next_link})
        page2 = _ok_response({"value": [{"id": "a2"}]})
        mock_get.side_effect = [page1, page2]

        result = _make_client().get_alerts()

        assert len(result["value"]) == 2
        assert mock_get.call_count == 2
