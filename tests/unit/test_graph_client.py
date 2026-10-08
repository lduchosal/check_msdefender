"""Unit tests for the Graph security client HTTP layer."""

from unittest.mock import Mock, patch

import pytest
import requests

from check_msdefender.core.exceptions import DefenderAPIError
from check_msdefender.core.graph import GRAPH_SCOPE, GraphClient


def _make_client() -> GraphClient:
    """Build a GraphClient with a stubbed authenticator."""
    authenticator = Mock()
    authenticator.get_token.return_value = Mock(token="graph-token")
    return GraphClient(authenticator)


def _ok_response(payload: dict) -> Mock:
    """Create a mock 200 response returning ``payload`` from ``.json()``."""
    response = Mock()
    response.status_code = 200
    response.raise_for_status.return_value = None
    response.json.return_value = payload
    return response


class TestGraphClient:
    """Tests for the Graph incident and hunting requests."""

    @patch("check_msdefender.core.graph.requests.Session.request")
    def test_incident_expands_alerts_with_graph_token(self, mock_request):
        """The incident is read with its alerts, on a Graph-scoped token."""
        mock_request.return_value = _ok_response({"id": "199", "alerts": []})
        client = _make_client()

        result = client.get_security_incident(199)

        assert result == {"id": "199", "alerts": []}
        args, kwargs = mock_request.call_args
        assert args == (
            "GET",
            "https://graph.microsoft.com/v1.0/security/incidents/199",
        )
        assert kwargs["params"] == {"$expand": "alerts"}
        assert kwargs["headers"]["Authorization"] == "Bearer graph-token"
        client.authenticator.get_token.assert_called_with(GRAPH_SCOPE)

    @patch("check_msdefender.core.graph.requests.Session.request")
    def test_hunting_query_posts_kql_and_returns_rows(self, mock_request):
        """A hunting query is a POST of the KQL; the rows come back from ``results``."""
        mock_request.return_value = _ok_response({"results": [{"Count": 3}]})

        rows = _make_client().run_hunting_query("DeviceEvents | count")

        assert rows == [{"Count": 3}]
        args, kwargs = mock_request.call_args
        assert args == (
            "POST",
            "https://graph.microsoft.com/v1.0/security/runHuntingQuery",
        )
        assert kwargs["json"] == {"Query": "DeviceEvents | count"}

    @patch("check_msdefender.core.graph.requests.Session.request")
    def test_http_error_names_graph_and_method(self, mock_request):
        """A refused call becomes a one-line DefenderAPIError naming Graph and the method."""
        response = Mock(status_code=403, reason="Forbidden", url="https://graph/x")
        response.raw = Mock(retries=None)
        error = requests.HTTPError(response=response)
        failing = Mock()
        failing.raise_for_status.side_effect = error
        failing.status_code = 403
        mock_request.return_value = failing

        with pytest.raises(
            DefenderAPIError, match="^Graph API 403 Forbidden after 1 attempt: POST"
        ):
            _make_client().run_hunting_query("x")

    def test_post_is_retried(self):
        """RunHuntingQuery only reads: its POST is retried like a GET."""
        adapter = _make_client().session.get_adapter("https://graph.microsoft.com")
        assert "POST" in adapter.max_retries.allowed_methods
