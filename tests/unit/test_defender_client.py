"""
Unit tests for the DefenderClient HTTP layer.

These tests patch ``requests.Session.get`` so they exercise the real request-building code in
``DefenderClient`` (URL, query parameters, pagination, error handling) without any network access.
They are the regression guard for API-contract bugs that service-level tests (which mock the whole
client) cannot catch.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest.mock import Mock, patch

import pytest
import requests

from check_msdefender.core.defender import (
    RETRY_AFTER_MAX,
    RETRY_STATUSES,
    DefenderClient,
)
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

    @patch("check_msdefender.core.defender.requests.Session.get")
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

    @patch("check_msdefender.core.defender.requests.Session.get")
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

    @patch("check_msdefender.core.defender.requests.Session.get")
    def test_http_error_raises_defender_api_error(self, mock_get):
        """An HTTP 400 (or any HTTPError) surfaces as DefenderAPIError."""
        response = Mock()
        response.status_code = 400
        response.content = b"Bad Request"
        response.raise_for_status.side_effect = requests.HTTPError("400 Bad Request")
        mock_get.return_value = response

        client = _make_client()
        with pytest.raises(DefenderAPIError, match="MS Defender API"):
            client.get_machine_alerts("MID")


class TestGetAlerts:
    """Tests for the tenant-wide alerts request."""

    @patch("check_msdefender.core.defender.requests.Session.get")
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

    @patch("check_msdefender.core.defender.requests.Session.get")
    def test_follows_pagination(self, mock_get):
        """Tenant-wide alerts also follow ``@odata.nextLink``."""
        next_link = "https://api.security.microsoft.com/api/alerts?page=2"
        page1 = _ok_response({"value": [{"id": "a1"}], "@odata.nextLink": next_link})
        page2 = _ok_response({"value": [{"id": "a2"}]})
        mock_get.side_effect = [page1, page2]

        result = _make_client().get_alerts()

        assert len(result["value"]) == 2
        assert mock_get.call_count == 2


class TestDefaultTimeout:
    """Default request timeout (ken #974)."""

    def test_default_timeout_is_30s(self):
        """The client default matches the documented 30s default."""
        assert _make_client().timeout == 30


class _ScriptedHandler(BaseHTTPRequestHandler):
    """Answer each request with the next (status, headers) of the server's script."""

    def do_GET(self):
        """Serve the next scripted answer and record the hit."""
        server = self.server
        status, headers = server.script[min(server.hits, len(server.script) - 1)]
        server.hits += 1
        body = json.dumps({"value": [{"id": "MID"}]}).encode()
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        """Keep pytest output quiet."""


@pytest.fixture
def api_server():
    """Serve a scripted fake Defender API on localhost; yields a configure function."""
    server = HTTPServer(("127.0.0.1", 0), _ScriptedHandler)
    server.script = [(200, {})]
    server.hits = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    def serve(*script):
        server.script = list(script)
        client = _make_client()
        client.base_url = f"http://127.0.0.1:{server.server_port}"
        return client, server

    yield serve
    server.shutdown()
    server.server_close()


@pytest.fixture
def sleeps():
    """Record urllib3's retry sleeps instead of waiting them out."""
    with patch("urllib3.util.retry.time.sleep") as sleep:
        yield sleep


class TestRetry:
    """Transient API failures are retried through the real urllib3 adapter (ken #1121)."""

    def test_transient_503_then_success(self, api_server, sleeps):
        """A passing 503 is absorbed: the check sees the eventual 200."""
        client, server = api_server((503, {}), (200, {}))

        result = client.get_machine_by_dns_name("host.example")

        assert result == {"value": [{"id": "MID"}]}
        assert server.hits == 2

    def test_retries_exhausted_raise_one_line_error(self, api_server, sleeps):
        """A persistent 503 gives up after three attempts with a single-line error."""
        client, server = api_server((503, {}))

        with pytest.raises(DefenderAPIError) as excinfo:
            client.get_machine_by_dns_name("host.example")

        message = str(excinfo.value)
        assert server.hits == 3
        assert message.startswith(
            "MS Defender API 503 Service Unavailable after 3 attempts"
        )
        assert "computerDnsName eq 'host.example'" in message
        assert "\n" not in message

    def test_client_error_is_not_retried(self, api_server, sleeps):
        """A 4xx other than 429 is our mistake: one attempt, no retry."""
        client, server = api_server((400, {}))

        with pytest.raises(DefenderAPIError, match="400 Bad Request after 1 attempt:"):
            client.get_machine_by_id("MID")

        assert server.hits == 1
        sleeps.assert_not_called()

    def test_throttling_retry_after_is_capped(self, api_server, sleeps):
        """A 429 is retried and a long Retry-After is capped to keep the check in budget."""
        client, server = api_server((429, {"Retry-After": "120"}), (200, {}))

        client.get_machine_by_id("MID")

        assert server.hits == 2
        sleeps.assert_called_once_with(RETRY_AFTER_MAX)

    def test_every_retryable_status_is_retried(self):
        """The retry list covers throttling and the transient 5xx."""
        assert set(RETRY_STATUSES) == {429, 500, 502, 503, 504}
