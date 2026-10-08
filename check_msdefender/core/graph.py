"""Microsoft Graph security API client (incidents and Advanced Hunting)."""

import time
from typing import Any, cast

import requests

from check_msdefender.core.defender import build_session, describe_failure
from check_msdefender.core.exceptions import DefenderAPIError
from check_msdefender.core.logging_config import get_verbose_logger

GRAPH_URL = "https://graph.microsoft.com/v1.0"

GRAPH_SCOPE = "https://graph.microsoft.com/.default"

GRAPH_API = "Graph API"


class GraphClient:
    """
    Client for the Microsoft Graph security endpoints.

    Needs the application permissions ``SecurityIncident.Read.All`` (incidents) and
    ``ThreatHunting.Read.All`` (Advanced Hunting).
    """

    def __init__(
        self, authenticator: Any, timeout: int = 30, verbose_level: int = 0
    ) -> None:
        """
        Initialize with authenticator.

        Args:
            authenticator: Authentication provider
            timeout: Request timeout in seconds
            verbose_level: Verbosity level for logging
        """
        self.authenticator = authenticator
        self.timeout = timeout
        self.logger = get_verbose_logger(__name__, verbose_level)
        # runHuntingQuery is a POST that only reads: as safe to retry as a GET.
        self.session = build_session(frozenset({"GET", "POST"}))

    def get_security_incident(self, incident_id: int) -> dict[str, Any]:
        """Get an incident with its alerts (and their evidence) from Graph."""
        self.logger.method_entry("get_security_incident", incident_id=incident_id)
        url = f"{GRAPH_URL}/security/incidents/{incident_id}"
        result = cast(
            "dict[str, Any]", self._request("GET", url, params={"$expand": "alerts"})
        )
        self.logger.method_exit("get_security_incident", result)
        return result

    def run_hunting_query(self, query: str) -> list[dict[str, Any]]:
        """Run an Advanced Hunting KQL query and return its result rows."""
        self.logger.method_entry("run_hunting_query", query=query)
        url = f"{GRAPH_URL}/security/runHuntingQuery"
        body = cast("dict[str, Any]", self._request("POST", url, json={"Query": query}))
        rows = cast("list[dict[str, Any]]", body.get("results", []))
        self.logger.method_exit("run_hunting_query", f"{len(rows)} row(s)")
        return rows

    def _request(
        self,
        method: str,
        url: str,
        params: "dict[str, str] | None" = None,
        json: "dict[str, Any] | None" = None,
    ) -> Any:
        """
        Send ``method`` to ``url`` and return the decoded JSON body.

        Raises:
            DefenderAPIError: If the request fails or ends on an HTTP error status.
        """
        headers = {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }
        try:
            start_time = time.time()
            response = self.session.request(
                method,
                url,
                headers=headers,
                params=params,
                json=json,
                timeout=self.timeout,
            )
            self.logger.api_call(
                method, url, response.status_code, time.time() - start_time
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {e}")
            if e.response is not None:
                self.logger.debug(f"Response: {e.response.content!r}")
            raise DefenderAPIError(describe_failure(e, GRAPH_API, method)) from e

    def _get_token(self) -> str:
        """Get a Graph access token from the authenticator."""
        return str(self.authenticator.get_token(GRAPH_SCOPE).token)
