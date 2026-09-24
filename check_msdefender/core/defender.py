"""Microsoft Defender API client."""

import time
from typing import Any, cast
from urllib.parse import unquote_plus

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from check_msdefender.core.exceptions import DefenderAPIError
from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.core.models import (
    AlertDict,
    AlertListResponse,
    MachineDict,
    MachineListResponse,
    ProductListResponse,
    VulnerabilityListResponse,
)

PARAM_EXPAND = "$expand"

PARAM_ORDERBY = "$orderby"

PARAM_FILTER = "$filter"

PARAM_SELECT = "$select"

# Transient API answers worth another try: throttling (429) and the 5xx a Microsoft-side
# hiccup produces. 4xx other than 429 are our mistakes; retrying them only wastes quota.
RETRY_STATUSES = (429, 500, 502, 503, 504)

# Retry budget, sized to keep a check well inside Nagios' 60 s service_check_timeout even
# for sub-commands that make two calls (DNS name -> id, then the endpoint). Only fast
# status answers are retried: a request that already burnt the full read/connect timeout
# is not tried again, or two calls x three attempts x 30 s would blow the budget. The
# sleeps between attempts are bounded: 0 s then BACKOFF_FACTOR * 2 s, or the server's
# Retry-After capped at RETRY_AFTER_MAX -- at most 10 s of waiting per call.
RETRY_ATTEMPTS = 3
BACKOFF_FACTOR = 2.0
RETRY_AFTER_MAX = 5


def _build_session() -> requests.Session:
    """Return a session that retries transient API failures with backoff."""
    retry = Retry(
        total=RETRY_ATTEMPTS - 1,
        connect=0,
        read=0,
        other=0,
        status=RETRY_ATTEMPTS - 1,
        status_forcelist=RETRY_STATUSES,
        allowed_methods=frozenset({"GET"}),
        backoff_factor=BACKOFF_FACTOR,
        respect_retry_after_header=True,
        retry_after_max=RETRY_AFTER_MAX,
        # Hand the last response back instead of raising MaxRetryError, so the caller
        # reports the real status rather than urllib3's "too many 503 error responses".
        raise_on_status=False,
    )
    session = requests.Session()
    # The Defender endpoints are HTTPS only; plain HTTP gets no retrying adapter.
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def _attempts(response: requests.Response) -> int:
    """Return how many attempts urllib3 made before settling on ``response``."""
    retries = getattr(response.raw, "retries", None)
    return len(retries.history) + 1 if isinstance(retries, Retry) else 1


def _describe_failure(error: requests.RequestException) -> str:
    """Render a failed API request as one Nagios-friendly line."""
    response = error.response
    if response is None:
        return f"MS Defender API request failed: {error}"
    attempts = _attempts(response)
    plural = "attempt" if attempts == 1 else "attempts"
    return (
        f"MS Defender API {response.status_code} {response.reason} "
        f"after {attempts} {plural}: GET {unquote_plus(response.url)}"
    )


class DefenderClient:
    """Client for Microsoft Defender API."""

    application_json = "application/json"

    def __init__(
        self,
        authenticator: Any,
        timeout: int = 30,
        region: str = "api",
        verbose_level: int = 0,
    ) -> None:
        """
        Initialize with authenticator and optional region.

        Args:
            authenticator: Authentication provider
            timeout: Request timeout in seconds
            region: Geographic region (eu, eu3, us, uk)
            verbose_level: Verbosity level for logging
        """
        self.authenticator = authenticator
        self.timeout = timeout
        self.region = region
        self.base_url = self._get_base_url(region)
        self.logger = get_verbose_logger(__name__, verbose_level)
        self.session = _build_session()

    def _get_base_url(self, region: str) -> str:
        """Get base URL for the specified region."""
        endpoints = {
            "eu": "https://eu.api.security.microsoft.com",
            "us": "https://us.api.security.microsoft.com",
            "uk": "https://uk.api.security.microsoft.com",
            "api": "https://api.security.microsoft.com",
        }
        return endpoints.get(region, endpoints["eu"])

    def get_machine_by_dns_name(self, dns_name: str) -> MachineListResponse:
        """Get machine information by DNS name."""
        self.logger.method_entry("get_machine_by_dns_name", dns_name=dns_name)

        token = self._get_token()

        url = f"{self.base_url}/api/machines"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        params = {PARAM_FILTER: f"computerDnsName eq '{dns_name}'", PARAM_SELECT: "id"}

        self.logger.info(f"Querying machine by DNS name: {dns_name}")
        result = cast(MachineListResponse, self._get_json(url, headers, params))
        self.logger.json_response(str(result))
        self.logger.method_exit("get_machine_by_dns_name", result)
        return result

    def get_machine_by_id(self, machine_id: str) -> MachineDict:
        """Get machine information by machine ID."""
        self.logger.method_entry("get_machine_by_id", machine_id=machine_id)

        token = self._get_token()

        url = f"{self.base_url}/api/machines/{machine_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        self.logger.info(f"Querying machine by ID: {machine_id}")
        result = cast(MachineDict, self._get_json(url, headers, None))
        self.logger.json_response(str(result))
        self.logger.method_exit("get_machine_by_id", result)
        return result

    def get_machine_vulnerabilities(self, machine_id: str) -> VulnerabilityListResponse:
        """Get vulnerabilities for a machine."""
        self.logger.method_entry("get_machine_vulnerabilities", machine_id=machine_id)

        token = self._get_token()

        url = f"{self.base_url}/api/machines/{machine_id}/vulnerabilities"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        self.logger.info(f"Querying vulnerabilities for machine: {machine_id}")
        result = cast(VulnerabilityListResponse, self._get_json(url, headers, None))
        self.logger.json_response(str(result))
        self.logger.method_exit("get_machine_vulnerabilities", result)
        return result

    def list_machines(self) -> MachineListResponse:
        """Get list of all machines."""
        self.logger.method_entry("list_machines")

        token = self._get_token()

        url = f"{self.base_url}/api/machines"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        params = {PARAM_SELECT: "id,computerDnsName,onboardingStatus,osPlatform"}

        self.logger.info("Querying all machines")
        result = cast(MachineListResponse, self._get_json(url, headers, params))
        self.logger.json_response(str(result))
        self.logger.method_exit("list_machines", result)
        return result

    def _fetch_alerts_paginated(
        self, url: str, params: "dict[str, str] | None"
    ) -> "list[AlertDict]":
        """
        Fetch alerts from a URL, following OData ``@odata.nextLink`` pagination.

        Returns the accumulated list of alert objects across every page so that no alert is silently
        dropped by a server-side page-size cap.
        """
        token = self._get_token()

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        alerts: list[AlertDict] = []
        next_url: str | None = url
        next_params: dict[str, str] | None = params

        while next_url:
            page = cast(
                "dict[str, Any]", self._get_json(next_url, headers, next_params)
            )
            alerts.extend(cast("list[AlertDict]", page.get("value", [])))

            # Follow server-driven pagination; nextLink already carries the query.
            next_link = page.get("@odata.nextLink")
            next_url = next_link if isinstance(next_link, str) else None
            next_params = None

        return alerts

    def get_alerts(self) -> AlertListResponse:
        """Get alerts from Microsoft Defender (all pages, tenant-wide)."""
        self.logger.method_entry("get_alerts")
        self.logger.info("Querying alerts")

        url = f"{self.base_url}/api/alerts"
        params = {
            PARAM_EXPAND: "evidence",
            PARAM_ORDERBY: "alertCreationTime desc",
            PARAM_SELECT: (
                "status,title,machineId,computerDnsName,incidentId,"
                "alertCreationTime,firstEventTime,lastEventTime,"
                "lastUpdateTime,severity"
            ),
        }

        result: AlertListResponse = {"value": self._fetch_alerts_paginated(url, params)}
        self.logger.json_response(str(result))
        self.logger.method_exit("get_alerts", result)
        return result

    def get_machine_alerts(self, machine_id: str) -> AlertListResponse:
        """Get all alerts related to a specific machine (all pages, device-scoped)."""
        self.logger.method_entry("get_machine_alerts", machine_id=machine_id)
        self.logger.info(f"Querying alerts for machine: {machine_id}")

        # The device-scoped alerts endpoint does not support OData query options
        # (e.g. $expand/$select/$top); sending any returns HTTP 400. Request it bare.
        url = f"{self.base_url}/api/machines/{machine_id}/alerts"

        result: AlertListResponse = {"value": self._fetch_alerts_paginated(url, None)}
        self.logger.json_response(str(result))
        self.logger.method_exit("get_machine_alerts", result)
        return result

    def get_products(self) -> ProductListResponse:
        """Get installed products for a machine."""
        self.logger.method_entry("get_products")

        token = self._get_token()

        # Use the TVM API endpoint for products
        url = f"{self.base_url}/api/machines/SoftwareVulnerabilitiesByMachine"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        params = {"pageIndex": "1", "pageSize": "50000"}

        self.logger.info("Querying products")
        result = cast(ProductListResponse, self._get_json(url, headers, params))
        self.logger.json_response(str(result))
        self.logger.method_exit("get_products", result)
        return result

    def _get_json(
        self, url: str, headers: "dict[str, str]", params: "dict[str, str] | None"
    ) -> Any:
        """
        GET ``url`` and return the decoded JSON body.

        Transient failures (429/5xx) are retried by the session's adapter; what is left
        once the retries are spent is reported as a single-line DefenderAPIError.

        Raises:
            DefenderAPIError: If the request fails or ends on an HTTP error status.
        """
        try:
            start_time = time.time()
            response = self.session.get(
                url, headers=headers, params=params, timeout=self.timeout
            )
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {e}")
            if e.response is not None:
                self.logger.debug(f"Response: {e.response.content!r}")
            raise DefenderAPIError(_describe_failure(e)) from e

    def _get_token(self) -> str:
        """Get access token from authenticator."""
        self.logger.trace("Getting access token from authenticator")
        scope = "https://api.securitycenter.microsoft.com/.default"
        token = self.authenticator.get_token(scope)
        self.logger.trace(f"Token acquired successfully (expires: {token.expires_on})")
        return str(token.token)
