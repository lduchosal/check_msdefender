"""Microsoft Defender API client."""

import time
from typing import Any, cast

import requests

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


class DefenderClient:
    """Client for Microsoft Defender API."""

    application_json = "application/json"

    def __init__(
        self,
        authenticator: Any,
        timeout: int = 15,
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
        """Get machine information by DNS name.

        Raises:
            DefenderAPIError: If the Microsoft Defender API request fails.
        """
        self.logger.method_entry("get_machine_by_dns_name", dns_name=dns_name)

        token = self._get_token()

        url = f"{self.base_url}/api/machines"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        params = {PARAM_FILTER: f"computerDnsName eq '{dns_name}'", PARAM_SELECT: "id"}

        try:
            start_time = time.time()
            self.logger.info(f"Querying machine by DNS name: {dns_name}")
            response = requests.get(
                url, headers=headers, params=params, timeout=self.timeout
            )
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()

            result = cast(MachineListResponse, response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("get_machine_by_dns_name", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {e.response.content!r}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {e}")

    def get_machine_by_id(self, machine_id: str) -> MachineDict:
        """Get machine information by machine ID.

        Raises:
            DefenderAPIError: If the Microsoft Defender API request fails.
        """
        self.logger.method_entry("get_machine_by_id", machine_id=machine_id)

        token = self._get_token()

        url = f"{self.base_url}/api/machines/{machine_id}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        try:
            start_time = time.time()
            self.logger.info(f"Querying machine by ID: {machine_id}")
            response = requests.get(url, headers=headers, timeout=self.timeout)
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()

            result = cast(MachineDict, response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("get_machine_by_id", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {e.response.content!r}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {e}")

    def get_machine_vulnerabilities(self, machine_id: str) -> VulnerabilityListResponse:
        """Get vulnerabilities for a machine.

        Raises:
            DefenderAPIError: If the Microsoft Defender API request fails.
        """
        self.logger.method_entry("get_machine_vulnerabilities", machine_id=machine_id)

        token = self._get_token()

        url = f"{self.base_url}/api/machines/{machine_id}/vulnerabilities"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        try:
            start_time = time.time()
            self.logger.info(f"Querying vulnerabilities for machine: {machine_id}")
            response = requests.get(url, headers=headers, timeout=self.timeout)
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()

            result = cast(VulnerabilityListResponse, response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("get_machine_vulnerabilities", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {e.response.content!r}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {e}")

    def list_machines(self) -> MachineListResponse:
        """Get list of all machines.

        Raises:
            DefenderAPIError: If the Microsoft Defender API request fails.
        """
        self.logger.method_entry("list_machines")

        token = self._get_token()

        url = f"{self.base_url}/api/machines"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        params = {PARAM_SELECT: "id,computerDnsName,onboardingStatus,osPlatform"}

        try:
            start_time = time.time()
            self.logger.info("Querying all machines")
            response = requests.get(
                url, headers=headers, params=params, timeout=self.timeout
            )
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()

            result = cast(MachineListResponse, response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("list_machines", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {e.response.content!r}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {e}")

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
        next_url: "str | None" = url
        next_params: "dict[str, str] | None" = params

        try:
            while next_url:
                start_time = time.time()
                response = requests.get(
                    next_url,
                    headers=headers,
                    params=next_params,
                    timeout=self.timeout,
                )
                elapsed = time.time() - start_time

                self.logger.api_call("GET", next_url, response.status_code, elapsed)
                response.raise_for_status()

                page = cast("dict[str, Any]", response.json())
                alerts.extend(cast("list[AlertDict]", page.get("value", [])))

                # Follow server-driven pagination; nextLink already carries the query.
                next_link = page.get("@odata.nextLink")
                next_url = next_link if isinstance(next_link, str) else None
                next_params = None

            return alerts
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {e.response.content!r}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {e}")

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
        """Get installed products for a machine.

        Raises:
            DefenderAPIError: If the Microsoft Defender API request fails.
        """
        self.logger.method_entry("get_products")

        token = self._get_token()

        # Use the TVM API endpoint for products
        url = f"{self.base_url}/api/machines/SoftwareVulnerabilitiesByMachine"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        params = {"pageIndex": "1", "pageSize": "50000"}

        try:
            start_time = time.time()
            self.logger.info("Querying products")
            response = requests.get(
                url, headers=headers, params=params, timeout=self.timeout
            )
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()

            result = cast(ProductListResponse, response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("get_products", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {e}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {e.response.content!r}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {e}")

    def _get_token(self) -> str:
        """Get access token from authenticator."""
        self.logger.trace("Getting access token from authenticator")
        scope = "https://api.securitycenter.microsoft.com/.default"
        token = self.authenticator.get_token(scope)
        self.logger.trace(f"Token acquired successfully (expires: {token.expires_on})")
        return str(token.token)
