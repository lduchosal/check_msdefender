"""Microsoft Defender API client."""

import time
import requests
from typing import Any, Dict, cast
from check_msdefender.core.exceptions import DefenderAPIError
from check_msdefender.core.logging_config import get_verbose_logger

PARAM_TOP = "$top"

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
        """Initialize with authenticator and optional region.

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

    def get_machine_by_dns_name(self, dns_name: str) -> Dict[str, Any]:
        """Get machine information by DNS name."""
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
            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()

            result = cast(Dict[str, Any], response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("get_machine_by_dns_name", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {str(e.response.content)}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {str(e)}")

    def get_machine_by_id(self, machine_id: str) -> Dict[str, Any]:
        """Get machine information by machine ID."""
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

            result = cast(Dict[str, Any], response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("get_machine_by_id", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {str(e.response.content)}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {str(e)}")

    def get_machine_vulnerabilities(self, machine_id: str) -> Dict[str, Any]:
        """Get vulnerabilities for a machine."""
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

            result = cast(Dict[str, Any], response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("get_machine_vulnerabilities", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {str(e.response.content)}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {str(e)}")

    def list_machines(self) -> Dict[str, Any]:
        """Get list of all machines."""
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
            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()

            result = cast(Dict[str, Any], response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("list_machines", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {str(e.response.content)}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {str(e)}")

    def get_alerts(self) -> Dict[str, Any]:
        """Get alerts from Microsoft Defender."""
        self.logger.method_entry("get_alerts")

        token = self._get_token()

        url = f"{self.base_url}/api/alerts"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        params = {
            PARAM_TOP: "100",
            PARAM_EXPAND: "evidence",
            PARAM_ORDERBY: "alertCreationTime desc",
            PARAM_SELECT: "status,title,machineId,computerDnsName,alertCreationTime,firstEventTime,lastEventTime,lastUpdateTime,severity",
        }

        try:
            start_time = time.time()
            self.logger.info("Querying alerts")
            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()

            result = cast(Dict[str, Any], response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("get_alerts", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {str(e.response.content)}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {str(e)}")

    def get_products(self) -> Dict[str, Any]:
        """Get installed products for a machine."""
        self.logger.method_entry("get_products")

        token = self._get_token()

        # Use the TVM API endpoint for vulnerabilities by machine
        url = f"{self.base_url}/api/vulnerabilities/machinesVulnerabilities"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": DefenderClient.application_json,
        }

        params = {"$top": "10000"}

        try:
            start_time = time.time()
            self.logger.info("Querying products")
            response = requests.get(url, headers=headers, params=params, timeout=self.timeout)
            elapsed = time.time() - start_time

            self.logger.api_call("GET", url, response.status_code, elapsed)
            response.raise_for_status()

            result = cast(Dict[str, Any], response.json())
            self.logger.json_response(str(result))
            self.logger.method_exit("get_products", result)
            return result
        except requests.RequestException as e:
            self.logger.debug(f"API request failed: {str(e)}")
            if hasattr(e, "response") and e.response is not None:
                self.logger.debug(f"Response: {str(e.response.content)}")
            raise DefenderAPIError(f"Failed to query MS Defender API: {str(e)}")

    def _get_token(self) -> str:
        """Get access token from authenticator."""
        self.logger.trace("Getting access token from authenticator")
        scope = "https://api.securitycenter.microsoft.com/.default"
        token = self.authenticator.get_token(scope)
        self.logger.trace(f"Token acquired successfully (expires: {token.expires_on})")
        return str(token.token)
