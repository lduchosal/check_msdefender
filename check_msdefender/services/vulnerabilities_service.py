"""Vulnerabilities service implementation."""

from typing import Any, Dict, List, Optional

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.services.models import Vulnerability, VulnerabilityScore


class VulnerabilitiesService:
    """Service for checking vulnerabilities."""

    def __init__(self, defender_client: Any, verbose_level: int = 0) -> None:
        """Initialize with Defender client."""
        self.client = defender_client
        self.logger = get_verbose_logger(__name__, verbose_level)
        self._severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    def get_result(
        self, machine_id: Optional[str] = None, dns_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get vulnerability result with value and details for a machine."""
        self.logger.method_entry("get_result", machine_id=machine_id, dns_name=dns_name)

        if not machine_id and not dns_name:
            raise ValidationError("Either machine_id or dns_name must be provided")

        # Get machine ID if DNS name provided
        if dns_name:
            self.logger.info(f"Resolving machine ID for DNS name: {dns_name}")
            machines_data = self.client.get_machine_by_dns_name(dns_name)
            if not machines_data.get("value"):
                raise ValidationError(f"Machine not found with DNS name: {dns_name}")
            machine_id = machines_data["value"][0]["id"]
            self.logger.debug(f"Resolved machine ID: {machine_id}")

        # Get vulnerabilities for the machine
        self.logger.info(f"Fetching vulnerabilities for machine: {machine_id}")
        raw_vulnerabilities = self.client.get_machine_vulnerabilities(machine_id).get(
            "value", []
        )
        self.logger.info(f"Found {len(raw_vulnerabilities)} raw vulnerabilities")

        # Process and deduplicate vulnerabilities
        vulnerabilities = self._process_vulnerabilities(raw_vulnerabilities)
        self.logger.info(
            f"Found {len(vulnerabilities)} unique vulnerabilities after deduplication"
        )

        # Calculate vulnerability score
        score = VulnerabilityScore()

        # Create detailed output
        details = []

        # Sort vulnerabilities by severity for consistent output
        sorted_vulnerabilities = self._sort_by_severity(vulnerabilities)

        for vuln in sorted_vulnerabilities:
            severity = vuln.severity.lower()
            self.logger.debug(
                f"Processing vulnerability {vuln.id} with severity: {severity}"
            )

            if severity == "critical":
                score.critical += 1
            elif severity == "high":
                score.high += 1
            elif severity == "medium":
                score.medium += 1
            elif severity == "low":
                score.low += 1

            description = self.clean_and_truncate(vuln.description)
            # Add to details list
            details.append(f"{vuln.id}: {description} {vuln.severity.upper()}")

        self.logger.info(
            f"Vulnerability score breakdown - Critical: {score.critical}, High: {score.high}, Medium: {score.medium}, Low: {score.low}"
        )
        self.logger.info(f"Total vulnerability score: {score.total_score}")

        details.insert(
            0,
            f"Vulnerabilities: {len(raw_vulnerabilities)}, score: {score.total_score}",
        )

        result = {"value": score.total_score, "details": details}

        self.logger.method_exit("get_result", result)
        return result

    def clean_and_truncate(
        self, text: Optional[str], prefix: str = "Summary: ", word_count: int = 10
    ) -> str:
        # Handle None text
        if text is None:
            return ""
        # Remove prefix and get first N words
        cleaned = text.replace(prefix, "", 1)  # Remove only first occurrence
        words = cleaned.split()[:word_count]
        return " ".join(words)

    def get_detailed_vulnerabilities(
        self, machine_id: Optional[str] = None, dns_name: Optional[str] = None
    ) -> List[Vulnerability]:
        """Get detailed vulnerability information for a machine."""
        self.logger.method_entry(
            "get_detailed_vulnerabilities", machine_id=machine_id, dns_name=dns_name
        )

        if not machine_id and not dns_name:
            raise ValidationError("Either machine_id or dns_name must be provided")

        # Get machine ID if DNS name provided
        if dns_name:
            self.logger.info(f"Resolving machine ID for DNS name: {dns_name}")
            machines_data = self.client.get_machine_by_dns_name(dns_name)
            if not machines_data.get("value"):
                raise ValidationError(f"Machine not found with DNS name: {dns_name}")
            machine_id = machines_data["value"][0]["id"]
            self.logger.debug(f"Resolved machine ID: {machine_id}")

        # Get vulnerabilities for the machine
        self.logger.info(f"Fetching vulnerabilities for machine: {machine_id}")
        raw_vulnerabilities = self.client.get_machine_vulnerabilities(machine_id).get(
            "value", []
        )

        # Process and deduplicate vulnerabilities
        vulnerabilities = self._process_vulnerabilities(raw_vulnerabilities)

        # Sort by severity
        sorted_vulnerabilities = self._sort_by_severity(vulnerabilities)

        self.logger.method_exit(
            "get_detailed_vulnerabilities", len(sorted_vulnerabilities)
        )
        return sorted_vulnerabilities

    def _process_vulnerabilities(
        self, raw_vulnerabilities: List[Dict[str, Any]]
    ) -> List[Vulnerability]:
        """Process and deduplicate vulnerabilities."""
        seen_cves = set()
        unique_vulnerabilities = []

        for vuln_data in raw_vulnerabilities:
            vuln_id = vuln_data.get("id", "")

            # Skip if we've already seen this CVE
            if vuln_id in seen_cves:
                continue

            seen_cves.add(vuln_id)

            # Create Vulnerability object
            vulnerability = Vulnerability(
                id=vuln_id,
                severity=vuln_data.get("severity", "unknown"),
                title=vuln_data.get("name", "Unknown vulnerability"),
                description=vuln_data.get("description"),
            )

            unique_vulnerabilities.append(vulnerability)

        return unique_vulnerabilities

    def _sort_by_severity(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """Sort vulnerabilities by severity (Critical > High > Medium > Low)."""
        return sorted(
            vulnerabilities,
            key=lambda v: self._severity_order.get(v.severity.lower(), 999),
        )
