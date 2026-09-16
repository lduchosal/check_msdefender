"""Products service implementation."""

from __future__ import annotations

from itertools import starmap

from check_msdefender.core.logging_config import get_verbose_logger
from check_msdefender.core.models import (
    CveInfo,
    DefenderClientProtocol,
    ProductsResult,
    ProductVulnerabilityDict,
    SoftwareEntry,
)
from check_msdefender.services.machine_resolver import resolve_machine
from check_msdefender.services.products_verifier import (
    ProductsVerifier,
    VerificationOutcome,
)

# CVSS-style weight applied to each CVE according to its severity.
_SEVERITY_SCORES: dict[str, int] = {
    "critical": 100,
    "high": 10,
    "medium": 5,
    "low": 1,
}

# Both lists are truncated in the output, never in the score: the summary line and the
# perfdata always count every product.
_TOP_PRODUCTS = 10
_TOP_STALE = 10


class DetailObject:
    """Detail object for a software entry with vulnerabilities."""

    def __init__(self, key: str, software: str, data: str, score: int) -> None:
        """Initialize the detail object for a software entry."""
        self.key = key
        self.software = software
        self.data = data
        self.score = score
        self.paths: list[str] = []


class ProductsService:
    """Service for checking installed products on machines."""

    def __init__(
        self,
        defender_client: DefenderClientProtocol,
        verbose_level: int = 0,
        verifier: ProductsVerifier | None = None,
    ) -> None:
        """Initialize with Defender client and, optionally, a path verifier."""
        self.defender = defender_client
        self.verifier = verifier
        self.logger = get_verbose_logger(__name__, verbose_level)

    def get_result(
        self, machine_id: str | None = None, dns_name: str | None = None
    ) -> ProductsResult:
        """Get products result with value and details for a machine."""
        self.logger.method_entry("get_result", machine_id=machine_id, dns_name=dns_name)

        target_machine_id, target_dns_name = resolve_machine(
            self.defender, machine_id, dns_name
        )

        # Get products for the machine
        self.logger.info("Fetching products from Microsoft Defender")
        all_products = self.defender.get_products().get("value", [])
        products = [
            product
            for product in all_products
            if product.get("deviceId") == target_machine_id
        ]

        self.logger.info(
            f"Found {len(products)} vulnerabilities for machine {target_dns_name}"
        )

        software_vulnerabilities = self._group_by_software(products)
        outcome = None
        if self.verifier is not None:
            outcome = self.verifier.verify(target_dns_name, software_vulnerabilities)

        result = self._build_result(products, software_vulnerabilities, outcome)
        self.logger.info(
            f"Products analysis complete: {result.get('vulnerable_count')} vulnerable "
            f"products, score: {result.get('value')}"
        )
        self.logger.method_exit("get_result", result)
        return result

    def _build_result(
        self,
        products: list[ProductVulnerabilityDict],
        software_vulnerabilities: dict[str, SoftwareEntry],
        outcome: VerificationOutcome | None,
    ) -> ProductsResult:
        """Assemble the result from the grouped software and the host's verdicts."""
        stale_keys: set[str] = set(outcome.stale) if outcome else set()
        detail_objects = sorted(
            starmap(self._build_detail_object, software_vulnerabilities.items()),
            key=lambda detail_object: detail_object.score,
            reverse=True,
        )
        counted = [item for item in detail_objects if item.key not in stale_keys]
        stale = [item for item in detail_objects if item.key in stale_keys]
        raw_score = sum(item.score for item in detail_objects)
        total_score = sum(item.score for item in counted)
        severity_counts = self._count_by_severity(products)

        result: ProductsResult = {
            "value": total_score,
            "details": self._build_details(counted, stale, outcome, raw_score),
            "vulnerable_count": len(counted),
            "critical_count": severity_counts["critical"],
            "high_count": severity_counts["high"],
            "medium_count": severity_counts["medium"],
            "low_count": severity_counts["low"],
            "total_cves": len(products),
            "total_software": len(software_vulnerabilities),
        }
        if outcome is not None:
            self._add_verification_result(result, outcome, raw_score, total_score)
        return result

    @staticmethod
    def _add_verification_result(
        result: ProductsResult,
        outcome: VerificationOutcome,
        raw_score: int,
        total_score: int,
    ) -> None:
        """Record what the verification changed, as result keys and extra perfdata."""
        stale_score = raw_score - total_score
        result["raw_value"] = raw_score
        result["stale_value"] = stale_score
        result["stale_count"] = len(outcome.stale)
        result["unverified_count"] = outcome.unverified
        if outcome.error:
            result["verify_error"] = outcome.error
        # The raw score keeps being graphed even once the net score drops: a curve that
        # only showed the filtered value would hide both the real surface and a filter
        # that started swallowing too much.
        result["metrics"] = [
            ("raw", raw_score),
            ("stale", stale_score),
            ("unverified", outcome.unverified),
        ]

    @staticmethod
    def _group_by_software(
        products: list[ProductVulnerabilityDict],
    ) -> dict[str, SoftwareEntry]:
        """Group vulnerability records by software (name/version/vendor)."""
        software_vulnerabilities: dict[str, SoftwareEntry] = {}
        for vulnerability in products:
            software_name = vulnerability.get("softwareName", "Unknown")
            software_version = vulnerability.get("softwareVersion", "Unknown")
            software_vendor = vulnerability.get("softwareVendor", "Unknown")
            cve_id = vulnerability.get("cveId", "Unknown")
            cvss_score = vulnerability.get("cvssScore", 0.0)
            disk_paths = vulnerability.get("diskPaths", [])
            registry_paths = vulnerability.get("registryPaths", [])
            severity = vulnerability.get("vulnerabilitySeverityLevel", "Unknown")

            software_key = f"{software_name}-{software_version}-{software_vendor}"

            if software_key not in software_vulnerabilities:
                software_vulnerabilities[software_key] = SoftwareEntry(
                    name=software_name,
                    version=software_version,
                    vendor=software_vendor,
                    cves=[],
                    paths=set(),
                    registryPaths=set(),
                    max_cvss=0.0,
                    severities=[],
                )

            entry = software_vulnerabilities[software_key]
            cve_info = CveInfo(cve_id=cve_id, severity=severity)
            entry["cves"].append(cve_info)
            entry["paths"].update(disk_paths)
            entry["registryPaths"].update(registry_paths)
            entry["max_cvss"] = max(entry["max_cvss"], cvss_score)
            entry["severities"].append(severity)
        return software_vulnerabilities

    @staticmethod
    def _count_by_severity(
        products: list[ProductVulnerabilityDict],
    ) -> dict[str, int]:
        """Count vulnerabilities by severity (critical/high/medium/low)."""
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for vulnerability in products:
            severity_level = vulnerability.get("vulnerabilitySeverityLevel", "Unknown")
            severity_lower = (severity_level or "Unknown").lower()
            if severity_lower in counts:
                counts[severity_lower] += 1
        return counts

    @classmethod
    def _build_details(
        cls,
        counted: list[DetailObject],
        stale: list[DetailObject],
        outcome: VerificationOutcome | None,
        raw_score: int,
    ) -> list[str]:
        """Build the human-readable detail lines."""
        if not counted and not stale:
            return []

        total_score = sum(item.score for item in counted)
        details: list[str] = [
            cls._summary_line(len(counted), total_score, outcome, raw_score),
            "",
        ]
        for detail_object in counted[:_TOP_PRODUCTS]:
            details.append(f"{detail_object.software} - {detail_object.data}")
            details.extend(detail_object.paths)
            details.append("")
        details.extend(cls._stale_lines(stale, outcome))
        return details

    @staticmethod
    def _summary_line(
        counted: int,
        total_score: int,
        outcome: VerificationOutcome | None,
        raw_score: int,
    ) -> str:
        """Build the first line, the only one Nagios shows in its service list."""
        summary = f"{counted} vulnerable products, score: {total_score}"
        if outcome is None:
            return summary
        if outcome.error:
            # Fail closed: an unreachable host must never look like a clean one, so the
            # raw score is what gets compared to the thresholds.
            return f"{summary} (path verification FAILED: {outcome.error})"
        if outcome.stale:
            summary += (
                f" (raw {raw_score}, {len(outcome.stale)} stale excluded: "
                f"{raw_score - total_score})"
            )
        if outcome.unverified:
            summary += f", {outcome.unverified} unverified"
        return summary

    @staticmethod
    def _stale_lines(
        stale: list[DetailObject], outcome: VerificationOutcome | None
    ) -> list[str]:
        """List the entries the host no longer confirms, with the reason for each."""
        if outcome is None or not stale:
            return []
        masked = sum(item.score for item in stale)
        lines = [f"Stale entries excluded ({len(stale)} products, score: {masked}):"]
        for detail_object in stale[:_TOP_STALE]:
            entry = outcome.stale[detail_object.key]
            lines.append(
                f" - {detail_object.software} - Score: {detail_object.score}"
                f" - {entry.reason}: {entry.evidence}"
            )
        if len(stale) > _TOP_STALE:
            lines.append(f" - .. (+{len(stale) - _TOP_STALE} more)")
        return lines

    @staticmethod
    def _build_detail_object(key: str, software: SoftwareEntry) -> DetailObject:
        """Build a single software detail entry with its score and paths."""
        cve_count = len(software["cves"])
        unique_cves = list({cve["cve_id"] for cve in software["cves"]})
        cve_list = ", ".join(unique_cves[:5])  # Show first 5 CVEs

        # Count severities
        severity_counts: dict[str, int] = {
            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Unknown": 0,
        }
        for sev in software["severities"]:
            sev_key = sev or "Unknown"
            severity_counts[sev_key] += 1
        severities = ", ".join(
            f"{name}: {value}" for name, value in severity_counts.items() if value > 0
        )

        score = sum(
            _SEVERITY_SCORES.get((cve["severity"] or "Unknown").lower(), 0)
            for cve in software["cves"]
        )

        if len(unique_cves) > 5:
            cve_list += f".. (+{len(unique_cves) - 5} more)"

        detail_object = DetailObject(
            key=key,
            software=f"{software['name']} {software['version']} ({software['vendor']})",
            data=f"Score: {score}, CVEs: {cve_count} ({severities}), ({cve_list})",
            score=score,
        )

        # Add paths (limit to 4)
        paths_list = list(software["paths"])
        for path in paths_list[:4]:
            detail_object.paths.append(f" - {path}")
        if len(paths_list) > 4:
            detail_object.paths.append(f" - .. (+{len(paths_list) - 4} more)")

        # Add registry paths if available (limit to 4)
        registry_list = list(software["registryPaths"])
        for registry_path in registry_list[:4]:
            detail_object.paths.append(f" - {registry_path}")
        if len(registry_list) > 4:
            detail_object.paths.append(f" - .. (+{len(registry_list) - 4} more)")

        return detail_object
