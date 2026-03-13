"""Products service implementation."""

from typing import Dict, Optional, Any
from datetime import datetime

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.core.logging_config import get_verbose_logger


class DetailObject:
    def __init__(self, software: str, data: str, score: int):
        self.software = software
        self.data = data
        self.score = score
        self.paths: list[str] = []


class ProductsService:
    """Service for checking installed products on machines."""

    def __init__(self, defender_client: Any, verbose_level: int = 0) -> None:
        """Initialize with Defender client."""
        self.defender = defender_client
        self.logger = get_verbose_logger(__name__, verbose_level)

    def get_result(
        self, machine_id: Optional[str] = None, dns_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get products result with value and details for a machine."""
        self.logger.method_entry("get_result", machine_id=machine_id, dns_name=dns_name)

        if not machine_id and not dns_name:
            raise ValidationError("Either machine_id or dns_name must be provided")

        # Get machine information
        target_dns_name = dns_name
        target_machine_id = machine_id

        if machine_id:
            # Get DNS name from machine_id
            machine_details = self.defender.get_machine_by_id(machine_id)
            target_dns_name = machine_details.get("computerDnsName", "Unknown")
        elif dns_name:
            # Get machine_id from dns_name
            dns_response = self.defender.get_machine_by_dns_name(dns_name)
            machines = dns_response.get("value", [])
            if not machines:
                raise ValidationError(f"Machine not found with DNS name: {dns_name}")
            target_machine_id = machines[0].get("id")
            target_dns_name = dns_name

        # Get products for the machine
        self.logger.info("Fetching products from Microsoft Defender")
        products_data = self.defender.get_products()
        all_products = products_data.get("value", [])
        products = [
            product for product in all_products if product.get("deviceId") == target_machine_id
        ]

        self.logger.info(f"Found {len(products)} vulnerabilities for machine {target_dns_name}")

        # Group vulnerabilities by software
        software_vulnerabilities = {}
        for vulnerability in products:
            software_name = vulnerability.get("softwareName", "Unknown")
            software_version = vulnerability.get("softwareVersion", "Unknown")
            software_vendor = vulnerability.get("softwareVendor", "Unknown")
            cve_id = vulnerability.get("cveId", "Unknown")
            cvss_score = vulnerability.get("cvssScore", 0)
            disk_paths = vulnerability.get("diskPaths", [])
            registry_paths = vulnerability.get("registryPaths", [])
            severity = vulnerability.get("vulnerabilitySeverityLevel", "Unknown")

            software_key = f"{software_name}-{software_version}-{software_vendor}"

            if software_key not in software_vulnerabilities:
                software_vulnerabilities[software_key] = {
                    "name": software_name,
                    "version": software_version,
                    "vendor": software_vendor,
                    "cves": [],
                    "paths": set(),
                    "registryPaths": set(),
                    "max_cvss": 0,
                    "severities": [],
                }

            cve_info = {"cve_id": cve_id, "severity": severity}
            software_vulnerabilities[software_key]["cves"].append(cve_info)
            software_vulnerabilities[software_key]["paths"].update(disk_paths)
            software_vulnerabilities[software_key]["registryPaths"].update(registry_paths)
            software_vulnerabilities[software_key]["max_cvss"] = max(
                software_vulnerabilities[software_key]["max_cvss"], cvss_score
            )
            software_vulnerabilities[software_key]["severities"].append(severity)

        # Count vulnerabilities by severity
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for vulnerability in products:
            severityLevel = vulnerability.get("vulnerabilitySeverityLevel", "Unknown")
            severity = (severityLevel or "Unknown").lower()
            if severity == "critical":
                critical_count += 1
            elif severity == "high":
                high_count += 1
            elif severity == "medium":
                medium_count += 1
            elif severity == "low":
                low_count += 1

        # Count vulnerable software for reporting
        vulnerable_software = []
        for software in software_vulnerabilities.values():
            if len(software["cves"]) > 0:
                vulnerable_software.append(software)

        # Create details for output
        details = []
        total_score = 0
        if software_vulnerabilities:

            detail_objects = []

            # Add software details
            for software in list(software_vulnerabilities.values()):
                score = 0
                    
                cve_count = len(software["cves"])
                unique_cves = list(set(cve["cve_id"] for cve in software["cves"]))
                cve_list = ", ".join(unique_cves[:5])  # Show first 5 CVEs
                severities = ""
                # Count severities
                severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
                for sev in software["severities"]:
                    sev = (sev or "Unknown")
                    severity_counts[sev] += 1
                severities = ", ".join(
                    f"{key}: {value}" for key, value in severity_counts.items() if value > 0
                )

                for cve in software["cves"]:
                    severity = (cve["severity"] or "Unknown").lower()
                    if severity == "critical":
                        score += 100
                    elif severity == "high":
                        score += 10
                    elif severity == "medium":
                        score += 5
                    elif severity == "low":
                        score += 1

                if len(unique_cves) > 5:
                    cve_list += f".. (+{len(unique_cves) - 5} more)"

                detail_object = DetailObject(
                    software=f"{software['name']} {software['version']} ({software['vendor']})",
                    data=f"Score: {score}, CVEs: {cve_count} ({severities}), ({cve_list})",
                    score=score,
                )

                total_score += score

                # Add paths (limit to 4)
                for path in list(software["paths"])[:4]:
                    detail_object.paths.append(f" - {path}")

                # Indicate if more paths exist
                if len(software["paths"]) > 4:
                    detail_object.paths.append(f" - .. (+{len(software['paths']) - 4} more)")

                # Add registry paths if available (limit to 4)
                for registry_path in list(software["registryPaths"])[:4]:
                    detail_object.paths.append(f" - {registry_path}")

                # Indicate if more registry paths exist
                if len(software["registryPaths"]) > 4:
                    detail_object.paths.append(
                        f" - .. (+{len(software['registryPaths']) - 4} more)"
                    )

                # Collect detail objects for sorting
                detail_objects.append(detail_object)

            summary_line = f"{len(vulnerable_software)} vulnerable products, score: {total_score}"
            details.append(summary_line)
            details.append("")

            # Sort detail objects by score descending
            detail_objects.sort(key=lambda x: x.score, reverse=True)

            # Limit to top 10
            for detail_object in detail_objects[:10]:
                details.append(f"{detail_object.software} - {detail_object.data}")
                details.extend(detail_object.paths)
                details.append("")

        # Determine the value based on severity:
        # - Critical vulnerabilities trigger critical threshold
        # - High/Medium vulnerabilities trigger warning threshold
        # - Low vulnerabilities or no vulnerabilities are OK
        result = {
            "value": total_score,
            "details": details,
            "vulnerable_count": len(vulnerable_software),
            "critical_count": critical_count,
            "high_count": high_count,
            "medium_count": medium_count,
            "low_count": low_count,
            "total_cves": len(products),
            "total_software": len(software_vulnerabilities),
        }

        self.logger.info(
            f"Products analysis complete: {len(vulnerable_software)} vulnerable products, score: {total_score}"
        )
        self.logger.method_exit("get_result", result)
        return result
