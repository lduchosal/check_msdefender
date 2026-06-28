"""Unit tests for ProductsService."""

from unittest.mock import Mock

import pytest

from check_msdefender.core.exceptions import ValidationError
from check_msdefender.services.products_service import ProductsService

_PRODUCTS = {
    "value": [
        {
            "deviceId": "m1",
            "softwareName": "openssl",
            "softwareVersion": "1.0",
            "softwareVendor": "openssl",
            "cveId": "CVE-2024-0001",
            "cvssScore": 9.8,
            "vulnerabilitySeverityLevel": "Critical",
            "diskPaths": ["/usr/bin/openssl"],
            "registryPaths": [],
        },
        {
            "deviceId": "m1",
            "softwareName": "openssl",
            "softwareVersion": "1.0",
            "softwareVendor": "openssl",
            "cveId": "CVE-2024-0002",
            "cvssScore": 5.0,
            "vulnerabilitySeverityLevel": "Medium",
            "diskPaths": ["/usr/bin/openssl"],
            "registryPaths": [],
        },
        {
            "deviceId": "other",
            "softwareName": "ignored",
            "softwareVersion": "1",
            "softwareVendor": "x",
            "cveId": "CVE-2024-9999",
            "cvssScore": 1.0,
            "vulnerabilitySeverityLevel": "Low",
            "diskPaths": [],
            "registryPaths": [],
        },
    ]
}


def _product(
    *,
    software="openssl",
    cve="CVE-2024-0001",
    severity="Critical",
    disk=None,
    registry=None,
    device="m1",
):
    """Build a single product/vulnerability record for the m1 machine."""
    return {
        "deviceId": device,
        "softwareName": software,
        "softwareVersion": "1.0",
        "softwareVendor": "openssl",
        "cveId": cve,
        "cvssScore": 9.8,
        "vulnerabilitySeverityLevel": severity,
        "diskPaths": disk or [],
        "registryPaths": registry or [],
    }


def _software_line(details, prefix):
    """Return the single detail line that starts with the given software prefix."""
    return next(line for line in details if line.startswith(prefix))


class TestProductsService:
    """Unit tests for ProductsService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.service = ProductsService(self.mock_client)
        self.mock_client.get_machine_by_id.return_value = {"computerDnsName": "a.dom"}

    def test_get_result_by_machine_id(self):
        """Aggregate the machine's products and score them."""
        self.mock_client.get_machine_by_id.return_value = {"computerDnsName": "a.dom"}
        self.mock_client.get_products.return_value = _PRODUCTS
        result = self.service.get_result(machine_id="m1")
        # Critical (100) + Medium (5) for the single openssl entry.
        assert result["value"] == 105
        assert any("vulnerable products" in line for line in result["details"])
        assert any("openssl" in line for line in result["details"])

    def test_get_result_by_dns_name(self):
        """Resolve the machine by DNS name, then aggregate."""
        self.mock_client.get_machine_by_dns_name.return_value = {
            "value": [{"id": "m1"}]
        }
        self.mock_client.get_products.return_value = _PRODUCTS
        result = self.service.get_result(dns_name="a.dom")
        assert result["value"] == 105

    def test_get_result_no_products(self):
        """No matching products → score 0, empty details."""
        self.mock_client.get_machine_by_id.return_value = {"computerDnsName": "a.dom"}
        self.mock_client.get_products.return_value = {"value": []}
        result = self.service.get_result(machine_id="m1")
        assert result["value"] == 0

    def test_get_result_no_params(self):
        """No identifier → ValidationError (propagated from the resolver)."""
        with pytest.raises(ValidationError, match="Either machine_id or dns_name"):
            self.service.get_result()

    def test_severity_weights_and_line_format(self):
        """Each severity adds its fixed weight (100/10/5/1, Unknown=0) and the
        detail line keeps its exact format."""
        self.mock_client.get_products.return_value = {
            "value": [
                _product(cve="CVE-1", severity="Critical"),
                _product(cve="CVE-2", severity="High"),
                _product(cve="CVE-3", severity="Medium"),
                _product(cve="CVE-4", severity="Low"),
                _product(cve="CVE-5", severity="Unknown"),
            ]
        }
        result = self.service.get_result(machine_id="m1")

        assert result["value"] == 116  # 100 + 10 + 5 + 1 + 0
        assert result["critical_count"] == 1
        assert result["high_count"] == 1
        assert result["medium_count"] == 1
        assert result["low_count"] == 1

        line = _software_line(result["details"], "openssl ")
        assert line.startswith(
            "openssl 1.0 (openssl) - Score: 116, CVEs: 5 "
            "(Critical: 1, High: 1, Medium: 1, Low: 1, Unknown: 1), ("
        )
        # The 5 CVEs all appear (order is set-derived, so not asserted).
        for cve in ("CVE-1", "CVE-2", "CVE-3", "CVE-4", "CVE-5"):
            assert cve in line

    def test_cve_list_truncation(self):
        """More than 5 unique CVEs are truncated with a '+N more' marker."""
        self.mock_client.get_products.return_value = {
            "value": [_product(cve=f"CVE-{i:02d}", severity="Low") for i in range(7)]
        }
        result = self.service.get_result(machine_id="m1")

        assert result["value"] == 7  # 7 x Low(1)
        line = _software_line(result["details"], "openssl ")
        assert "CVEs: 7" in line
        assert ".. (+2 more)" in line

    def test_path_and_registry_truncation(self):
        """Disk and registry paths are each capped at 4 with their own '+N more'."""
        self.mock_client.get_products.return_value = {
            "value": [
                _product(
                    cve="CVE-1",
                    severity="Critical",
                    disk=[f"/opt/d{i}" for i in range(6)],
                    registry=[f"HKLM\\r{i}" for i in range(5)],
                )
            ]
        }
        result = self.service.get_result(machine_id="m1")

        path_lines = [line for line in result["details"] if line.startswith(" - ")]
        # 4 disk + marker + 4 registry + marker
        assert len(path_lines) == 10
        assert " - .. (+2 more)" in path_lines  # 6 disk paths -> +2
        assert " - .. (+1 more)" in path_lines  # 5 registry paths -> +1

    def test_top_10_limit_and_descending_sort(self):
        """All software is counted, but only the 10 highest scores are detailed,
        sorted descending; the total score still sums every product."""
        items = []
        for s in range(12):
            # soft{s} has (s + 1) Critical CVEs -> score (s + 1) * 100.
            for c in range(s + 1):
                items.append(
                    _product(
                        software=f"soft{s:02d}",
                        cve=f"CVE-{s:02d}-{c:02d}",
                        severity="Critical",
                    )
                )
        self.mock_client.get_products.return_value = {"value": items}
        result = self.service.get_result(machine_id="m1")

        assert result["vulnerable_count"] == 12
        assert result["total_software"] == 12
        assert result["value"] == 7800  # 100 * (1 + 2 + ... + 12)
        assert result["details"][0] == "12 vulnerable products, score: 7800"

        soft_lines = [line for line in result["details"] if line.startswith("soft")]
        assert len(soft_lines) == 10  # top 10 only
        assert soft_lines[0].startswith("soft11 ")  # highest score first
        assert soft_lines[-1].startswith("soft02 ")  # 10th highest
        # The two lowest-scoring products are dropped from the detail list.
        assert not any(line.startswith("soft00 ") for line in soft_lines)
        assert not any(line.startswith("soft01 ") for line in soft_lines)
