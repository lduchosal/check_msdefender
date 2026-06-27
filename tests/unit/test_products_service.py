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


class TestProductsService:
    """Unit tests for ProductsService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.service = ProductsService(self.mock_client)

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
