"""Unit tests for MachinesService."""

from unittest.mock import Mock

from check_msdefender.services.machines_service import MachinesService

_MACHINES = {
    "value": [
        {
            "id": "m-3",
            "computerDnsName": "c.dom",
            "osPlatform": "Linux",
            "onboardingStatus": "CanBeOnboarded",
        },
        {
            "id": "m-1",
            "computerDnsName": "a.dom",
            "osPlatform": "Windows10",
            "onboardingStatus": "Onboarded",
        },
        {
            "id": "m-2",
            "computerDnsName": "b.dom",
            "osPlatform": "Windows11",
            "onboardingStatus": "InsufficientInfo",
        },
    ]
}


class TestMachinesService:
    """Unit tests for MachinesService."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_client = Mock()
        self.service = MachinesService(self.mock_client)

    def test_get_result_counts_and_sorts(self):
        """Count machines and sort Onboarded first."""
        self.mock_client.list_machines.return_value = _MACHINES
        result = self.service.get_result()
        assert result["value"] == 3
        # First listed machine line (after the "Total machines" header) is the
        # Onboarded one, with a check mark.
        assert result["details"][0] == "Total machines: 3"
        assert "a.dom" in result["details"][1]
        assert "✓" in result["details"][1]

    def test_get_result_no_machines(self):
        """No machines → value 0 with a friendly message."""
        self.mock_client.list_machines.return_value = {"value": []}
        result = self.service.get_result()
        assert result["value"] == 0
        assert "No machines found" in result["details"][0]

    def test_get_details(self):
        """get_details returns one line per machine."""
        self.mock_client.list_machines.return_value = _MACHINES
        details = self.service.get_details()
        assert len(details) == 3
        assert any("a.dom" in line for line in details)

    def test_get_details_no_machines(self):
        """get_details returns empty list when there are no machines."""
        self.mock_client.list_machines.return_value = {"value": []}
        assert self.service.get_details() == []
