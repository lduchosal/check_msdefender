"""Mock Defender client for fixture tests."""

import json
from pathlib import Path

from check_msdefender.core.exceptions import ValidationError


class MockDefenderClient:
    """Mock Microsoft Defender client using fixture data."""

    def __init__(self):
        """Initialize with fixture data."""
        fixtures_dir = Path(__file__).parent

        # Load machine data
        with (fixtures_dir / "machine_data.json").open() as f:
            self.machine_data = json.load(f)

        # Load vulnerability data
        with (fixtures_dir / "vulnerability_data.json").open() as f:
            self.vulnerability_data = json.load(f)

        # Load alerts data
        with (fixtures_dir / "alerts_data.json").open() as f:
            self.alerts_data = json.load(f)

    def get_machine_by_id(self, machine_id):
        """Get machine by ID from fixtures."""
        machine = self.machine_data["machine_by_id"].get(machine_id)
        if not machine:
            raise ValidationError(f"Machine not found: {machine_id}")
        return machine

    def get_machine_by_dns_name(self, dns_name):
        """Get machine by DNS name from fixtures."""
        return self.machine_data["machine_by_dns"].get(dns_name, {"value": []})

    def get_machine_vulnerabilities(self, machine_id):
        """Get vulnerabilities for machine from fixtures."""
        return self.vulnerability_data["vulnerabilities_by_machine"].get(
            machine_id, {"value": []}
        )

    def get_alerts(self):
        """Get all alerts from fixtures."""
        return self.alerts_data["alerts"]
